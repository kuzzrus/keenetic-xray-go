package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
)

// cmdInternal dispatches the hidden subcommands the .ipk's postinst/prerm
// scripts call -- not meant for interactive use.
func cmdInternal(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray internal {postinst-setup|prerm-cleanup|ensure-xray-core|ensure-naive-core|self-rollback|watchdog-restart-hook} [args]")
	}
	switch args[0] {
	case "postinst-setup":
		return cmdPostinstSetup()
	case "prerm-cleanup":
		return cmdPrermCleanup(args[1:])
	case "ensure-xray-core":
		return cmdEnsureXrayCore(args[1:])
	case "ensure-naive-core":
		return cmdEnsureNaiveCore(args[1:])
	case "self-rollback":
		return cmdSelfRollback(args[1:])
	case "watchdog-restart-hook":
		return cmdWatchdogRestartHook(args[1:])
	default:
		return fmt.Errorf("unknown internal subcommand %q", args[0])
	}
}

// cmdEnsureXrayCore installs a runnable xray-core binary if one isn't
// already present: the vendored, size-optimised build from this project's
// releases by default, or `opkg install xray-core` as the fallback.
//
//	--prefer=vendored|entware   force one install path (also KEENETIC_XRAY_CORE)
//	--tag=vX.Y.Z | stable       switch this router onto a specific vendored
//	                            tag (also KEENETIC_XRAY_CORE_TAG). "stable"
//	                            (or the current DefaultTag) clears the pin.
//	                            An explicit --tag persists to config and
//	                            forces a reinstall even if a core already
//	                            runs; without it this only fills a gap.
func cmdEnsureXrayCore(args []string) error {
	prefer := os.Getenv("KEENETIC_XRAY_CORE")
	tagArg := os.Getenv("KEENETIC_XRAY_CORE_TAG")
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--prefer="):
			prefer = strings.TrimPrefix(a, "--prefer=")
		case strings.HasPrefix(a, "--tag="):
			tagArg = strings.TrimPrefix(a, "--tag=")
		}
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	tag := cfg.XrayCoreTag
	explicit := tagArg != ""
	if explicit {
		tag = strings.TrimSpace(tagArg)
		if tag == "stable" || tag == xraycore.DefaultTag {
			tag = "" // clear the pin, back to the default
		}
		if !config.ValidXrayCoreTag(tag) {
			return fmt.Errorf("--tag %q: want a release tag like %s, or \"stable\"", tagArg, xraycore.PrereleaseTag)
		}
		if tag != cfg.XrayCoreTag {
			cfg.XrayCoreTag = tag
			if err := cfg.Save(configPath()); err != nil {
				return fmt.Errorf("saving the xray-core tag: %w", err)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	src, err := xraycore.Ensure(ctx, xraycore.Options{
		Dest:    xrayBinaryPath(),
		Prefer:  prefer,
		Tag:     tag,
		Force:   explicit,
		BaseURL: os.Getenv("KEENETIC_XRAY_CORE_BASE_URL"), // "" -> the real release URL; overridable for a fork or tests
	})
	if err != nil {
		return fmt.Errorf("ensuring xray-core: %w", err)
	}
	shown := tag
	if shown == "" {
		shown = xraycore.DefaultTag
	}
	fmt.Printf("xray-core ready (%s, %s) at %s\n", src, shown, xrayBinaryPath())
	return nil
}

func installPaths() install.Paths {
	return install.Paths{
		ConfigDir:  filepath.Dir(configPath()),
		ConfigFile: configPath(),
		LibDir:     filepath.Dir(productionConfigPath()),
		LogDir:     logDir(),
		RunDir:     runDir(),
	}
}

func cmdPostinstSetup() error {
	if err := install.PostinstSetup(installPaths()); err != nil {
		return err
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	// Proxy0 is on by default; install.sh --no-proxy0 sets this env.
	if os.Getenv("KEENETIC_XRAY_NO_PROXY0") != "" && cfg.Proxy0.Enabled {
		cfg.Proxy0.Enabled = false
		if err := cfg.Save(configPath()); err != nil {
			return err
		}
	}
	fmt.Printf("keenetic-xray installed (variant: %s, proxy0: %v)\n", cfg.Variant, cfg.Proxy0.Enabled)
	if len(cfg.Profiles) == 0 {
		fmt.Println("run `keenetic-xray setup` to configure your VLESS profiles")
	}

	// Best-effort, on by default: rc.func doesn't respawn a crashed
	// daemon on its own (unlike the control-server's systemd unit,
	// Restart=on-failure). A cron dependency missing/unstartable just
	// means no watchdog, same as ensure-xray-core's own best-effort
	// framing above -- not fatal to the install.
	if err := install.EnsureCron(); err != nil {
		fmt.Println("warning: could not ensure a cron daemon is running, the watchdog won't fire:", err)
	}
	if err := install.SetWatchdogCron(cronFilePath(), watchdogScriptPath(), initScript, watchdogLogPath(), true); err != nil {
		fmt.Println("warning: could not install the watchdog cron entry:", err)
	}
	return nil
}

func cmdPrermCleanup(args []string) error {
	purge := len(args) > 0 && args[0] == "--purge"
	// opkg removes packaged files with the package, but a stale copy left
	// by a botched removal would keep SIGUSR1'ing a non-existent PID --
	// drop the ndm hooks (netfilter.d + ifipchanged.d + ifstatechanged.d)
	// explicitly on any prerm.
	for _, h := range ndmHookPaths() {
		_ = os.Remove(h)
	}
	// INST-05: same "explicitly on any prerm" reasoning as the ndm hooks
	// above, not gated on --purge -- a plain (non-purge) `opkg remove`
	// used to leave the watchdog cron entry (*/2 * * * *) invoking a now-
	// deleted binary forever. Safe unconditionally because postinst
	// already force-installs this entry on every install/upgrade
	// regardless of prior state ("on by default"), so removing it here
	// is a harmless tear-down-and-rebuild for an upgrade, and the actual
	// fix for a real removal. Local cron file, no ndmc/purge needed.
	if err := install.SetWatchdogCron(cronFilePath(), watchdogScriptPath(), initScript, watchdogLogPath(), false); err != nil {
		fmt.Println("warning: could not remove the watchdog cron entry:", err)
	}
	if purge && keenetic.Available() {
		// Remove this project's DNS-route object-groups + routes (only the
		// keenetic-xray-* prefixed ones -- the operator's own web-UI lists
		// are never touched). Best-effort: a router that can't do this
		// still gets the package removed.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := keenetic.ClearRoutes(ctx); err != nil {
			fmt.Println("warning: could not clear DNS routes:", err)
		}
		// Drop the forwarded-TCP MSS-clamp rule we own (tagged
		// keenetic-xray-mss); a router without iptables is a no-op.
		if err := keenetic.ClearMSSClamp(ctx); err != nil {
			fmt.Println("warning: could not clear the MSS-clamp rule:", err)
		}
		// Remove the in-router WireGuard transport interface (found by
		// its keenetic-xray-wg marker; hand-made WG tunnels are untouched).
		if err := keenetic.ClearWGTransport(ctx); err != nil {
			fmt.Println("warning: could not remove the WG-transport interface:", err)
		}
		// Drop the secure-DNS upstreams we manage (catalogue IPs/URLs only;
		// a hand-added upstream is untouched).
		if _, err := keenetic.ClearDNS(ctx, dnsupstream.AllTLSIPs(), dnsupstream.AllDoHURLs()); err != nil {
			fmt.Println("warning: could not clear secure-DNS upstreams:", err)
		}
		// INST-05: adaptive routing's REDIRECT/ipset rule and L7 SNI's
		// NFLOG capture rule were never wired into any cleanup path at
		// all -- only the CLI/bot's own on/off commands touched them.
		// Left in place, they'd keep matching traffic and feeding it
		// (or a now-nonexistent NFLOG listener) after the package -- and
		// the xray-core dokodemo-door inbound they redirect into -- is
		// gone.
		if err := adaptiveroute.ClearRedirect(ctx); err != nil {
			fmt.Println("warning: could not clear the adaptive-route REDIRECT rule:", err)
		}
		if err := l7capture.ClearRules(ctx); err != nil {
			fmt.Println("warning: could not clear the L7 SNI capture rule:", err)
		}
	}
	return install.PrermCleanup(installPaths(), purge)
}
