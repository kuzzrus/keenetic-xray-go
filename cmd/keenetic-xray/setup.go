package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

// setupOpts drives runSetup. With From set (and/or --yes) it runs fully
// non-interactive -- that's the path the .ipk postinst takes when the
// installer was given a link, so `install.sh --sub=...` needs no follow-up
// commands. Without From and without --yes, postinst now runs this
// interactively too (see packaging/ipk/postinst), asking primary and
// backup as two independent sources -- same model as the bot's
// 🔗 Источники (Config.PrimarySource/BackupSource) -- plus the SOCKS/HTTP
// port numbers, rather than the older single-source-then-pick-an-index
// flow non-interactive mode still uses.
type setupOpts struct {
	From       string // vless:// link or http(s):// subscription URL -- non-interactive mode only
	PrimarySel string // index or a remark substring; "" -> 0 -- non-interactive mode only
	BackupSel  string // index or a remark substring; "" -> 1 (or 0 with one profile) -- non-interactive mode only
	Proxy0     string // "", "yes", "no" ("" -> prompt interactively, or auto when non-interactive)
	SOCKSPort  int    // 0 -> prompt interactively, or config.Default's 1080 when non-interactive
	HTTPPort   int    // 0 -> prompt interactively, or config.Default's 1081 when non-interactive
	Yes        bool
}

// cmdSetup is the first-run configurator: pick a primary/backup pair,
// optionally wire Keenetic's Proxy0 to the local inbound, and
// (interactively) offer to restart the daemon so the change takes
// effect.
func cmdSetup(args []string) error {
	var o setupOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-y":
			o.Yes = true
		case a == "--proxy0":
			o.Proxy0 = "yes"
		case a == "--no-proxy0":
			o.Proxy0 = "no"
		case strings.HasPrefix(a, "--from="):
			o.From = a[len("--from="):]
		case a == "--from" && i+1 < len(args):
			i++
			o.From = args[i]
		case strings.HasPrefix(a, "--primary="):
			o.PrimarySel = a[len("--primary="):]
		case strings.HasPrefix(a, "--backup="):
			o.BackupSel = a[len("--backup="):]
		case strings.HasPrefix(a, "--socks-port="):
			n, err := strconv.Atoi(a[len("--socks-port="):])
			if err != nil {
				return fmt.Errorf("--socks-port: %w", err)
			}
			o.SOCKSPort = n
		case strings.HasPrefix(a, "--http-port="):
			n, err := strconv.Atoi(a[len("--http-port="):])
			if err != nil {
				return fmt.Errorf("--http-port: %w", err)
			}
			o.HTTPPort = n
		default:
			return fmt.Errorf("setup: unexpected argument %q", a)
		}
	}
	return runSetup(os.Stdin, o)
}

func runSetup(stdin io.Reader, o setupOpts) error {
	reader := bufio.NewReader(stdin)
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if o.From == "" && !o.Yes {
		return runSetupInteractive(reader, cfg, o)
	}
	return runSetupNonInteractive(cfg, o)
}

// runSetupNonInteractive is the postinst / scripted path: one source
// (a link or a subscription), primary/backup picked from it by index or
// name, no prompts. Unchanged in shape since before per-slot independent
// sources existed; `install.sh --sub=...` and CI depend on this exact
// behavior.
func runSetupNonInteractive(cfg *config.Config, o setupOpts) error {
	input := strings.TrimSpace(o.From)
	if input == "" {
		return fmt.Errorf("no vless:// link or subscription URL given")
	}

	var profiles []config.Profile
	switch {
	case strings.HasPrefix(input, "vless://"):
		p, err := config.ParseVLESSURI(input)
		if err != nil {
			return fmt.Errorf("parsing vless link: %w", err)
		}
		profiles = []config.Profile{p}
	case strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://"):
		fmt.Println("fetching subscription...")
		result, err := subscription.Refresh(context.Background(), input, "", "")
		if err != nil {
			return fmt.Errorf("fetching subscription: %w", err)
		}
		for _, w := range result.Warnings {
			fmt.Println("warning:", w)
		}
		profiles = result.Profiles
		cfg.Subscription = &config.Subscription{URL: input, LastFetchedAt: time.Now()}
	default:
		return fmt.Errorf("input doesn't look like a vless:// link or an http(s):// subscription URL")
	}

	if len(profiles) == 0 {
		return fmt.Errorf("no usable vless:// profiles found")
	}
	if cfg.PrimarySource != nil || cfg.BackupSource != nil {
		fmt.Println("warning: this replaces ALL profiles, including the independent primary/backup sources set via the bot's 🔗 Источники -- re-add them afterward if you still want them")
	}
	cfg.Profiles = profiles

	primaryIdx, err := resolveProfileSelector(profiles, o.PrimarySel, 0)
	if err != nil {
		return fmt.Errorf("--primary: %w", err)
	}
	defBackup := 0
	if len(profiles) > 1 {
		defBackup = 1
		if primaryIdx == 1 {
			defBackup = 0
		}
	}
	backupIdx, err := resolveProfileSelector(profiles, o.BackupSel, defBackup)
	if err != nil {
		return fmt.Errorf("--backup: %w", err)
	}

	cfg.PrimaryIndex = primaryIdx
	cfg.BackupIndex = backupIdx
	if cfg.Subscription != nil {
		cfg.Subscription.PrimaryKey = profiles[primaryIdx].Remark
		cfg.Subscription.BackupKey = profiles[backupIdx].Remark
	}
	applyPortOverrides(cfg, o)

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("\nSaved: primary=%s, backup=%s\n", profiles[primaryIdx].Remark, profiles[backupIdx].Remark)

	if o.Proxy0 == "yes" || (o.Proxy0 != "no" && keenetic.Available()) {
		doSetupProxy0(cfg)
	}
	fmt.Println("apply with: /opt/etc/init.d/S99keenetic-xray restart")
	return nil
}

// runSetupInteractive is the terminal wizard: primary and backup each
// get their own prompt (a vless:// link, or a subscription URL with an
// interactive pick among its profiles) and their own SlotSource, exactly
// like the bot's 🔗 Источники -- so a slot set up this way is never at
// risk of a subscription refresh elsewhere silently discarding it (see
// Config.PrimarySource/BackupSource, IndependentSlots). Then SOCKS/HTTP
// port numbers, Proxy0, and a restart offer.
func runSetupInteractive(reader *bufio.Reader, cfg *config.Config, o setupOpts) error {
	fmt.Println("keenetic-xray setup")

	primary, err := promptSlotSource(reader, cfg, "PRIMARY")
	if err != nil {
		return err
	}
	cfg.PrimaryIndex = cfg.UpsertProfile(primary.profile)
	cfg.PrimarySource = &config.SlotSource{URL: primary.src, Selector: primary.selector}
	fmt.Printf("Saved primary: %s\n\n", primary.profile.Remark)

	backup, err := promptSlotSource(reader, cfg, "BACKUP")
	if err != nil {
		return err
	}
	cfg.BackupIndex = cfg.UpsertProfile(backup.profile)
	cfg.BackupSource = &config.SlotSource{URL: backup.src, Selector: backup.selector}
	fmt.Printf("Saved backup: %s\n", backup.profile.Remark)

	socksPort, httpPort, err := promptPorts(reader, cfg, o)
	if err != nil {
		return err
	}
	cfg.Failover.SOCKSPort = socksPort
	cfg.Failover.HTTPPort = httpPort

	if err := cfg.Save(configPath()); err != nil {
		return err
	}

	switch {
	case o.Proxy0 == "no":
		// leave Proxy0 alone
	case o.Proxy0 == "yes":
		doSetupProxy0(cfg)
	default:
		maybeSetupProxy0(reader, cfg)
	}

	offerDaemonRestart(reader)
	return nil
}

// slotSourceResult is one resolved slot source: the chosen profile, plus
// what to persist in Config.PrimarySource/BackupSource (the source
// string as typed, and the selector -- either what the user typed, or
// the index they picked from a listed subscription -- so a later
// re-resolution of the same source picks the same profile).
type slotSourceResult struct {
	profile  config.Profile
	src      string
	selector string
}

// promptSlotSource asks for one slot's source (a vless:// link, or a
// subscription URL followed by an interactive pick if it has more than
// one profile) and resolves it to a single profile. label is "PRIMARY"
// or "BACKUP", used only in the prompts.
func promptSlotSource(reader *bufio.Reader, cfg *config.Config, label string) (slotSourceResult, error) {
	fmt.Printf("%s -- paste a vless:// link, or a subscription http(s):// URL:\n> ", label)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return slotSourceResult{}, fmt.Errorf("reading input: %w", err)
	}
	src := strings.TrimSpace(line)
	if src == "" {
		return slotSourceResult{}, fmt.Errorf("%s: no vless:// link or subscription URL given", label)
	}

	switch {
	case strings.HasPrefix(src, "vless://"):
		p, err := config.ParseVLESSURI(src)
		if err != nil {
			return slotSourceResult{}, fmt.Errorf("%s: parsing vless link: %w", label, err)
		}
		return slotSourceResult{profile: p, src: src}, nil
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		fmt.Println("fetching subscription...")
		result, err := subscription.Refresh(context.Background(), src, "", "")
		if err != nil {
			return slotSourceResult{}, fmt.Errorf("%s: fetching subscription: %w", label, err)
		}
		for _, w := range result.Warnings {
			fmt.Println("warning:", w)
		}
		if len(result.Profiles) == 0 {
			return slotSourceResult{}, fmt.Errorf("%s: no usable vless:// profiles found in that subscription", label)
		}
		if len(result.Profiles) == 1 {
			return slotSourceResult{profile: result.Profiles[0], src: src}, nil
		}
		fmt.Println("\nAvailable profiles:")
		for i, p := range result.Profiles {
			fmt.Printf("  %d: %s -- %s:%d\n", i, p.Remark, p.Address, p.Port)
		}
		idx, err := promptIndex(reader, "Select "+label, len(result.Profiles), 0)
		if err != nil {
			return slotSourceResult{}, err
		}
		return slotSourceResult{profile: result.Profiles[idx], src: src, selector: strconv.Itoa(idx)}, nil
	default:
		return slotSourceResult{}, fmt.Errorf("%s: input doesn't look like a vless:// link or an http(s):// subscription URL", label)
	}
}

// promptPorts asks for the SOCKS/HTTP inbound ports, defaulting to
// whatever's already in cfg (config.Default's 1080/1081 on a fresh
// config). A flag (--socks-port=/--http-port=) skips its own prompt.
// Re-prompts if the two would collide.
func promptPorts(reader *bufio.Reader, cfg *config.Config, o setupOpts) (socksPort, httpPort int, err error) {
	fmt.Println()
	for {
		socksPort = o.SOCKSPort
		if socksPort == 0 {
			if socksPort, err = promptPort(reader, "SOCKS port", cfg.Failover.SOCKSPort); err != nil {
				return 0, 0, err
			}
		}
		httpPort = o.HTTPPort
		if httpPort == 0 {
			if httpPort, err = promptPort(reader, "HTTP port", cfg.Failover.HTTPPort); err != nil {
				return 0, 0, err
			}
		}
		if socksPort != httpPort {
			return socksPort, httpPort, nil
		}
		fmt.Println("SOCKS and HTTP ports must differ, try again")
		if o.SOCKSPort != 0 && o.HTTPPort != 0 {
			// Both came from flags -- re-prompting can't change them.
			return 0, 0, fmt.Errorf("--socks-port and --http-port must differ")
		}
	}
}

// promptPort reads a line, re-prompting on an invalid or out-of-range
// port; an empty line (just Enter) accepts def.
func promptPort(reader *bufio.Reader, label string, def int) (int, error) {
	for {
		fmt.Printf("%s [default %d]: ", label, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return 0, fmt.Errorf("reading input: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > 65535 {
			fmt.Println("invalid port, try again")
			continue
		}
		return n, nil
	}
}

// applyPortOverrides sets cfg's SOCKS/HTTP ports from --socks-port=/
// --http-port= when given; used by the non-interactive path, which
// otherwise never touches them (config.Default's 1080/1081 stand).
func applyPortOverrides(cfg *config.Config, o setupOpts) {
	if o.SOCKSPort != 0 {
		cfg.Failover.SOCKSPort = o.SOCKSPort
	}
	if o.HTTPPort != 0 {
		cfg.Failover.HTTPPort = o.HTTPPort
	}
}

// resolveProfileSelector turns a --primary/--backup value into an index:
// an integer index, or a case-insensitive substring of exactly one
// profile's remark. Empty selects def.
func resolveProfileSelector(profiles []config.Profile, sel string, def int) (int, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return def, nil
	}
	if n, err := strconv.Atoi(sel); err == nil {
		if n < 0 || n >= len(profiles) {
			return 0, fmt.Errorf("index %d out of range (0..%d)", n, len(profiles)-1)
		}
		return n, nil
	}
	match := -1
	low := strings.ToLower(sel)
	for i, p := range profiles {
		if strings.Contains(strings.ToLower(p.Remark), low) {
			if match >= 0 {
				return 0, fmt.Errorf("%q matches more than one profile", sel)
			}
			match = i
		}
	}
	if match < 0 {
		return 0, fmt.Errorf("no profile matches %q", sel)
	}
	return match, nil
}

// doSetupProxy0 performs the ndmc-side Proxy0 wiring and records it in the
// config. Router-only; a no-op where ndmc isn't present.
func doSetupProxy0(cfg *config.Config) {
	if !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		fmt.Println("  could not detect the router LAN IP:", err)
		fmt.Println("  run: keenetic-xray proxy0 set --lan-ip=192.168.x.1")
		return
	}
	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: cfg.Proxy0Port(),
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		fmt.Println("  Proxy0 setup failed:", err)
		return
	}
	cfg.Proxy0.Enabled = true
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  Proxy0 configured on the router but saving config failed:", err)
		return
	}
	fmt.Printf("  Proxy0 -> %s:%d. Assign devices/policies to Proxy0 in the Keenetic UI.\n", ip, cfg.Proxy0Port())
}

// maybeSetupProxy0 is the interactive prompt in front of doSetupProxy0.
func maybeSetupProxy0(reader *bufio.Reader, cfg *config.Config) {
	if !keenetic.Available() {
		return
	}
	fmt.Print("\nPoint Keenetic's Proxy0 at the proxy now (route the LAN through it)? [y/N]: ")
	line, _ := reader.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
		fmt.Println("skipped -- set it up later with: keenetic-xray proxy0 set")
		return
	}
	doSetupProxy0(cfg)
}

// promptIndex reads a line, re-prompting on invalid input; an empty line
// (just Enter) accepts def.
func promptIndex(reader *bufio.Reader, label string, count, def int) (int, error) {
	for {
		fmt.Printf("%s [0-%d, default %d]: ", label, count-1, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return 0, fmt.Errorf("reading input: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 0 || idx >= count {
			fmt.Println("invalid selection, try again")
			continue
		}
		return idx, nil
	}
}
