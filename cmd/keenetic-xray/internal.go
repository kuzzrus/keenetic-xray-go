package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
)

// cmdInternal dispatches the hidden subcommands the .ipk's postinst/prerm
// scripts call -- not meant for interactive use.
func cmdInternal(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray internal {postinst-setup|prerm-cleanup|ensure-xray-core} [args]")
	}
	switch args[0] {
	case "postinst-setup":
		return cmdPostinstSetup()
	case "prerm-cleanup":
		return cmdPrermCleanup(args[1:])
	case "ensure-xray-core":
		return cmdEnsureXrayCore(args[1:])
	default:
		return fmt.Errorf("unknown internal subcommand %q", args[0])
	}
}

// cmdEnsureXrayCore installs a runnable xray-core binary if one isn't
// already present: the vendored, size-optimised build from this project's
// releases by default, or `opkg install xray-core` as the fallback.
// `--prefer=` (or the KEENETIC_XRAY_CORE env var that install.sh forwards)
// takes "vendored" or "entware" to force one path.
func cmdEnsureXrayCore(args []string) error {
	prefer := os.Getenv("KEENETIC_XRAY_CORE")
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--prefer="); ok {
			prefer = v
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	src, err := xraycore.Ensure(ctx, xraycore.Options{Dest: xrayBinaryPath(), Prefer: prefer})
	if err != nil {
		return fmt.Errorf("ensuring xray-core: %w", err)
	}
	fmt.Printf("xray-core ready (%s) at %s\n", src, xrayBinaryPath())
	return nil
}

func installPaths() install.Paths {
	return install.Paths{
		ConfigDir:     filepath.Dir(configPath()),
		ConfigFile:    configPath(),
		LibDir:        filepath.Dir(productionConfigPath()),
		LogDir:        logDir(),
		RunDir:        runDir(),
		DiskCheckPath: optPath(),
	}
}

func cmdPostinstSetup() error {
	if err := install.PostinstSetup(installPaths(), install.DefaultMiniThresholdBytes); err != nil {
		return err
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	fmt.Printf("keenetic-xray installed (variant: %s)\n", cfg.Variant)
	if len(cfg.Profiles) == 0 {
		fmt.Println("run `keenetic-xray setup` to configure your VLESS profiles")
	}
	return nil
}

func cmdPrermCleanup(args []string) error {
	purge := len(args) > 0 && args[0] == "--purge"
	return install.PrermCleanup(installPaths(), purge)
}
