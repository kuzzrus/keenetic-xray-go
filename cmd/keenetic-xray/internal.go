package main

import (
	"fmt"
	"path/filepath"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

// cmdInternal dispatches the hidden subcommands the .ipk's postinst/prerm
// scripts call -- not meant for interactive use.
func cmdInternal(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray internal {postinst-setup|prerm-cleanup} [args]")
	}
	switch args[0] {
	case "postinst-setup":
		return cmdPostinstSetup()
	case "prerm-cleanup":
		return cmdPrermCleanup(args[1:])
	default:
		return fmt.Errorf("unknown internal subcommand %q", args[0])
	}
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
