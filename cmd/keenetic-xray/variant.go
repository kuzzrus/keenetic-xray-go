package main

import (
	"fmt"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func cmdVariant(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray variant {show|set} [args]")
	}
	switch args[0] {
	case "show":
		return variantShow()
	case "set":
		return variantSet(args[1:])
	default:
		return fmt.Errorf("unknown variant subcommand %q", args[0])
	}
}

func variantShow() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	fmt.Println(cfg.Variant)
	return nil
}

func variantSet(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: keenetic-xray variant set {mini|full}")
	}
	switch args[0] {
	case config.VariantMini, config.VariantFull:
	default:
		return fmt.Errorf("unknown variant %q, want %q or %q", args[0], config.VariantMini, config.VariantFull)
	}

	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	cfg.Variant = args[0]
	if args[0] == config.VariantMini && cfg.Agent.Enabled {
		// The remote control agent is Full-only (see docs/full-vs-mini.md);
		// downgrading must not leave a stale enabled agent behind that
		// `daemon` would otherwise still start.
		cfg.Agent.Enabled = false
		fmt.Println("remote control agent disabled (not available on Mini)")
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("variant set to %s\n", args[0])
	return nil
}
