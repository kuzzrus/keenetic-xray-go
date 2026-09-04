package main

import (
	"fmt"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// cmdFailover reads or tunes the health-check/failover knobs -- e.g. a
// single flaky server that only warrants a longer failures_required
// instead of hand-editing config.json.
func cmdFailover(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray failover {show|set <key> <value>}")
	}
	switch args[0] {
	case "show":
		return failoverShow()
	case "set":
		return failoverSet(args[1:])
	default:
		return fmt.Errorf("unknown failover subcommand %q", args[0])
	}
}

func failoverShow() error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	fmt.Println(cfg.Failover.TunablesText())
	return nil
}

func failoverSet(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: keenetic-xray failover set <key> <value>")
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if err := cfg.Failover.SetTunable(args[0], args[1]); err != nil {
		return err
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("%s = %s\nRestart the daemon to apply: %s restart\n", args[0], args[1], initScript)
	return nil
}
