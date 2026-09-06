package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdRoutes_LifecycleWithoutNdmc(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)

	// new: creates a list, classifies, rejects a private subnet.
	if err := run([]string{"routes", "new", "media", "netflix.com", "10.0.0.0/8", "1.2.3.0/24"}); err != nil {
		t.Fatalf("routes new: %v", err)
	}
	cfg, _ := config.Load(cfgFile)
	if len(cfg.Routing.Lists) != 1 || cfg.Routing.Lists[0].Name != "media" {
		t.Fatalf("lists = %+v", cfg.Routing.Lists)
	}
	if got := len(cfg.Routing.Lists[0].Entries); got != 2 { // netflix.com + 1.2.3.0/24
		t.Errorf("entries = %d, want 2", got)
	}

	// set --exclusive --iface
	if err := run([]string{"routes", "set", "media", "--exclusive", "--iface=Proxy1"}); err != nil {
		t.Fatalf("routes set: %v", err)
	}
	cfg, _ = config.Load(cfgFile)
	if !cfg.Routing.Lists[0].Exclusive || cfg.Routing.Lists[0].Interface != "Proxy1" {
		t.Errorf("after set: %+v", cfg.Routing.Lists[0])
	}

	// disable / enable
	if err := run([]string{"routes", "disable", "media"}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = config.Load(cfgFile); !cfg.Routing.Lists[0].Disabled {
		t.Error("not disabled")
	}
	if err := run([]string{"routes", "enable", "media"}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = config.Load(cfgFile); cfg.Routing.Lists[0].Disabled {
		t.Error("not re-enabled")
	}

	// del one entry, then rm the list
	if err := run([]string{"routes", "del", "media", "netflix.com"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"routes", "rm", "media"}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ = config.Load(cfgFile); len(cfg.Routing.Lists) != 0 {
		t.Errorf("list not removed: %+v", cfg.Routing.Lists)
	}

	// errors
	if err := run([]string{"routes", "add", "ghost", "a.io"}); err == nil {
		t.Error("add to a nonexistent list should error")
	}
	if err := run([]string{"routes", "new", "!!!", "a.io"}); err == nil {
		t.Error("unusable list name should error")
	}
}
