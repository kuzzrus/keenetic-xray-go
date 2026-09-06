package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdTransport_ModeOverride(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)

	if err := run([]string{"transport", "mode", "stream-up"}); err != nil {
		t.Fatalf("transport mode stream-up: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.XHTTPMode != "stream-up" {
		t.Errorf("XHTTPMode = %q, want stream-up", cfg.XHTTPMode)
	}

	if err := run([]string{"transport", "mode-clear"}); err != nil {
		t.Fatalf("transport mode-clear: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.XHTTPMode != "" {
		t.Errorf("XHTTPMode = %q, want cleared", cfg.XHTTPMode)
	}

	if err := run([]string{"transport", "mode", "turbo"}); err == nil {
		t.Error("an unknown mode should error")
	}
}

func TestCmdTransport_MSSClamp(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	// Proxy0 is disabled by default, so `transport mss` only persists the
	// value and never touches iptables here.

	if err := run([]string{"transport", "mss", "1400"}); err != nil {
		t.Fatalf("transport mss 1400: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.Proxy0.MSSClamp != 1400 {
		t.Errorf("MSSClamp = %d, want 1400", cfg.Proxy0.MSSClamp)
	}

	if err := run([]string{"transport", "mss", "off"}); err != nil {
		t.Fatalf("transport mss off: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.Proxy0.MSSClamp != -1 {
		t.Errorf("MSSClamp = %d, want -1 (off)", cfg.Proxy0.MSSClamp)
	}

	if err := run([]string{"transport", "mss", "auto"}); err != nil {
		t.Fatalf("transport mss auto: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.Proxy0.MSSClamp != 0 {
		t.Errorf("MSSClamp = %d, want 0 (auto)", cfg.Proxy0.MSSClamp)
	}

	if err := run([]string{"transport", "mss", "9000"}); err == nil {
		t.Error("an out-of-range MSS should error")
	}
}

func TestCmdTransport_WGShow(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)

	// `transport wg show` is read-only and works without ndmc.
	if err := run([]string{"transport", "wg", "show"}); err != nil {
		t.Fatalf("transport wg show: %v", err)
	}
	if err := run([]string{"transport", "wg", "bogus"}); err == nil {
		t.Error("an unknown wg subcommand should error")
	}
	// `transport show` also surfaces WG state without touching it.
	if err := run([]string{"transport", "show"}); err != nil {
		t.Fatalf("transport show: %v", err)
	}
	if cfg, _ := config.Load(cfgFile); cfg.WGTransport.Enabled {
		t.Error("transport show/wg show must not enable the WG transport")
	}
}
