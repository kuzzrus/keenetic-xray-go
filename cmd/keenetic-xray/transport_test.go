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
