package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdLogsAccess_TogglesAndPersists(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	t.Setenv("KEENETIC_XRAY_PID_FILE", filepath.Join(t.TempDir(), "none.pid")) // no daemon to signal

	for _, c := range []struct {
		arg  string
		want bool
	}{{"on", true}, {"off", false}} {
		if err := run([]string{"logs", "access", c.arg}); err != nil {
			t.Fatalf("logs access %s: %v", c.arg, err)
		}
		if cfg, _ := config.Load(cfgFile); cfg.XrayAccessLog != c.want {
			t.Errorf("after `logs access %s`: XrayAccessLog = %v, want %v", c.arg, cfg.XrayAccessLog, c.want)
		}
	}
	if err := run([]string{"logs", "access", "maybe"}); err == nil {
		t.Error("an unknown value should error")
	}
	if err := run([]string{"logs", "access"}); err != nil {
		t.Errorf("logs access (show): %v", err)
	}
}
