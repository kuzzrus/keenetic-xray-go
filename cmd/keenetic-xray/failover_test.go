package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdFailover_Show(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"failover", "show"}); err != nil {
		t.Fatalf("failover show: %v", err)
	}
}

func TestCmdFailover_Set(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	if err := run([]string{"failover", "set", "failures_required", "6"}); err != nil {
		t.Fatalf("failover set: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Failover.FailuresRequired != 6 {
		t.Errorf("FailuresRequired = %d, want 6", cfg.Failover.FailuresRequired)
	}
}

func TestCmdFailover_SetRejectsBadValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"failover", "set", "failures_required", "0"}); err == nil {
		t.Error("expected an error for a non-positive failures_required")
	}
	if err := run([]string{"failover", "set", "unknown_key", "1"}); err == nil {
		t.Error("expected an error for an unknown key")
	}
}
