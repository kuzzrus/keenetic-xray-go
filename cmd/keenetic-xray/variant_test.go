package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdVariant_ShowDefaultsToFull(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"variant", "show"}); err != nil {
		t.Fatalf("variant show: %v", err)
	}
}

func TestCmdVariant_Set(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	if err := run([]string{"variant", "set", "mini"}); err != nil {
		t.Fatalf("variant set mini: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Variant != config.VariantMini {
		t.Errorf("Variant = %q, want %q", cfg.Variant, config.VariantMini)
	}
}

func TestCmdVariant_SetRejectsUnknown(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"variant", "set", "extreme"}); err == nil {
		t.Error("expected error for an unknown variant")
	}
}

func TestCmdVariant_SetMiniDisablesEnabledAgent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	t.Setenv("KEENETIC_XRAY_AGENT_TOKEN_FILE", filepath.Join(dir, "token.secret"))

	if err := run([]string{"agent", "configure", "https://vps.example.com:8443", "router-1", "deadbeef", "s3cr3t"}); err != nil {
		t.Fatalf("agent configure: %v", err)
	}
	if err := run([]string{"agent", "enable"}); err != nil {
		t.Fatalf("agent enable: %v", err)
	}

	if err := run([]string{"variant", "set", "mini"}); err != nil {
		t.Fatalf("variant set mini: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.Enabled {
		t.Error("Agent.Enabled should be forced false after downgrading to mini")
	}
}
