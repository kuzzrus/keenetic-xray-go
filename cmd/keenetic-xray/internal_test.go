package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdInternal_PostinstSetupThenPrermCleanup(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "etc", "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_PRODUCTION_CONFIG", filepath.Join(dir, "lib", "xray-production.json"))
	t.Setenv("KEENETIC_XRAY_LOG_DIR", filepath.Join(dir, "log"))
	t.Setenv("KEENETIC_XRAY_RUN_DIR", filepath.Join(dir, "run"))
	t.Setenv("KEENETIC_XRAY_OPT", dir)

	if err := run([]string{"internal", "postinst-setup"}); err != nil {
		t.Fatalf("postinst-setup: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Variant != config.VariantFull {
		t.Errorf("Variant = %q, want %q (plenty of space in a tmpdir)", cfg.Variant, config.VariantFull)
	}
	if _, err := os.Stat(filepath.Dir(configFile)); err != nil {
		t.Errorf("config dir should exist: %v", err)
	}

	// A second postinst-setup run (upgrade case) must not touch an
	// already-configured config.json.
	cfg.Profiles = []config.Profile{{
		UUID: "u", Address: "a", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "keep-me",
	}}
	cfg.PrimaryIndex = 0
	if err := cfg.Save(configFile); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"internal", "postinst-setup"}); err != nil {
		t.Fatalf("second postinst-setup: %v", err)
	}
	got, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load after second postinst-setup: %v", err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Remark != "keep-me" {
		t.Errorf("upgrade should not touch existing config: %#v", got.Profiles)
	}

	// prerm-cleanup without --purge leaves everything alone.
	if err := run([]string{"internal", "prerm-cleanup"}); err != nil {
		t.Fatalf("prerm-cleanup: %v", err)
	}
	if _, err := os.Stat(configFile); err != nil {
		t.Errorf("config.json should survive a non-purge prerm-cleanup: %v", err)
	}

	// prerm-cleanup --purge removes it.
	if err := run([]string{"internal", "prerm-cleanup", "--purge"}); err != nil {
		t.Fatalf("prerm-cleanup --purge: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(configFile)); !os.IsNotExist(err) {
		t.Errorf("config dir should be removed after --purge, stat err = %v", err)
	}
}
