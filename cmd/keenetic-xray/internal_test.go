package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

func TestCmdInternal_PostinstSetupThenPrermCleanup(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "etc", "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_PRODUCTION_CONFIG", filepath.Join(dir, "lib", "xray-production.json"))
	t.Setenv("KEENETIC_XRAY_LOG_DIR", filepath.Join(dir, "log"))
	t.Setenv("KEENETIC_XRAY_RUN_DIR", filepath.Join(dir, "run"))
	t.Setenv("KEENETIC_XRAY_OPT", dir)
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(dir, "cron", "root"))

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
	if enabled, err := install.WatchdogEnabled(cronFilePath()); err != nil || !enabled {
		t.Errorf("watchdog should be enabled after postinst-setup: enabled=%v err=%v", enabled, err)
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

	// Proxy0 is on by default in a fresh config...
	fresh := filepath.Join(t.TempDir(), "fresh.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", fresh)
	if err := run([]string{"internal", "postinst-setup"}); err != nil {
		t.Fatalf("postinst-setup (fresh): %v", err)
	}
	if c, _ := config.Load(fresh); !c.Proxy0.Enabled {
		t.Error("fresh config: Proxy0.Enabled should default to true")
	}
	// ...unless install.sh passed --no-proxy0.
	noP := filepath.Join(t.TempDir(), "noproxy.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", noP)
	t.Setenv("KEENETIC_XRAY_NO_PROXY0", "1")
	if err := run([]string{"internal", "postinst-setup"}); err != nil {
		t.Fatalf("postinst-setup (--no-proxy0): %v", err)
	}
	if c, _ := config.Load(noP); c.Proxy0.Enabled {
		t.Error("KEENETIC_XRAY_NO_PROXY0 should turn Proxy0 off")
	}
	t.Setenv("KEENETIC_XRAY_NO_PROXY0", "")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)

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

func TestNdmHookPaths_DerivesSiblings(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_NETFILTER_HOOK", "/x/ndm/netfilter.d/50-keenetic-xray.sh")
	got := ndmHookPaths()
	// The daemon only ever runs on Linux; normalise separators so the
	// derivation is still checkable from the Windows dev box.
	want := []string{
		"/x/ndm/netfilter.d/50-keenetic-xray.sh",
		"/x/ndm/ifipchanged.d/50-keenetic-xray.sh",
		"/x/ndm/ifstatechanged.d/50-keenetic-xray.sh",
	}
	if len(got) != len(want) {
		t.Fatalf("ndmHookPaths() = %v, want %v", got, want)
	}
	for i := range want {
		if filepath.ToSlash(got[i]) != want[i] {
			t.Errorf("ndmHookPaths()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// prerm-cleanup drops every ndm hook, not just netfilter.d, so a botched
// removal can't leave one behind SIGUSR1'ing a dead PID.
func TestCmdInternal_PrermCleanupRemovesAllNdmHooks(t *testing.T) {
	dir := t.TempDir()
	nf := filepath.Join(dir, "ndm", "netfilter.d", "50-keenetic-xray.sh")
	t.Setenv("KEENETIC_XRAY_NETFILTER_HOOK", nf)
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "etc", "config.json"))

	hooks := ndmHookPaths()
	for _, h := range hooks {
		if err := os.MkdirAll(filepath.Dir(h), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := run([]string{"internal", "prerm-cleanup"}); err != nil {
		t.Fatalf("prerm-cleanup: %v", err)
	}
	for _, h := range hooks {
		if _, err := os.Stat(h); !os.IsNotExist(err) {
			t.Errorf("hook %s should be gone after prerm-cleanup, stat err = %v", h, err)
		}
	}
}

func TestCmdEnsureXrayCore_TagPersistsBeforeDownload(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "etc", "keenetic-xray", "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_BINARY", filepath.Join(dir, "xray"))
	t.Setenv("KEENETIC_XRAY_CORE", "vendored")
	// Point the download at a dead local address so the fetch fails
	// instantly -- we only care that the tag is validated and saved first.
	t.Setenv("KEENETIC_XRAY_CORE_BASE_URL", "http://127.0.0.1:0")

	// An explicit --tag is recorded to config even though the fetch that
	// follows can't succeed in a test.
	_ = run([]string{"internal", "ensure-xray-core", "--tag=v26.9.8"})
	if cfg, err := config.Load(configFile); err != nil || cfg.XrayCoreTag != "v26.9.8" {
		t.Fatalf("XrayCoreTag = %q (err %v), want v26.9.8 persisted", cfg.XrayCoreTag, err)
	}

	// "stable" clears it again.
	_ = run([]string{"internal", "ensure-xray-core", "--tag=stable"})
	if cfg, _ := config.Load(configFile); cfg.XrayCoreTag != "" {
		t.Errorf("XrayCoreTag = %q, want cleared by --tag=stable", cfg.XrayCoreTag)
	}

	// A malformed tag is rejected and nothing is written.
	if err := run([]string{"internal", "ensure-xray-core", "--tag=nightly"}); err == nil {
		t.Error("expected an error for --tag=nightly")
	}
}
