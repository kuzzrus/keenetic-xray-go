package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestCmdAgent_ConfigureEnableDisable(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")
	tokenFile := filepath.Join(dir, "token.secret")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_AGENT_TOKEN_FILE", tokenFile)

	if err := run([]string{"agent", "configure", "https://vps.example.com:8443", "router-1", "deadbeef", "s3cr3t"}); err != nil {
		t.Fatalf("agent configure: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.ControlServerURL != "https://vps.example.com:8443" || cfg.Agent.RouterID != "router-1" || cfg.Agent.FingerprintSHA256 != "deadbeef" {
		t.Errorf("Agent config = %+v", cfg.Agent)
	}
	if cfg.Agent.Enabled {
		t.Error("Agent should not be enabled by configure alone")
	}

	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatalf("reading token file: %v", err)
	}
	if string(tokenBytes) != "s3cr3t\n" {
		t.Errorf("token file contents = %q, want %q", tokenBytes, "s3cr3t\n")
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("token file mode = %o, want 0600", perm)
	}

	if err := run([]string{"agent", "enable"}); err != nil {
		t.Fatalf("agent enable: %v", err)
	}
	cfg, _ = config.Load(configFile)
	if !cfg.Agent.Enabled {
		t.Error("Agent should be enabled after `agent enable`")
	}

	if err := run([]string{"agent", "disable"}); err != nil {
		t.Fatalf("agent disable: %v", err)
	}
	cfg, _ = config.Load(configFile)
	if cfg.Agent.Enabled {
		t.Error("Agent should be disabled after `agent disable`")
	}

	if err := run([]string{"agent", "status"}); err != nil {
		t.Fatalf("agent status: %v", err)
	}
}

func TestCmdAgent_EnableWithoutConfigureErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"agent", "enable"}); err == nil {
		t.Error("expected error enabling an unconfigured agent")
	}
}

func TestCmdAgent_EnableRejectedOnMiniVariant(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_AGENT_TOKEN_FILE", filepath.Join(dir, "token.secret"))

	if err := run([]string{"agent", "configure", "https://vps.example.com:8443", "router-1", "deadbeef", "s3cr3t"}); err != nil {
		t.Fatalf("agent configure: %v", err)
	}
	if err := run([]string{"variant", "set", "mini"}); err != nil {
		t.Fatalf("variant set mini: %v", err)
	}

	if err := run([]string{"agent", "enable"}); err == nil {
		t.Error("expected error enabling the agent on the Mini variant")
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.Enabled {
		t.Error("Agent.Enabled should remain false after a rejected enable")
	}
}

func TestLoadAgentOptions_MissingTokenFile(t *testing.T) {
	cfg := config.Default()
	cfg.Agent.ControlServerURL = "https://x"
	cfg.Agent.RouterID = "r"
	cfg.Agent.FingerprintSHA256 = "ab"
	cfg.Agent.TokenFile = "/this/does/not/exist"

	if _, err := loadAgentOptions(cfg); err == nil {
		t.Error("expected error for a missing token file")
	}
}
