package main

import (
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS != "windows" { // POSIX mode bits aren't meaningful on Windows; the agent only runs on Linux
		info, err := os.Stat(tokenFile)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("token file mode = %o, want 0600", perm)
		}
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

// TestCmdAgent_ConfigureWithoutFingerprintEnablesCleanly is the 3-arg
// form (no fingerprint -- CA-trust mode via a domain with an ACME-issued
// certificate, see internal/botcontrol's autocert support). Enable must
// succeed too: a stale "fingerprint required" check here would let
// `configure` pass but then block `enable` right after, contradicting
// the 3-arg form configure itself accepts.
func TestCmdAgent_ConfigureWithoutFingerprintEnablesCleanly(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.json")
	tokenFile := filepath.Join(dir, "token.secret")
	t.Setenv("KEENETIC_XRAY_CONFIG", configFile)
	t.Setenv("KEENETIC_XRAY_AGENT_TOKEN_FILE", tokenFile)

	if err := run([]string{"agent", "configure", "https://vps.example.com:8443", "router-1", "s3cr3t"}); err != nil {
		t.Fatalf("agent configure (3-arg): %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Agent.ControlServerURL != "https://vps.example.com:8443" || cfg.Agent.RouterID != "router-1" {
		t.Errorf("Agent config = %+v", cfg.Agent)
	}
	if cfg.Agent.FingerprintSHA256 != "" {
		t.Errorf("FingerprintSHA256 = %q, want empty for the 3-arg CA-trust form", cfg.Agent.FingerprintSHA256)
	}

	if err := run([]string{"agent", "enable"}); err != nil {
		t.Fatalf("agent enable after fingerprint-less configure: %v", err)
	}
	cfg, _ = config.Load(configFile)
	if !cfg.Agent.Enabled {
		t.Error("Agent should be enabled")
	}
}

func TestCmdAgent_ConfigureBadArgCount(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))
	for _, args := range [][]string{
		{"agent", "configure"},
		{"agent", "configure", "url"},
		{"agent", "configure", "url", "id"},
		{"agent", "configure", "url", "id", "fp", "token", "extra"},
	} {
		if err := run(args); err == nil {
			t.Errorf("run(%v) expected a usage error", args)
		}
	}
}

func TestCmdAgent_EnableWithoutConfigureErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"agent", "enable"}); err == nil {
		t.Error("expected error enabling an unconfigured agent")
	}
}

// The agent is no longer Full-gated -- it enables fine on Mini.
func TestCmdAgent_EnableAllowedOnMiniVariant(t *testing.T) {
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
	if err := run([]string{"agent", "enable"}); err != nil {
		t.Fatalf("agent enable on mini: %v", err)
	}

	cfg, err := config.Load(configFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Agent.Enabled {
		t.Error("Agent.Enabled should be true after enable on mini")
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
