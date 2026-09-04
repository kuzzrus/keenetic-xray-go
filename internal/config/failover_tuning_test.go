package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailoverConfig_SetTunable(t *testing.T) {
	f := DefaultFailoverConfig()

	cases := []struct {
		key, val string
		wantErr  bool
	}{
		{"check_interval_seconds", "20", false},
		{"check_interval_seconds", "0", true},
		{"check_interval_seconds", "nope", true},
		{"failures_required", "5", false},
		{"failures_required", "-1", true},
		{"recovery_successes_required", "5", false},
		{"cooldown_cycles", "0", false},
		{"cooldown_cycles", "-1", true},
		{"rollback_backoff_seconds", "600", false},
		{"check_retries", "3", false},
		{"check_retry_delay_seconds", "5", false},
		{"health_check_url", "https://example.com/204", false},
		{"health_check_url", "ftp://example.com", true},
		{"nonsense_key", "1", true},
	}
	for _, c := range cases {
		err := f.SetTunable(c.key, c.val)
		if c.wantErr && err == nil {
			t.Errorf("SetTunable(%q, %q): want error, got nil", c.key, c.val)
		}
		if !c.wantErr && err != nil {
			t.Errorf("SetTunable(%q, %q): unexpected error: %v", c.key, c.val, err)
		}
	}

	if f.CheckIntervalSeconds != 20 || f.FailuresRequired != 5 || f.CheckRetries != 3 {
		t.Errorf("valid sets did not stick: %+v", f)
	}
}

func TestFailoverConfig_TunablesText(t *testing.T) {
	f := DefaultFailoverConfig()
	text := f.TunablesText()
	for _, want := range []string{"check_interval_seconds: 10", "failures_required: 3", "check_retries: 1", "health_check_url: https://www.gstatic.com/generate_204", "health_check_fallback_urls:"} {
		if !strings.Contains(text, want) {
			t.Errorf("TunablesText() missing %q:\n%s", want, text)
		}
	}
}

// TestLoad_UpgradesOldConfigWithNewFailoverDefaults is the regression test
// for the auto-upgrade claim: a config.json saved before CheckRetries /
// HealthCheckFallbackURLs existed must pick up their new defaults on load,
// not zero values -- because Load starts from DefaultFailoverConfig() and
// only overwrites what's actually present in the file.
func TestLoad_UpgradesOldConfigWithNewFailoverDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	// Deliberately the pre-retry/fallback shape: no check_retries, no
	// check_retry_delay_seconds, no health_check_fallback_urls.
	oldShape := `{
		"variant": "full",
		"primary_index": -1,
		"backup_index": -1,
		"failover": {
			"check_interval_seconds": 10,
			"failures_required": 3,
			"recovery_successes_required": 3,
			"cooldown_cycles": 2,
			"rollback_backoff_seconds": 300,
			"health_check_url": "https://www.gstatic.com/generate_204",
			"socks_port": 1080,
			"http_port": 1081,
			"pretest_port": 11080
		}
	}`
	if err := os.WriteFile(path, []byte(oldShape), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := DefaultFailoverConfig()
	if cfg.Failover.CheckRetries != want.CheckRetries {
		t.Errorf("CheckRetries = %d, want the default %d", cfg.Failover.CheckRetries, want.CheckRetries)
	}
	if cfg.Failover.CheckRetryDelaySeconds != want.CheckRetryDelaySeconds {
		t.Errorf("CheckRetryDelaySeconds = %d, want the default %d", cfg.Failover.CheckRetryDelaySeconds, want.CheckRetryDelaySeconds)
	}
	if len(cfg.Failover.HealthCheckFallbackURLs) != len(want.HealthCheckFallbackURLs) {
		t.Errorf("HealthCheckFallbackURLs = %v, want %v", cfg.Failover.HealthCheckFallbackURLs, want.HealthCheckFallbackURLs)
	}
}
