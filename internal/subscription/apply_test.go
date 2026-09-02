package subscription

import (
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestApplyResult_UniqueMatches(t *testing.T) {
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: "https://example.com/sub"}

	result := RefreshResult{
		Profiles: []config.Profile{
			{Remark: "alpha", UUID: "a", Address: "a.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
			{Remark: "beta", UUID: "b", Address: "b.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
		},
		PrimaryIndex: 0, PrimaryStatus: MatchUnique,
		BackupIndex: 1, BackupStatus: MatchUnique,
	}

	warnings := ApplyResult(cfg, result)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Errorf("PrimaryIndex/BackupIndex = %d/%d, want 0/1", cfg.PrimaryIndex, cfg.BackupIndex)
	}
	if cfg.Subscription.PrimaryKey != "alpha" || cfg.Subscription.BackupKey != "beta" {
		t.Errorf("Subscription keys = %q/%q, want alpha/beta", cfg.Subscription.PrimaryKey, cfg.Subscription.BackupKey)
	}
	if cfg.Subscription.LastFetchedAt.IsZero() {
		t.Error("LastFetchedAt should be set")
	}
}

func TestApplyResult_UnmatchedDoesNotGuess(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{{Remark: "old-primary"}}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0

	result := RefreshResult{
		Profiles: []config.Profile{
			{Remark: "new-name", UUID: "a", Address: "a.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
		},
		PrimaryIndex: -1, PrimaryStatus: MatchNotFound,
		BackupIndex: -1, BackupStatus: MatchAmbiguous,
	}

	warnings := ApplyResult(cfg, result)
	if len(warnings) != 2 {
		t.Fatalf("warnings = %v, want 2 (primary not found, backup ambiguous)", warnings)
	}
	if cfg.PrimaryIndex != -1 || cfg.BackupIndex != -1 {
		t.Errorf("PrimaryIndex/BackupIndex = %d/%d, want -1/-1 (must not guess)", cfg.PrimaryIndex, cfg.BackupIndex)
	}
}

func TestApplyResult_NilSubscriptionIsSafe(t *testing.T) {
	cfg := config.Default() // cfg.Subscription is nil
	result := RefreshResult{
		Profiles:     []config.Profile{{Remark: "a", UUID: "u", Address: "h", Port: 443, Network: "tcp", Security: "none", Encryption: "none"}},
		PrimaryIndex: 0, PrimaryStatus: MatchUnique,
		BackupIndex: 0, BackupStatus: MatchUnique,
	}
	// Must not panic on a nil Subscription.
	ApplyResult(cfg, result)
	if cfg.PrimaryIndex != 0 {
		t.Errorf("PrimaryIndex = %d, want 0", cfg.PrimaryIndex)
	}
}
