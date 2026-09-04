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

// TestApplyResult_UnmatchedDoesNotGuess covers the >1-profile case: with
// a real choice to make and no confident match, ApplyResult must not
// guess. (With exactly one fetched profile there's no guess involved --
// see TestApplyResult_SingleProfileDefaultsUnmatchedSlots.)
func TestApplyResult_UnmatchedDoesNotGuess(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{{Remark: "old-primary"}}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0

	result := RefreshResult{
		Profiles: []config.Profile{
			{Remark: "new-name", UUID: "a", Address: "a.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
			{Remark: "other", UUID: "b", Address: "b.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
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

// TestApplyResult_SingleProfileDefaultsUnmatchedSlots is the regression
// test for the incident that motivated it: a subscription that now
// returns exactly one profile (the previous remark gone) must not leave
// the daemon idling with both slots unset -- default them to the sole
// profile instead, silently (no "pick one" warning that implies a choice
// that doesn't actually exist).
func TestApplyResult_SingleProfileDefaultsUnmatchedSlots(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{{Remark: "old-primary"}, {Remark: "old-backup"}}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1

	result := RefreshResult{
		Profiles: []config.Profile{
			{Remark: "new-name", UUID: "a", Address: "a.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
		},
		PrimaryIndex: -1, PrimaryStatus: MatchNotFound,
		BackupIndex: -1, BackupStatus: MatchNotFound,
	}

	warnings := ApplyResult(cfg, result)
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none (a single-profile default isn't a problem)", warnings)
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 0 {
		t.Errorf("PrimaryIndex/BackupIndex = %d/%d, want 0/0 (the daemon must keep running)", cfg.PrimaryIndex, cfg.BackupIndex)
	}
}

// TestApplyResult_IndependentSlotSurvivesRefresh is the regression test
// for the incident itself: refreshing the shared Subscription must not
// discard a backup fed by its own independent SlotSource -- even when
// the fresh fetch has nothing in common with it.
func TestApplyResult_IndependentSlotSurvivesRefresh(t *testing.T) {
	independentBackup := config.Profile{
		Remark: "backup-node", UUID: "bk", Address: "backup.example.com", Port: 443,
		Network: "tcp", Security: "none", Encryption: "none",
	}
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{Remark: "old-primary", UUID: "old", Address: "old.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
		independentBackup,
	}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.BackupSource = &config.SlotSource{URL: "vless://bk@backup.example.com:443"}

	// The shared subscription refreshes to a single, unrelated profile;
	// neither old remark matches it.
	result := RefreshResult{
		Profiles: []config.Profile{
			{Remark: "new-primary", UUID: "new", Address: "new.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none"},
		},
		PrimaryIndex: -1, PrimaryStatus: MatchNotFound,
		BackupIndex: -1, BackupStatus: MatchNotFound,
	}

	ApplyResult(cfg, result)

	if got := cfg.Backup(); got == nil || got.UUID != "bk" {
		t.Fatalf("Backup() = %+v, want the independently-sourced backup-node to survive", got)
	}
	if got := cfg.Primary(); got == nil || got.UUID != "new" {
		t.Errorf("Primary() = %+v, want the freshly-fetched single profile (not independently sourced)", got)
	}
	if len(cfg.Profiles) != 2 {
		t.Errorf("Profiles = %+v, want exactly 2 (the fresh one + the preserved backup, no duplicates)", cfg.Profiles)
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
