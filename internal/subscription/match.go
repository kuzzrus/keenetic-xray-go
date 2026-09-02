package subscription

import (
	"context"
	"fmt"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// MatchResult reports how confidently a remark could be matched against a
// freshly-fetched profile list.
type MatchResult int

const (
	// MatchNotFound means no profile in the new list has this remark.
	MatchNotFound MatchResult = iota
	// MatchUnique means exactly one profile matched -- safe to use.
	MatchUnique
	// MatchAmbiguous means more than one profile shares this remark --
	// not safe to guess which one is "the" primary/backup.
	MatchAmbiguous
)

// MatchByRemark looks for profiles whose Remark equals remark. It never
// guesses: a tie counts as MatchAmbiguous, not "the first one".
func MatchByRemark(profiles []config.Profile, remark string) (index int, result MatchResult) {
	if remark == "" {
		return -1, MatchNotFound
	}
	found := -1
	count := 0
	for i, p := range profiles {
		if p.Remark == remark {
			count++
			if found == -1 {
				found = i
			}
		}
	}
	switch count {
	case 0:
		return -1, MatchNotFound
	case 1:
		return found, MatchUnique
	default:
		return -1, MatchAmbiguous
	}
}

// RefreshResult is the outcome of Refresh: the freshly-parsed profile
// list, any lines that had to be skipped, and -- for each of
// primary/backup -- either its new index (if it could be confidently
// re-matched by remark) or -1 with a MatchResult explaining why not.
type RefreshResult struct {
	Profiles      []config.Profile
	Warnings      []string
	PrimaryIndex  int
	PrimaryStatus MatchResult
	BackupIndex   int
	BackupStatus  MatchResult
}

// Refresh fetches, decodes, and parses the subscription at url, then tries
// to re-match the previously-selected primary/backup by remark
// (previousPrimaryKey/previousBackupKey, normally
// config.Subscription.PrimaryKey/BackupKey).
//
// It never repoints live traffic at a guess: callers should only update
// Config.PrimaryIndex/BackupIndex when the corresponding *Status is
// MatchUnique, and surface a warning otherwise so the user can re-pick
// manually (e.g. via `subscription list` + `subscription set-primary`) --
// a botched auto-match silently changing which server carries traffic is
// worse than a no-op.
func Refresh(ctx context.Context, url, previousPrimaryKey, previousBackupKey string) (RefreshResult, error) {
	body, err := Fetch(ctx, url)
	if err != nil {
		return RefreshResult{}, fmt.Errorf("fetching subscription: %w", err)
	}

	decoded := Decode(body)
	profiles, warnings := Parse(decoded)
	if len(profiles) == 0 {
		return RefreshResult{}, fmt.Errorf("subscription contained no usable vless:// entries")
	}

	primaryIndex, primaryStatus := MatchByRemark(profiles, previousPrimaryKey)
	backupIndex, backupStatus := MatchByRemark(profiles, previousBackupKey)

	return RefreshResult{
		Profiles:      profiles,
		Warnings:      warnings,
		PrimaryIndex:  primaryIndex,
		PrimaryStatus: primaryStatus,
		BackupIndex:   backupIndex,
		BackupStatus:  backupStatus,
	}, nil
}
