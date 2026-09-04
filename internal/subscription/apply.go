package subscription

import (
	"fmt"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// ApplyResult mutates cfg in place to reflect a successful Refresh:
// replaces Profiles, stamps Subscription.LastFetchedAt, and sets
// PrimaryIndex/BackupIndex from the fresh list. The caller (CLI, bot) is
// responsible for cfg.Save afterward; this is the one place that logic
// lives so both frontends apply a refresh identically.
//
// Two safety nets on top of Refresh's own remark-matching:
//
//   - A slot fed by its own independent SlotSource (PrimarySource /
//     BackupSource, set via the bot's 🔗 Источники) is never touched by a
//     refresh of the *shared* Subscription -- that slot's profile isn't
//     from this subscription at all, so replacing Profiles wholesale must
//     not silently discard it. This is what protects a mixed primary/
//     backup-from-different-sources setup.
//   - If a slot still has no match (not independently sourced, remark
//     gone) but the fresh list has exactly one usable profile, that slot
//     defaults to it rather than being left unset -- same convenience
//     `keenetic-xray setup` already applies for a single-profile source,
//     now also on refresh. Leaving both primary and backup unset idles
//     the daemon entirely, which is a worse outcome than a failover-free
//     single profile the operator can fix at their leisure.
func ApplyResult(cfg *config.Config, result RefreshResult) (warnings []string) {
	warnings = append(warnings, result.Warnings...)
	independent := cfg.SnapshotIndependentSlots()

	cfg.Profiles = result.Profiles
	if cfg.Subscription != nil {
		cfg.Subscription.LastFetchedAt = time.Now()
	}

	if result.PrimaryStatus == MatchUnique {
		cfg.PrimaryIndex = result.PrimaryIndex
		if cfg.Subscription != nil {
			cfg.Subscription.PrimaryKey = result.Profiles[result.PrimaryIndex].Remark
		}
	} else {
		cfg.PrimaryIndex = -1
		if independent.Primary == nil && len(result.Profiles) != 1 {
			warnings = append(warnings, fmt.Sprintf("could not re-match primary (%s) -- pick one with subscription set-primary", matchStatusReason(result.PrimaryStatus)))
		}
	}

	if result.BackupStatus == MatchUnique {
		cfg.BackupIndex = result.BackupIndex
		if cfg.Subscription != nil {
			cfg.Subscription.BackupKey = result.Profiles[result.BackupIndex].Remark
		}
	} else {
		cfg.BackupIndex = -1
		if independent.Backup == nil && len(result.Profiles) != 1 {
			warnings = append(warnings, fmt.Sprintf("could not re-match backup (%s) -- pick one with subscription set-backup", matchStatusReason(result.BackupStatus)))
		}
	}

	// Single-profile default: only for a slot that isn't independently
	// sourced (that always wins via Restore below) and still unset.
	if len(result.Profiles) == 1 {
		if cfg.PrimaryIndex < 0 && independent.Primary == nil {
			cfg.PrimaryIndex = 0
		}
		if cfg.BackupIndex < 0 && independent.Backup == nil {
			cfg.BackupIndex = 0
		}
	}

	independent.Restore(cfg)

	return warnings
}

func matchStatusReason(s MatchResult) string {
	switch s {
	case MatchNotFound:
		return "not found in the refreshed list"
	case MatchAmbiguous:
		return "ambiguous -- multiple profiles share that name"
	default:
		return "no prior selection"
	}
}
