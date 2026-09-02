package subscription

import (
	"fmt"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// ApplyResult mutates cfg in place to reflect a successful Refresh:
// replaces Profiles, stamps Subscription.LastFetchedAt, and sets
// PrimaryIndex/BackupIndex only where the match was unique -- leaving an
// index at -1 (with a warning appended) otherwise, exactly matching
// Refresh's own fail-safe design. The caller (CLI, bot) is responsible
// for cfg.Save afterward; this is the one place that logic lives so both
// frontends apply a refresh identically.
func ApplyResult(cfg *config.Config, result RefreshResult) (warnings []string) {
	warnings = append(warnings, result.Warnings...)

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
		warnings = append(warnings, fmt.Sprintf("could not re-match primary (%s) -- pick one with subscription set-primary", matchStatusReason(result.PrimaryStatus)))
	}

	if result.BackupStatus == MatchUnique {
		cfg.BackupIndex = result.BackupIndex
		if cfg.Subscription != nil {
			cfg.Subscription.BackupKey = result.Profiles[result.BackupIndex].Remark
		}
	} else {
		cfg.BackupIndex = -1
		warnings = append(warnings, fmt.Sprintf("could not re-match backup (%s) -- pick one with subscription set-backup", matchStatusReason(result.BackupStatus)))
	}

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
