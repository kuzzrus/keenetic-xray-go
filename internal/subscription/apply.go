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
// Refresh itself already fails a fetch that errored or came back with no
// usable entries, so a *failed* or *empty* refresh never reaches here.
// On top of that, three safety nets keep a *successful but changed*
// refresh from losing the server that's actually carrying traffic:
//
//   - A slot fed by its own independent SlotSource (PrimarySource /
//     BackupSource, the bot's 🔗 Источники) is never touched by a refresh
//     of the *shared* Subscription -- see SnapshotIndependentSlots.
//   - If the shared active/backup profile can't be re-matched by remark
//     but a fresh profile has the same Profile.ImportKey (the provider
//     renamed the node), that fresh profile is adopted and the stored key
//     updated -- a rename no longer drops the slot.
//   - If it still can't be found and there's more than one fresh profile
//     to choose from, the slot *keeps its last-good profile* (re-added to
//     the pool) rather than being left unset. Idling the daemon, or
//     guessing some other server, is worse than staying put on a server
//     that may simply have vanished from the list; the operator gets a
//     loud warning to re-pick. With exactly one fresh profile the slot
//     defaults to it instead (no real choice to make).
func ApplyResult(cfg *config.Config, result RefreshResult) (warnings []string) {
	warnings = append(warnings, result.Warnings...)
	independent := cfg.SnapshotIndependentSlots()

	// Snapshot the shared-subscription primary/backup *before* the pool is
	// replaced, so an unmatched slot can fall back to its last-good entry.
	var oldPrimary, oldBackup *config.Profile
	if independent.Primary == nil {
		if p := cfg.Primary(); p != nil {
			cp := *p
			oldPrimary = &cp
		}
	}
	if independent.Backup == nil {
		if p := cfg.Backup(); p != nil {
			cp := *p
			oldBackup = &cp
		}
	}

	cfg.Profiles = result.Profiles
	var primaryKey, backupKey *string
	if cfg.Subscription != nil {
		cfg.Subscription.LastFetchedAt = time.Now()
		primaryKey, backupKey = &cfg.Subscription.PrimaryKey, &cfg.Subscription.BackupKey
	}

	cfg.PrimaryIndex, warnings = resolveSharedSlot(cfg, "основной",
		result.PrimaryIndex, result.PrimaryStatus, oldPrimary, primaryKey, warnings)
	cfg.BackupIndex, warnings = resolveSharedSlot(cfg, "резервный",
		result.BackupIndex, result.BackupStatus, oldBackup, backupKey, warnings)

	// Single-profile default: a slot that isn't independently sourced and
	// is still unset takes the sole fresh profile (see the doc comment).
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

// resolveSharedSlot decides one shared-subscription slot's index against a
// freshly-replaced cfg.Profiles: a confident remark match wins; else an
// ImportKey match (renamed node) wins and updates the stored key; else,
// when there's a real choice among several fresh profiles, the slot keeps
// its last-good profile (old) re-added to the pool; else -1 for the
// caller's single-profile default / "re-pick" warning.
func resolveSharedSlot(cfg *config.Config, label string, matchIndex int, status MatchResult, old *config.Profile, key *string, warnings []string) (int, []string) {
	setKey := func(k string) {
		if key != nil {
			*key = k
		}
	}
	if status == MatchUnique {
		setKey(cfg.Profiles[matchIndex].Remark)
		return matchIndex, warnings
	}

	if old != nil {
		want := old.ImportKey()
		for i := range cfg.Profiles {
			if cfg.Profiles[i].ImportKey() == want {
				setKey(cfg.Profiles[i].Remark)
				warnings = append(warnings, fmt.Sprintf("%s: сервер переименован в подписке — сопоставлен по отпечатку соединения (%s)", label, cfg.Profiles[i].Remark))
				return i, warnings
			}
		}
	}

	if len(cfg.Profiles) == 1 {
		return -1, warnings // caller defaults it to the sole profile
	}

	if old != nil {
		idx := cfg.UpsertProfile(*old)
		warnings = append(warnings, fmt.Sprintf("%s: «%s» пропал из подписки — оставлен прежний сервер; выбери новый через 🔗 Источники / subscription set-%s", label, old.Remark, slotWord(label)))
		return idx, warnings
	}

	warnings = append(warnings, fmt.Sprintf("could not re-match %s (%s) -- pick one with subscription set-%s", slotWord(label), matchStatusReason(status), slotWord(label)))
	return -1, warnings
}

func slotWord(label string) string {
	if label == "основной" {
		return "primary"
	}
	return "backup"
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
