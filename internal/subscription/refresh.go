package subscription

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// ErrNothingToRefresh is what RefreshConfig returns for a config with neither
// a shared subscription URL nor an independently-sourced slot.
var ErrNothingToRefresh = errors.New("no subscription URL or slot sources set")

// SourceReport is the outcome for one independently-sourced slot.
type SourceReport struct {
	Slot   string // "primary" | "backup"
	Remark string // the profile the slot now points at (empty when Err is set)
	Err    error
}

// Report says what a RefreshConfig did, for the CLI, the bot and the daemon's
// own periodic refresh to phrase each in its own way.
type Report struct {
	Shared   bool     // the shared Subscription was fetched
	Profiles int      // how many profiles it held
	Warnings []string // parse warnings and re-match notes (see ApplyResult)
	// SlotNotes is the part of Warnings that needs the operator: a slot whose
	// server is gone from the subscription (kept as it was) or could not be
	// re-matched. Not the lines the parser skipped, which a provider repeats on
	// every fetch, and not a server that was merely renamed -- that is matched by
	// its connection fingerprint and is no cause for a message.
	SlotNotes []string
	Sources   []SourceReport
}

// RefreshConfig re-fetches everything in cfg that has a source -- the shared
// Subscription, then each independently-sourced slot -- and applies it to cfg
// in place: ApplyResult for the shared list (which deliberately leaves the
// independent slots alone), then each slot re-resolved by its ImportKey anchor
// and upserted over its index. It does not save cfg; the caller does, and tells
// the daemon.
//
// A failed fetch of the shared subscription is returned as an error with cfg
// untouched. A failing slot source does not abort the others: it is reported
// in Report.Sources.
//
// One implementation for the CLI's `subscription refresh`, the bot's
// 🔄 Обновить подписку and the daemon's periodic refresh, so they cannot drift.
func RefreshConfig(ctx context.Context, cfg *config.Config) (Report, error) {
	var rep Report
	hasShared := cfg.Subscription != nil && cfg.Subscription.URL != ""
	hasSlots := cfg.PrimarySource != nil || cfg.BackupSource != nil
	if !hasShared && !hasSlots {
		return rep, ErrNothingToRefresh
	}

	if hasShared {
		var primaryKey, backupKey string
		if p := cfg.Primary(); p != nil {
			primaryKey = p.Remark
		}
		if b := cfg.Backup(); b != nil {
			backupKey = b.Remark
		}
		result, err := Refresh(ctx, cfg.Subscription.URL, primaryKey, backupKey)
		if err != nil {
			return Report{}, err
		}
		rep.Shared, rep.Profiles = true, len(result.Profiles)
		// ApplyResult returns result.Warnings first, then its own slot notes.
		rep.Warnings = ApplyResult(cfg, result)
		for _, n := range rep.Warnings[len(result.Warnings):] {
			if !strings.Contains(n, renamedNote) {
				rep.SlotNotes = append(rep.SlotNotes, n)
			}
		}
	}

	// A shared-subscription refresh deliberately leaves independently-sourced
	// slots alone, so each is re-fetched here -- otherwise a provider's node
	// changes (and a new build's parsing) never reach them without re-pasting
	// the URL by hand.
	for _, s := range []struct {
		slot    string
		src     *config.SlotSource
		primary bool
	}{
		{"primary", cfg.PrimarySource, true},
		{"backup", cfg.BackupSource, false},
	} {
		if s.src == nil {
			continue
		}
		prof, key, err := ResolveSourcePinned(ctx, s.src.URL, s.src.Selector, s.src.ImportKey)
		if err != nil {
			rep.Sources = append(rep.Sources, SourceReport{Slot: s.slot, Err: err})
			continue
		}
		s.src.ImportKey = key // anchor (or backfill) so future refreshes stay on this server
		idx := cfg.UpsertProfile(prof)
		if s.primary {
			cfg.PrimaryIndex = idx
		} else {
			cfg.BackupIndex = idx
		}
		rep.Sources = append(rep.Sources, SourceReport{Slot: s.slot, Remark: prof.Remark})
	}
	return rep, nil
}

// HasRemote reports whether cfg has anything a periodic refresh would fetch
// over the network: a shared subscription URL, or an independently-sourced
// slot whose source is an http(s) URL (a pasted vless:// link has nothing to
// re-fetch).
func HasRemote(cfg *config.Config) bool {
	if cfg.Subscription != nil && cfg.Subscription.URL != "" {
		return true
	}
	for _, s := range []*config.SlotSource{cfg.PrimarySource, cfg.BackupSource} {
		if s == nil {
			continue
		}
		u := strings.TrimSpace(s.URL)
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return true
		}
	}
	return false
}

var urlInText = regexp.MustCompile(`https?://[^\s"'<>]+`)

// RedactURLs hides the path and query of every URL in s. A fetch error quotes
// the URL it failed on, and a subscription URL carries its token in the path:
// anything that goes to a log, a state file or a chat message goes through here.
func RedactURLs(s string) string {
	return urlInText.ReplaceAllStringFunc(s, func(m string) string {
		trail := ""
		for len(m) > 0 && strings.ContainsRune(":;,.)", rune(m[len(m)-1])) {
			trail = m[len(m)-1:] + trail
			m = m[:len(m)-1]
		}
		return config.RedactURL(m) + trail
	})
}
