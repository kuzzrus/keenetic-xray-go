package botcontrol

import (
	"context"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/updatecheck"
)

// DefaultUpdateCheckInterval is how often AppUpdateWatcher re-checks
// GitHub for a newer keenetic-xray release. Far coarser than
// DefaultOfflineCheckInterval on purpose: an outdated version is a
// standing fact, not an event to catch within the hour, and this is a
// one-time-per-version DM, not a live status -- once a day is plenty.
const DefaultUpdateCheckInterval = 24 * time.Hour

// AppUpdateWatcher periodically compares the latest keenetic-xray
// release (via Checker) against this control server's own running
// version and against every registered router's last-reported agent
// version (parsed from its heartbeat's rendered status text), and calls
// Notify once per newly-seen newer version -- never repeatedly for a
// target that's already been announced.
type AppUpdateWatcher struct {
	Store          *Store
	Checker        *updatecheck.Checker
	CurrentVersion string                         // this control server's own version.Version
	Interval       time.Duration                  // 0 -> DefaultUpdateCheckInterval
	Notify         func(subject, from, to string) // subject "" == the server itself, else a routerID

	notified map[string]string // subject -> latest version already announced for it
}

// Run checks immediately (so a fresh restart doesn't wait a full
// interval to say anything useful) and then on a ticker, until ctx is
// done.
func (w *AppUpdateWatcher) Run(ctx context.Context) {
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultUpdateCheckInterval
	}
	w.notified = map[string]string{}

	w.check(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.check(ctx)
		}
	}
}

func (w *AppUpdateWatcher) check(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	latest, err := w.Checker.LatestAppVersion(cctx)
	cancel()
	if err != nil || latest == "" {
		return // best-effort -- GitHub unreachable/rate-limited; try again next tick
	}

	w.consider("", w.CurrentVersion, latest)
	for _, r := range w.Store.Routers() {
		av := agentVersionFromStatus(r.LastStatus)
		if av == "" {
			continue // never heard from it yet, or an unexpectedly-shaped status
		}
		w.consider(r.ID, av, latest)
	}
}

// consider announces subject being behind latest, at most once per
// distinct latest value -- so the watcher doesn't repeat the same
// reminder every tick while nobody's updated yet, but does speak up
// again if an even newer release supersedes the one it already
// mentioned.
func (w *AppUpdateWatcher) consider(subject, running, latest string) {
	if updatecheck.CompareVersions(latest, running) <= 0 {
		return // already current, or ahead (a dev/dirty build) -- nothing to say
	}
	if w.notified[subject] == latest {
		return
	}
	w.notified[subject] = latest
	if w.Notify != nil {
		w.Notify(subject, running, latest)
	}
}

// agentVersionFromStatus extracts the agent's reported version tag
// (e.g. "v0.29.3") from the first line of a heartbeat's rendered status
// text -- "agent: v0.29.3 (abc1234)\n..." (see RouterHandler.status).
// Returns "" if the text doesn't start with that exact line: empty (no
// heartbeat received yet), stale pre-this-feature agent, or otherwise
// unexpected -- callers skip rather than compare against garbage.
func agentVersionFromStatus(status string) string {
	line, _, _ := strings.Cut(status, "\n")
	tag, ok := strings.CutPrefix(line, "agent: ")
	if !ok {
		return ""
	}
	tag, _, _ = strings.Cut(tag, " ") // drop the " (commit)" suffix
	return tag
}
