package botcontrol

import (
	"context"
	"time"
)

// DefaultOfflineThreshold is how long a router that had been polling may
// go silent before OfflineWatcher calls it offline. Agents poll every
// ~5s (DefaultPollInterval); 90s is ~18 missed polls -- long enough not
// to flap on a transient network blip, short enough to be useful.
const DefaultOfflineThreshold = 90 * time.Second

// DefaultOfflineCheckInterval is how often OfflineWatcher re-checks.
const DefaultOfflineCheckInterval = 30 * time.Second

// OfflineWatcher watches a Store's registry and reports when a router
// that had been polling stops (and when it resumes). It only concerns
// itself with routers that have polled at least once -- a freshly
// registered router that has never connected is "not set up yet", not
// "offline", and never triggers a notification.
type OfflineWatcher struct {
	Store     *Store
	Threshold time.Duration // 0 -> DefaultOfflineThreshold
	Interval  time.Duration // 0 -> DefaultOfflineCheckInterval
	Notify    func(routerID string, online bool)

	online map[string]bool // routerID -> last known online state
}

// Run checks on a ticker until ctx is cancelled. The first check seeds
// state from the current registry without notifying, so a control-server
// restart doesn't spray "offline"/"online" messages for the existing
// routers.
func (w *OfflineWatcher) Run(ctx context.Context) {
	threshold := w.Threshold
	if threshold <= 0 {
		threshold = DefaultOfflineThreshold
	}
	interval := w.Interval
	if interval <= 0 {
		interval = DefaultOfflineCheckInterval
	}

	w.online = map[string]bool{}
	w.scan(threshold, false) // seed, don't notify

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scan(threshold, true)
		}
	}
}

func (w *OfflineWatcher) scan(threshold time.Duration, notify bool) {
	seen := map[string]bool{}
	for _, r := range w.Store.Routers() {
		seen[r.ID] = true
		if r.LastPollAt.IsZero() {
			continue // never connected -- not "offline"
		}
		up := time.Since(r.LastPollAt) < threshold
		prev, known := w.online[r.ID]
		w.online[r.ID] = up
		if notify && known && prev != up && w.Notify != nil {
			w.Notify(r.ID, up)
		}
	}

	// Drop state for routers removed from the registry so a re-add
	// starts fresh.
	for id := range w.online {
		if !seen[id] {
			delete(w.online, id)
		}
	}
}
