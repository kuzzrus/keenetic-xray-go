package main

import (
	"context"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/knownranges"
)

// knownRangesRefreshInterval mirrors presetRefreshInterval -- the
// upstream source (lord-alfred/ipranges) is updated at most daily.
const knownRangesRefreshInterval = 24 * time.Hour

// knownRangesRefreshDelay lets the daemon settle (and any network come
// up) before the first pull, same reasoning as presetRefreshDelay.
const knownRangesRefreshDelay = 90 * time.Second

// knownRangesRefreshLoop keeps internal/knownranges' process-wide table
// in step with lord-alfred/ipranges, same shape as presetRefreshLoop:
// load the last cached copy immediately so ClrBlockPromote has real data
// from the first classify tick after a restart, not just after the
// first fetch of a fresh run completes, then refresh in the background
// once settled and daily after that.
func knownRangesRefreshLoop(ctx context.Context, logf func(string, ...any)) {
	if raw, err := knownranges.LoadCacheRaw(knownRangesCachePath()); err == nil {
		knownranges.SetCurrent(knownranges.Parse(raw))
		logf("known-ranges: loaded %d ranges from cache", knownranges.CurrentLen())
	}

	timer := time.NewTimer(knownRangesRefreshDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		runKnownRangesRefresh(ctx, logf)
		timer.Reset(knownRangesRefreshInterval)
	}
}

func runKnownRangesRefresh(ctx context.Context, logf func(string, ...any)) {
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, err := knownranges.FetchRaw(rctx, "")
	if err != nil {
		logf("known-ranges: refresh failed: %v", err)
		return
	}
	table := knownranges.Parse(raw)
	if table.Len() == 0 {
		logf("known-ranges: refresh returned no usable ranges -- keeping the previous copy")
		return
	}
	if err := knownranges.SaveCacheRaw(knownRangesCachePath(), raw); err != nil {
		// The freshly fetched table is still good even if persisting it
		// failed -- no reason to throw away a successful fetch over a
		// disk write error, only the next restart loses the head start.
		logf("known-ranges: could not persist cache: %v", err)
	}
	knownranges.SetCurrent(table)
	logf("known-ranges: refreshed, %d ranges loaded", table.Len())
}
