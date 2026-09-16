package main

import (
	"context"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
	"github.com/kuzzrus/keenetic-xray-go/internal/knownranges"
)

// georangesSourceURL is HackingGate/Country-IP-Blocks' own generated
// Russia IPv4 list -- see the russia-ip-exclusion-plan memory for why
// this source (RIR-delegated-stats-derived, public domain, genuinely
// live) was picked over the alternatives found.
const georangesSourceURL = "https://country-ip-blocks.hackinggate.com/RU_IPv4.txt"

// georangesRefreshInterval mirrors knownRangesRefreshInterval -- the
// upstream source updates on weekdays at most.
const georangesRefreshInterval = 24 * time.Hour

// georangesRefreshDelay lets the daemon settle (and any network come up)
// before the first pull, same reasoning as knownRangesRefreshDelay.
const georangesRefreshDelay = 90 * time.Second

// georangesRefreshLoop keeps internal/georanges' process-wide table in
// step with HackingGate/Country-IP-Blocks, same shape as
// knownRangesRefreshLoop: load the last cached copy immediately so
// ClrFast/ClrSoft's ExcludedRangeLookup has real data from the first
// classify tick after a restart, then refresh in the background once
// settled and daily after that. Fetch/cache plumbing is reused directly
// from internal/knownranges (FetchRaw/LoadCacheRaw/SaveCacheRaw are
// already generic over source URL and cache path) -- only the table
// shape itself (internal/georanges.Table's first-octet bucketing) is
// specific to this dataset, see that package's own doc comment for why.
func georangesRefreshLoop(ctx context.Context, logf func(string, ...any)) {
	if raw, err := knownranges.LoadCacheRaw(georangesCachePath()); err == nil {
		georanges.SetCurrent(georanges.Parse(raw))
		logf("georanges: loaded %d Russian ranges from cache", georanges.CurrentLen())
	}

	timer := time.NewTimer(georangesRefreshDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		runGeorangesRefresh(ctx, logf)
		timer.Reset(georangesRefreshInterval)
	}
}

func runGeorangesRefresh(ctx context.Context, logf func(string, ...any)) {
	rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	raw, err := knownranges.FetchRaw(rctx, georangesSourceURL)
	if err != nil {
		logf("georanges: refresh failed: %v", err)
		return
	}
	table := georanges.Parse(raw)
	if table.Len() == 0 {
		logf("georanges: refresh returned no usable ranges -- keeping the previous copy")
		return
	}
	if err := knownranges.SaveCacheRaw(georangesCachePath(), raw); err != nil {
		// The freshly fetched table is still good even if persisting it
		// failed -- no reason to throw away a successful fetch over a
		// disk write error, only the next restart loses the head start.
		logf("georanges: could not persist cache: %v", err)
	}
	georanges.SetCurrent(table)
	logf("georanges: refreshed, %d Russian ranges loaded", table.Len())
}
