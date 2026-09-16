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

// georangesBootstrapFetchTimeout bounds georangesBootstrap's own network
// fetch attempt (only reached when no cache exists yet) -- see that
// func's own doc comment for why this needs to be much shorter than
// runGeorangesRefresh's usual 2-minute ceiling.
const georangesBootstrapFetchTimeout = 8 * time.Second

// georangesBootstrap makes ONE best-effort attempt to have some
// Russian-ranges table loaded -- cache if one exists (near-instant,
// local disk), otherwise a single bounded network fetch -- and returns
// once that attempt is done, successful or not. Called synchronously
// from main, BEFORE adaptiveRouteClassifyLoop is spawned, specifically
// so ClrFast/ClrSoft's ExcludedRangeLookup veto is never racing its own
// data source.
//
// Found live (2026-09-16), twice, even after shortening the pre-fetch
// delay once already: georangesRefreshLoop used to do this same load
// inside its own independent goroutine, racing adaptiveRouteClassifyLoop's
// -- narrowing that goroutine's own delay before its first attempt
// shrank the window but never closed it, since the fetch itself still
// took nonzero time after the delay elapsed, during which the classify
// loop (ticking every 500ms, cmd/keenetic-xray/adaptiveroute.go) could
// already be confirming and promoting Russian addresses with nothing
// loaded yet to veto them. A confirmed address then stays redirected
// for its full ~6h OKTTL regardless of when the table finally loads.
// Synchronizing the two instead of racing them closes the window
// rather than just shrinking it again.
//
// Deliberately unconditional (not gated on cfg.AdaptiveRoute.Enabled):
// that flag can be toggled on later, live, without a daemon restart
// (adaptiveRouteClassifyLoop is already always running, it just no-ops
// while disabled) -- gating this on today's Enabled value would just
// move the same race to "whenever the operator turns adaptive routing
// on", not remove it. The cost of always paying this is small and
// mostly one-time in practice: georangesBootstrapFetchTimeout only
// matters on a router that has never successfully fetched this table
// before, every later restart finds a cache and returns near-instantly.
func georangesBootstrap(ctx context.Context, logf func(string, ...any)) {
	if raw, err := knownranges.LoadCacheRaw(georangesCachePath()); err == nil {
		georanges.SetCurrent(georanges.Parse(raw))
		logf("georanges: loaded %d Russian ranges from cache", georanges.CurrentLen())
		return
	}
	bctx, cancel := context.WithTimeout(ctx, georangesBootstrapFetchTimeout)
	defer cancel()
	runGeorangesRefresh(bctx, logf)
}

// georangesRefreshLoop keeps internal/georanges' process-wide table
// fresh going forward. georangesBootstrap (called synchronously before
// this is even spawned, see main.go) already made the first load
// attempt, so this only needs to repeat runGeorangesRefresh every
// georangesRefreshInterval from here on.
func georangesRefreshLoop(ctx context.Context, logf func(string, ...any)) {
	timer := time.NewTimer(georangesRefreshInterval)
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
