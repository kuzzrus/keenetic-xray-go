package main

import (
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestExclusionLookupFor is the regression test for AR-06: exclusions
// (in particular DisableRussianExclusion) used to be wired into clsCfg
// only when the classifier was first built, so flipping the setting live
// -- via the bot, with no daemon restart -- silently did nothing until
// AdaptiveRoute.Enabled was toggled off and back on. exclusionLookupFor
// is what adaptiveRouteClassifyLoop now calls every tick (alongside
// OKTTL/BlockThreshold, which already worked this way) instead of only
// once.
func TestExclusionLookupFor(t *testing.T) {
	cfg := config.Default()
	cfg.AdaptiveRoute.DisableRussianExclusion = false
	if got := exclusionLookupFor(cfg); got == nil {
		t.Error("exclusionLookupFor = nil, want georanges.Lookup when the exclusion is enabled")
	}

	cfg.AdaptiveRoute.DisableRussianExclusion = true
	if got := exclusionLookupFor(cfg); got != nil {
		t.Error("exclusionLookupFor = non-nil, want nil once the exclusion is disabled")
	}

	// And back on -- the live-toggle path this bug was about.
	cfg.AdaptiveRoute.DisableRussianExclusion = false
	if got := exclusionLookupFor(cfg); got == nil {
		t.Error("exclusionLookupFor = nil, want georanges.Lookup once re-enabled")
	}
}
