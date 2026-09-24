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

// TestExclusionOverlapFor mirrors TestExclusionLookupFor for the
// block-level veto. Wired independently of the address-level one on
// purpose (see exclusionOverlapFor's doc comment), so it needs its own
// coverage of the same live-toggle path -- a DisableRussianExclusion
// that switched one and not the other would leave the daemon half
// vetoing, which is worse than either consistent state.
func TestExclusionOverlapFor(t *testing.T) {
	cfg := config.Default()
	cfg.AdaptiveRoute.DisableRussianExclusion = false
	if got := exclusionOverlapFor(cfg); got == nil {
		t.Error("exclusionOverlapFor = nil, want georanges.Overlaps when the exclusion is enabled")
	}

	cfg.AdaptiveRoute.DisableRussianExclusion = true
	if got := exclusionOverlapFor(cfg); got != nil {
		t.Error("exclusionOverlapFor = non-nil, want nil once the exclusion is disabled")
	}

	cfg.AdaptiveRoute.DisableRussianExclusion = false
	if got := exclusionOverlapFor(cfg); got == nil {
		t.Error("exclusionOverlapFor = nil, want georanges.Overlaps once re-enabled")
	}
}

// TestExclusionTogglesMoveTogether: the two vetoes are separate fields
// driven by one setting, so the invariant worth asserting is that they
// are never in disagreement about it.
func TestExclusionTogglesMoveTogether(t *testing.T) {
	cfg := config.Default()
	for _, disabled := range []bool{false, true, false} {
		cfg.AdaptiveRoute.DisableRussianExclusion = disabled
		lookupOff := exclusionLookupFor(cfg) == nil
		overlapOff := exclusionOverlapFor(cfg) == nil
		if lookupOff != overlapOff {
			t.Errorf("DisableRussianExclusion=%v: lookup nil=%v but overlap nil=%v -- the two vetoes disagree",
				disabled, lookupOff, overlapOff)
		}
		if lookupOff != disabled {
			t.Errorf("DisableRussianExclusion=%v: vetoes off=%v, want %v", disabled, lookupOff, disabled)
		}
	}
}
