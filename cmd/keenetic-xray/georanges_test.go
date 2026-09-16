package main

import (
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
)

func classifierConfigWithExclusion() *classifier.Config {
	c := classifier.DefaultConfig()
	c.ExcludedRangeLookup = georanges.Lookup
	return &c
}

func classifierConfigWithoutExclusion() *classifier.Config {
	c := classifier.DefaultConfig()
	return &c
}

// TestGeorangesRetryBackoff_StaysWellUnderRefreshInterval is the
// regression guard for 2026-09-16: georangesRefreshLoop used to wait a
// full georangesRefreshInterval (24h) after a failed first fetch, so one
// timeout left the Russian-exclusion veto inert for a day. Every backoff
// step must stay far below that, and the last one is what repeats
// forever while the table is still empty.
func TestGeorangesRetryBackoff_StaysWellUnderRefreshInterval(t *testing.T) {
	if len(georangesRetryBackoff) == 0 {
		t.Fatal("no retry backoff configured -- a failed fetch would wait a full refresh interval")
	}
	for i, d := range georangesRetryBackoff {
		if d <= 0 {
			t.Errorf("step %d = %v, must be positive", i, d)
		}
		if d >= georangesRefreshInterval {
			t.Errorf("step %d = %v, want well under georangesRefreshInterval (%v)", i, d, georangesRefreshInterval)
		}
		if i > 0 && d < georangesRetryBackoff[i-1] {
			t.Errorf("step %d = %v is shorter than step %d (%v) -- backoff must not shrink", i, d, i-1, georangesRetryBackoff[i-1])
		}
	}
	if last := georangesRetryBackoff[len(georangesRetryBackoff)-1]; last > 30*time.Minute {
		t.Errorf("final backoff = %v; while the table is empty the veto is off, so the steady retry must stay brisk", last)
	}
}

// TestGeorangesBootstrapFetchTimeout_RoomForASlowRouter pins the other
// half of the same incident: 8s was not enough to pull ~200KB over a
// real router's WAN while the rest of the daemon was still starting, and
// every single attempt timed out.
func TestGeorangesBootstrapFetchTimeout_RoomForASlowRouter(t *testing.T) {
	if georangesBootstrapFetchTimeout < 20*time.Second {
		t.Errorf("georangesBootstrapFetchTimeout = %v, too tight for a router WAN at startup",
			georangesBootstrapFetchTimeout)
	}
	if georangesBootstrapFetchTimeout > time.Minute {
		t.Errorf("georangesBootstrapFetchTimeout = %v, long enough to visibly stall daemon startup",
			georangesBootstrapFetchTimeout)
	}
}

// TestWarnIfExclusionInert covers the "a silent safety feature has to
// keep saying it is silent" rule: warn when the veto is wired but has no
// data, stay quiet when it is not wired at all or when data is loaded,
// and do not repeat on every 500ms tick.
func TestWarnIfExclusionInert(t *testing.T) {
	t.Cleanup(func() { georanges.SetCurrent(nil) })
	georanges.SetCurrent(nil) // no table loaded

	var lines int
	logf := func(string, ...any) { lines++ }
	cfg := classifierConfigWithExclusion()

	var last time.Time
	warnIfExclusionInert(cfg, &last, logf)
	if lines != 1 {
		t.Fatalf("lines = %d, want 1 warning when the veto is wired but the table is empty", lines)
	}

	// Same tick a moment later: must not repeat.
	warnIfExclusionInert(cfg, &last, logf)
	if lines != 1 {
		t.Errorf("lines = %d, want no repeat inside inertExclusionWarnInterval", lines)
	}

	// Once the table loads, silence -- even after the interval passes.
	georanges.SetCurrent(georanges.Parse("213.180.192.0/19\n"))
	last = time.Now().Add(-2 * inertExclusionWarnInterval)
	warnIfExclusionInert(cfg, &last, logf)
	if lines != 1 {
		t.Errorf("lines = %d, want no warning once the table is loaded", lines)
	}

	// Veto not wired at all (operator disabled it): also silent.
	georanges.SetCurrent(nil)
	last = time.Now().Add(-2 * inertExclusionWarnInterval)
	warnIfExclusionInert(classifierConfigWithoutExclusion(), &last, logf)
	if lines != 1 {
		t.Errorf("lines = %d, want no warning when the exclusion is switched off", lines)
	}
}
