package main

import (
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestL7SNIMatchesRoutes_ExactMatch(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}},
	}}}
	if !l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("want exact-domain match")
	}
}

func TestL7SNIMatchesRoutes_SubdomainMatch(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}},
	}}}
	if !l7sniMatchesRoutes(cfg, "www.instagram.com") {
		t.Error("want subdomain match")
	}
	if !l7sniMatchesRoutes(cfg, "scontent.cdninstagram.instagram.com") {
		t.Error("want a multi-level subdomain to also match")
	}
}

func TestL7SNIMatchesRoutes_DoesNotMatchUnrelatedDomain(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}},
	}}}
	cases := []string{"notinstagram.com", "instagram.com.evil.example", "xinstagram.com", "gram.com"}
	for _, host := range cases {
		if l7sniMatchesRoutes(cfg, host) {
			t.Errorf("l7sniMatchesRoutes(%q): want false, matched instagram.com incorrectly", host)
		}
	}
}

func TestL7SNIMatchesRoutes_SkipsDisabledLists(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}, Disabled: true},
	}}}
	if l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("a disabled list should not match")
	}
}

func TestL7SNIMatchesRoutes_IgnoresIPAndCIDREntries(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "mixed", Entries: []string{"203.0.113.5", "198.51.100.0/24", "instagram.com"}},
	}}}
	// A hostname that happens to look like it could relate to an IP
	// entry must never match -- only real domain entries count.
	if l7sniMatchesRoutes(cfg, "203.0.113.5") {
		t.Error("an IP entry must never match as if it were a domain")
	}
	if !l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("the real domain entry in the same list should still match")
	}
}

func TestL7SNIMatchesRoutes_ChecksAllLists(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}},
		{Name: "yt", Entries: []string{"youtube.com"}},
	}}}
	if !l7sniMatchesRoutes(cfg, "youtube.com") {
		t.Error("want a match against the second list")
	}
}

func TestL7SNIMatchesRoutes_EmptyRouting(t *testing.T) {
	cfg := &config.Config{}
	if l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("no route lists configured at all: want no match")
	}
}

// --- l7sniSharedIPTracker (AR-07) ---

func TestL7SNISharedIPTracker_FirstSightingNotShared(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	if _, shared := tr.note([4]byte{1, 2, 3, 4}, "a.example", time.Now()); shared {
		t.Error("a first-ever sighting of an IP must not be reported as shared")
	}
}

func TestL7SNISharedIPTracker_SameHostRepeatedNotShared(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	if _, shared := tr.note([4]byte{1, 2, 3, 4}, "a.example", now.Add(time.Second)); shared {
		t.Error("the same hostname seen again on the same IP must not be reported as shared")
	}
}

func TestL7SNISharedIPTracker_DifferentHostWithinWindowIsShared(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	previousHost, shared := tr.note([4]byte{1, 2, 3, 4}, "b.example", now.Add(time.Minute))
	if !shared {
		t.Fatal("a different hostname on the same IP within the window must be reported as shared")
	}
	if previousHost != "a.example" {
		t.Errorf("previousHost = %q, want %q", previousHost, "a.example")
	}
}

func TestL7SNISharedIPTracker_DifferentHostPastMaxAgeNotShared(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	_, shared := tr.note([4]byte{1, 2, 3, 4}, "b.example", now.Add(l7sniSharedIPMaxAge+time.Second))
	if shared {
		t.Error("a differing sighting older than l7sniSharedIPMaxAge must not count as shared")
	}
}

func TestL7SNISharedIPTracker_DifferentIPsAreIndependent(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	if _, shared := tr.note([4]byte{5, 6, 7, 8}, "b.example", now.Add(time.Second)); shared {
		t.Error("a different IP's own first sighting must not be reported as shared")
	}
}

func TestL7SNISharedIPTracker_NoteUpdatesLatestSighting(t *testing.T) {
	// After a "shared" verdict, the tracker's own record for dst must
	// move on to the hostname that was just seen -- a third, distinct
	// sighting compares against b.example (the second), not a.example
	// (the first) still.
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	tr.note([4]byte{1, 2, 3, 4}, "b.example", now.Add(time.Second))
	previousHost, shared := tr.note([4]byte{1, 2, 3, 4}, "b.example", now.Add(2*time.Second))
	if shared {
		t.Errorf("expected no change (still b.example), got shared=true against %q", previousHost)
	}
}

func TestL7SNISharedIPTracker_ExpireDropsOldSightings(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	tr.expire(now.Add(l7sniSharedIPMaxAge + time.Second))
	if len(tr.seen) != 0 {
		t.Errorf("seen = %v, want empty after expiring past l7sniSharedIPMaxAge", tr.seen)
	}
}

func TestL7SNISharedIPTracker_ExpireLeavesFreshSightings(t *testing.T) {
	tr := newL7SNISharedIPTracker()
	now := time.Now()
	tr.note([4]byte{1, 2, 3, 4}, "a.example", now)
	tr.expire(now.Add(time.Second))
	if len(tr.seen) != 1 {
		t.Errorf("seen = %v, want the still-fresh entry kept", tr.seen)
	}
}
