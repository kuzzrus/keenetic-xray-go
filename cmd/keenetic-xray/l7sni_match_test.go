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

// TestL7SNIMatchesRoutes_SkipsNonDefaultInterface is L7-01's regression
// test for part 3/3: a route list explicitly pointed at a non-default
// Proxy interface must not be picked up by L7 SNI matching, since a
// match here can only ever feed the one adaptive-routing ipset, which
// always rides whatever profile is the current live egress -- there's
// no dataplane hook to actually honor a RouteIface() other than Proxy0.
func TestL7SNIMatchesRoutes_SkipsNonDefaultInterface(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "work-vpn", Entries: []string{"internal.example"}, Interface: "Proxy1"},
	}}}
	if l7sniMatchesRoutes(cfg, "internal.example") {
		t.Error("a list routed through a non-default interface must not match")
	}
}

// TestL7SNIMatchesRoutes_MatchesExplicitDefaultInterface confirms the
// filter is about the *resolved* interface, not merely an empty
// Interface field -- explicitly spelling out the default must still
// match, the same as leaving it blank does.
func TestL7SNIMatchesRoutes_MatchesExplicitDefaultInterface(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "insta", Entries: []string{"instagram.com"}, Interface: "Proxy0"},
	}}}
	if !l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("an explicit Proxy0 interface (the default, spelled out) should still match")
	}
}

// TestL7SNIMatchesRoutes_MixedInterfacesOnlyDefaultMatches covers both
// lists appearing side by side -- the non-default one must not shadow
// or otherwise interfere with the default one still matching correctly.
func TestL7SNIMatchesRoutes_MixedInterfacesOnlyDefaultMatches(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "default-iface", Entries: []string{"instagram.com"}},
		{Name: "other-iface", Entries: []string{"internal.example"}, Interface: "Proxy2"},
	}}}
	if !l7sniMatchesRoutes(cfg, "instagram.com") {
		t.Error("the default-interface list's own domain should still match")
	}
	if l7sniMatchesRoutes(cfg, "internal.example") {
		t.Error("the non-default-interface list's own domain must not match")
	}
}

// --- l7sniEnabled (L7-01, part 1/3) ---

func TestL7SNIEnabled_RequiresBothTogglesOn(t *testing.T) {
	cases := []struct {
		name            string
		l7sni, adaptive bool
		want            bool
	}{
		{"both off", false, false, false},
		{"l7sni on, adaptive route off", true, false, false},
		{"l7sni off, adaptive route on", false, true, false},
		{"both on", true, true, true},
	}
	for _, c := range cases {
		cfg := &config.Config{
			L7SNI:         config.L7SNIConfig{Enabled: c.l7sni},
			AdaptiveRoute: config.AdaptiveRouteConfig{Enabled: c.adaptive},
		}
		if got := l7sniEnabled(cfg); got != c.want {
			t.Errorf("%s: l7sniEnabled = %v, want %v", c.name, got, c.want)
		}
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
