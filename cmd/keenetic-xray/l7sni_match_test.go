package main

import (
	"testing"

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
