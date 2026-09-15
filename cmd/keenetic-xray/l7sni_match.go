package main

import (
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// l7sniMatchesRoutes reports whether host matches any enabled route
// list's domain entries -- exact, or as a subdomain (suffix matching on
// a '.' boundary, so "instagram.com" matches "www.instagram.com" but
// not "notinstagram.com"). Entries mix domains and IPv4/CIDR (see
// config.RouteList); ClassifyRouteEntry is what tells them apart here,
// same validator the CLI itself uses when an entry is first added.
//
// Pure and cross-platform on purpose, unlike l7sni_linux.go's own
// packet-handling code that calls it: this is plain string matching
// over already-loaded config, nothing Linux-specific about it, so it's
// worth being able to build and test on any platform (including the
// Windows box this project is developed on).
func l7sniMatchesRoutes(cfg *config.Config, host string) bool {
	for _, rl := range cfg.Routing.Lists {
		if rl.Disabled {
			continue
		}
		for _, e := range rl.Entries {
			kind, domain, err := config.ClassifyRouteEntry(e)
			if err != nil || kind != config.RouteDomain {
				continue
			}
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return true
			}
		}
	}
	return false
}
