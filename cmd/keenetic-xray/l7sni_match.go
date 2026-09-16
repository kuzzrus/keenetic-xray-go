package main

import (
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// l7sniDomainSet is every enabled route list's domain entries, already
// classified and flattened into one set. Built once whenever config is
// (re)read, not per packet: l7SNIHandlePacket's own hot path used to
// call config.ClassifyRouteEntry on every entry of every list for every
// captured packet, which on a real router means re-parsing a few hundred
// entries per HTTPS connection -- see l7sniConfigRefreshInterval's doc
// comment (l7sni_linux.go) for the measurement that prompted this.
type l7sniDomainSet map[string]struct{}

// l7sniDomainsFrom flattens cfg's enabled route lists into a
// l7sniDomainSet. Entries mix domains and IPv4/CIDR (see
// config.RouteList); ClassifyRouteEntry is what tells them apart, same
// validator the CLI itself uses when an entry is first added -- called
// here, once per config read, rather than once per packet.
func l7sniDomainsFrom(cfg *config.Config) l7sniDomainSet {
	set := l7sniDomainSet{}
	for _, rl := range cfg.Routing.Lists {
		if rl.Disabled {
			continue
		}
		for _, e := range rl.Entries {
			kind, domain, err := config.ClassifyRouteEntry(e)
			if err != nil || kind != config.RouteDomain {
				continue
			}
			set[domain] = struct{}{}
		}
	}
	return set
}

// matches reports whether host is covered by this set -- exact, or as a
// subdomain (matching on a '.' boundary, so "instagram.com" matches
// "www.instagram.com" but not "notinstagram.com").
//
// Walks host's own parent labels and looks each one up, rather than
// suffix-testing host against every domain in the set: a hostname has a
// handful of labels no matter how large the operator's route lists grow,
// so this is bounded by the *hostname*, not by the list size.
func (s l7sniDomainSet) matches(host string) bool {
	if len(s) == 0 {
		return false
	}
	for {
		if _, ok := s[host]; ok {
			return true
		}
		i := strings.IndexByte(host, '.')
		if i < 0 {
			return false
		}
		host = host[i+1:]
	}
}

// l7sniMatchesRoutes reports whether host matches any enabled route
// list's domain entries. The plain config-in form of the same question
// l7sniDomainSet.matches answers -- kept for callers (and tests) that
// have a *config.Config in hand and don't care about the hot path.
//
// Pure and cross-platform on purpose, unlike l7sni_linux.go's own
// packet-handling code that uses the set form: this is plain string
// matching over already-loaded config, nothing Linux-specific about it,
// so it's worth being able to build and test on any platform (including
// the Windows box this project is developed on).
func l7sniMatchesRoutes(cfg *config.Config, host string) bool {
	return l7sniDomainsFrom(cfg).matches(host)
}
