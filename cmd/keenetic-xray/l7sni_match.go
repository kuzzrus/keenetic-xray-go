package main

import (
	"strings"
	"time"

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

// l7sniSharedIPMaxAge bounds how long a previous SNI/Host sighting on an
// IP still counts as evidence that IP is shared (AR-07) -- old enough
// and the earlier hostname may no longer even be served from that
// address (CDN IPs get reassigned).
const l7sniSharedIPMaxAge = 10 * time.Minute

// l7sniSharedIPRedirectTTL is the redirect TTL l7SNIHandlePacket uses
// instead of the operator's own (typically hours-long) AdaptiveRoute
// TTL when l7sniSharedIPTracker.note reports the matched destination IP
// looks shared: a route-list match is only evidence about the specific
// hostname just seen, not about every other domain that IP might also
// be serving over SNI, and a full-length redirect would route all of it
// through the tunnel too. Short enough to bound the collateral window,
// long enough that an actively-used blocked domain keeps getting
// re-redirected on its own next connection well before this lapses.
const l7sniSharedIPRedirectTTL = 5 * time.Minute

// l7sniHostSighting is one IP's most recently observed SNI/Host
// hostname.
type l7sniHostSighting struct {
	host string
	at   time.Time
}

// l7sniSharedIPTracker records the most recent SNI/Host hostname seen
// per destination IP address, letting l7SNIHandlePacket notice -- at the
// moment it's about to redirect a whole IP into the tunnel over a single
// matched hostname -- that the same IP has recently also carried a
// *different* hostname. That's a strong, cheap-to-observe signal the
// address is a shared CDN/hosting IP rather than one exclusively serving
// the blocked domain (AR-07: SNI matching one domain otherwise opens the
// tunnel for the whole IP, including any unrelated traffic that happens
// to share it).
//
// Deliberately tracks only the single most-recently-seen hostname per
// IP, not a full set of every hostname ever observed there: telling
// "exclusively one domain" apart from "definitely shares this IP with
// something else" only needs one differing observation, and a full
// multi-hostname-per-IP set would need its own per-entry expiry
// bookkeeping for a P2-severity mitigation that doesn't need that
// precision.
//
// Not safe for concurrent use -- owned by l7SNIClassifyLoop's own
// goroutine and touched only from there, same "single reader/writer, no
// locking needed" convention as that loop's own Reassembler and
// l7sniSnapshot.
type l7sniSharedIPTracker struct {
	seen map[[4]byte]l7sniHostSighting
}

// newL7SNISharedIPTracker returns an empty, ready-to-use tracker.
func newL7SNISharedIPTracker() *l7sniSharedIPTracker {
	return &l7sniSharedIPTracker{seen: map[[4]byte]l7sniHostSighting{}}
}

// note records host as dst's latest sighting and reports whether a
// *different* hostname was seen at dst within l7sniSharedIPMaxAge --
// i.e. whether dst looks like a shared IP right now. Call this for
// every hostname successfully extracted from traffic to dst, matched or
// not: the signal this exists to catch is "what else does this IP
// serve", which needs every sighting, not just the ones that happen to
// match a route list.
func (t *l7sniSharedIPTracker) note(dst [4]byte, host string, now time.Time) (previousHost string, shared bool) {
	prev, ok := t.seen[dst]
	t.seen[dst] = l7sniHostSighting{host: host, at: now}
	if ok && prev.host != host && now.Sub(prev.at) <= l7sniSharedIPMaxAge {
		return prev.host, true
	}
	return "", false
}

// expire drops every sighting older than l7sniSharedIPMaxAge, so the
// tracker doesn't grow forever as new IPs are observed over the router's
// uptime. Not on the hot path -- call periodically, same convention as
// internal/l7sni.Reassembler's own Expire.
func (t *l7sniSharedIPTracker) expire(now time.Time) {
	for dst, sighting := range t.seen {
		if now.Sub(sighting.at) > l7sniSharedIPMaxAge {
			delete(t.seen, dst)
		}
	}
}
