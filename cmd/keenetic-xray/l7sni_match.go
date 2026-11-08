package main

import (
	"strings"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// l7sniDomainSet is every enabled route list's domain entries, already
// classified and flattened into one set. Built once whenever config is
// (re)read, not per packet: the packet handler's hot path used to call
// config.ClassifyRouteEntry on every entry of every list for every
// captured packet, which on a real router means re-parsing a few hundred
// entries per HTTPS connection -- see l7sniConfigRefreshInterval's doc
// comment (l7sni_handler.go) for the measurement that prompted this.
type l7sniDomainSet map[string]struct{}

// l7sniDomainsFrom flattens cfg's enabled route lists into a
// l7sniDomainSet. Entries mix domains and IPv4/CIDR (see
// config.RouteList); ClassifyRouteEntry is what tells them apart, same
// validator the CLI itself uses when an entry is first added -- called
// here, once per config read, rather than once per packet.
//
// L7-01 (part 3/3): only lists whose RouteIface() is "Proxy0" (the
// default, and the only one a bare RouteList without an explicit
// Interface resolves to) are included, even though RouteIface() exists
// and every other consumer of Routing.Lists (internal/botcontrol,
// cmd/keenetic-xray's own routes.go) already honors it. A match here
// only ever feeds the one adaptive-routing ipset, which always rides
// whatever profile is the current live egress (see
// transportAdaptive's own doc comment) -- there's no dataplane hook
// through which this could actually route a match through a specific
// non-default Proxy<n>/Wireguard<n> interface the way RouteIface()
// promises the rest of the system it will. Silently ignoring that
// promise for a domain the operator explicitly pointed elsewhere would
// be worse than not matching it here at all: NDM's own object-group
// dataplane (see config.L7SNIConfig's own doc comment) still routes it
// correctly whenever this router's own DNS actually resolves it, this
// just declines to be a second, conflicting path for entries this
// feature has no way to honor properly.
func l7sniDomainsFrom(cfg *config.Config) l7sniDomainSet {
	set := l7sniDomainSet{}
	for _, rl := range cfg.Routing.Lists {
		if rl.Disabled || rl.RouteIface() != "Proxy0" {
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

// l7sniEnabled reports whether L7 SNI matching should be active for cfg
// (L7-01, part 1/3) -- pulled out as its own pure function, cross-
// platform like l7sniMatchesRoutes above, so it's unit-testable without
// the real capture loop in l7sni_linux.go (Linux-only, and gated behind
// keenetic.Available() besides) that reads it through l7sniLoadSnapshot.
//
// Both L7SNI.Enabled and AdaptiveRoute.Enabled must be on: a match's
// only real effect is adaptiveroute.AddIP into the adaptive-routing
// ipset (see l7sniHandler.redirectMatch), which is exactly what
// AdaptiveRoute.Enabled governs. Without this, turning AdaptiveRoute
// off (leaving L7SNI on, its own separate toggle) kept capturing and
// matching every packet, and every match still tore down the
// triggering connection's conntrack entry for an AddIP that could
// never actually route anywhere.
func l7sniEnabled(cfg *config.Config) bool {
	return cfg.L7SNI.Enabled && cfg.AdaptiveRoute.Enabled
}

// l7sniQUICModeFor is the QUIC mode the capture actually runs with: off
// unless L7 detection itself is on; the configured "observe"/"act"
// otherwise, except that "act" with adaptive routing off is read as
// "observe" -- a match has nowhere to be redirected to, the same reason
// l7sniEnabled wants both switches for TLS and HTTP. Observing needs
// neither adaptive routing nor any route list: it only counts.
func l7sniQUICModeFor(cfg *config.Config) string {
	if !cfg.L7SNI.Enabled {
		return config.L7SNIQUICOff
	}
	mode := cfg.L7SNI.QUICMode()
	if mode == config.L7SNIQUICAct && !cfg.AdaptiveRoute.Enabled {
		return config.L7SNIQUICObserve
	}
	return mode
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

// l7sniSharedIPMaxEntries caps the tracker's table. Every distinct
// destination a LAN client opens a TLS, HTTP or QUIC connection to adds an
// entry and only age removes one, so without a cap a scanner, or a
// peer-to-peer client touching hundreds of thousands of addresses within
// l7sniSharedIPMaxAge, would grow it by tens of megabytes on a router with
// little to spare. 16384 is several times what a busy household reaches in
// that window; past it the tracker makes room (note) and carries on, since
// what it feeds is a best-effort mitigation, not a ledger.
const l7sniSharedIPMaxEntries = 16384

// l7sniSharedIPRedirectTTL is the redirect TTL l7sniHandler uses
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
// per destination IP address, letting l7sniHandler notice -- at the
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
// Safe for concurrent use: the capture loop calls note for every hostname
// it reads, while a timer goroutine calls expire to keep the table from
// growing for ever (l7SNIClassifySession). This used to be documented as
// owned by the capture goroutine alone, which the session did not honour --
// the Go runtime answers two goroutines on one map with a fatal "concurrent
// map iteration and map write" (or "concurrent map writes"), an
// unrecoverable crash of the whole daemon.
type l7sniSharedIPTracker struct {
	mu   sync.Mutex
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
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.seen[dst]
	if !ok && len(t.seen) >= l7sniSharedIPMaxEntries {
		// Full. Whatever is already stale goes first; when the table is
		// full of live sightings (a flood of distinct addresses) it is
		// forgotten wholesale -- the next connections re-teach it, and in
		// the meantime a shared address is treated as unshared, which is
		// what happened for every address before this tracker existed.
		t.dropStale(now)
		if len(t.seen) >= l7sniSharedIPMaxEntries {
			t.seen = make(map[[4]byte]l7sniHostSighting)
		}
	}
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
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropStale(now)
}

// dropStale removes every sighting older than l7sniSharedIPMaxAge; t.mu
// must be held.
func (t *l7sniSharedIPTracker) dropStale(now time.Time) {
	for dst, sighting := range t.seen {
		if now.Sub(sighting.at) > l7sniSharedIPMaxAge {
			delete(t.seen, dst)
		}
	}
}
