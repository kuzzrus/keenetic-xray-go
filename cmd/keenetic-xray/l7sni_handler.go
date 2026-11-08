package main

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7sni"
)

// The packet side of L7 hostname detection: what the capture loop
// (l7sni_linux.go) does with each NFLOG-delivered packet. It has no NFLOG,
// iptables or ipset of its own -- those are behind the handler's fields and
// the capture loop -- so it builds and is tested on every platform.

// l7sniReassembleMaxAge/l7sniReassembleMaxSize bound the Reassembler's
// memory: an incomplete split ClientHello is dropped after this long (a
// lost segment, or traffic that was never really TLS at all), and this
// is the largest single ClientHello this will ever buffer.
// l7sniQUICMaxFlights is how many QUIC first flights may be waiting for a
// second datagram at once.
const (
	l7sniReassembleMaxAge  = 5 * time.Second
	l7sniReassembleMaxSize = 16384
	l7sniQUICMaxFlights    = 256
)

// l7sniConfigRefreshInterval is how often the capture loop re-reads
// config, replacing what used to be a config.Load *per captured packet*
// inside the per-packet handler. Found by reading the hot path (2026-09-16)
// after l7sni turned out to load this router's CPU heavily enough to be
// worth turning off: every captured packet that yielded a hostname --
// i.e. every HTTPS connection on the network -- opened, read and
// JSON-unmarshalled the entire config (profiles, every route list, every
// setting) and then threw it away, plus re-classified every route entry
// (see l7sniDomainSet). One page load fans out to dozens of TLS
// connections, so ordinary browsing meant hundreds of full config parses
// a second for microseconds of actual work.
//
// 2s rather than the classify loop's own 500ms: nothing here needs to
// react fast. The operator toggling l7sni off or editing a route list
// taking a couple of seconds to take effect is irrelevant, and this is
// already several orders of magnitude cheaper than what it replaces.
const l7sniConfigRefreshInterval = 2 * time.Second

// l7sniSnapshot is everything the handler needs from config, resolved once
// per l7sniConfigRefreshInterval instead of per packet. Owned by the
// capture loop's own goroutine and passed down by value -- no atomics or
// locking needed, since that loop is the only reader.
type l7sniSnapshot struct {
	enabled bool
	ttl     time.Duration
	domains l7sniDomainSet

	// quic is the effective QUIC mode (config.L7SNIQUIC*): what the config
	// says, with "act" read as "observe" when adaptive routing is off -- a
	// match could not be redirected anywhere.
	quic string

	// excluded is the operator's never-route list. A routes-list match is
	// not allowed to override it: the list says this address must not go
	// through the tunnel, whatever name was seen on it. nil -> none.
	excluded *adaptiveroute.Exclusions
}

// l7sniExcludedLogEvery limits the "matched, but excluded" line (and the
// QUIC observe line) to once per key per this long -- a busy site would
// otherwise log it on every connection.
const l7sniExcludedLogEvery = 10 * time.Minute

var l7sniExcludedLogged = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// l7sniBlockedByExclusion reports whether a routes-list match on dstIP must be
// dropped because the operator excluded the address, saying so in the log at
// most once per l7sniExcludedLogEvery.
func l7sniBlockedByExclusion(snap l7sniSnapshot, host, dstIP string, dport uint, now time.Time, logf func(string, ...any)) bool {
	if !snap.excluded.Contains(dstIP) {
		return false
	}
	if l7sniShouldLogExcluded(dstIP, now) {
		logf("l7sni: %s -> %s:%d matched a routes list, but the address is on the adaptive-route exclusion list -- not redirecting",
			host, dstIP, dport)
	}
	return true
}

// l7sniShouldLogExcluded reports whether the line for key (an address, or a
// longer key for another rate-limited line) is due.
func l7sniShouldLogExcluded(key string, now time.Time) bool {
	l7sniExcludedLogged.Lock()
	defer l7sniExcludedLogged.Unlock()
	if last, ok := l7sniExcludedLogged.at[key]; ok && now.Sub(last) < l7sniExcludedLogEvery {
		return false
	}
	if len(l7sniExcludedLogged.at) >= 256 {
		l7sniExcludedLogged.at = map[string]time.Time{}
	}
	l7sniExcludedLogged.at[key] = now
	return true
}

// l7sniLoadSnapshot reads config once and pre-resolves it. A failed read
// yields the zero snapshot (disabled, no domains, QUIC off), which the hot
// path treats as "match nothing" -- the same do-nothing outcome the old
// per-packet config.Load already had on error.
func l7sniLoadSnapshot() l7sniSnapshot {
	cfg, err := config.Load(configPath())
	if err != nil {
		return l7sniSnapshot{quic: config.L7SNIQUICOff}
	}
	return l7sniSnapshot{
		enabled: l7sniEnabled(cfg),
		ttl:     cfg.AdaptiveRoute.EffectiveOKTTL(),
		domains: l7sniDomainsFrom(cfg),
		quic:    l7sniQUICModeFor(cfg),
	}
}

// l7sniHandler turns captured packets into hostnames and acts on matches.
// The capture loop's goroutine drives handle; expire is called from a timer
// goroutine, which is why every part that both touch is safe for that.
type l7sniHandler struct {
	reasm     *l7sni.Reassembler
	qreasm    *l7sni.QUICReassembler
	sharedIPs *l7sniSharedIPTracker
	stats     *l7sniStats

	// redirect puts ip into the adaptive-routing ipset for ttl; dropFlow
	// tears down the triggering connection's conntrack entry so it
	// re-routes at once. Fields so a test can run the handler without ipset
	// or conntrack.
	redirect func(ctx context.Context, ip string, ttl time.Duration) error
	dropFlow func(ctx context.Context, proto, src, dst string, sport, dport uint)
	now      func() time.Time
}

func newL7SNIHandler(stats *l7sniStats) *l7sniHandler {
	return &l7sniHandler{
		reasm:     l7sni.NewReassembler(l7sniReassembleMaxAge, l7sniReassembleMaxSize),
		qreasm:    l7sni.NewQUICReassembler(l7sniReassembleMaxAge, l7sniQUICMaxFlights),
		sharedIPs: newL7SNISharedIPTracker(),
		stats:     stats,
		redirect: func(ctx context.Context, ip string, ttl time.Duration) error {
			return adaptiveroute.AddIP(ctx, adaptiveRouteIPSet, ip, ttl)
		},
		dropFlow: keenetic.DeleteConntrackFlow,
		now:      time.Now,
	}
}

// expire drops whatever has been waiting longer than its limit.
func (h *l7sniHandler) expire(now time.Time) {
	h.reasm.Expire(now)
	h.qreasm.Expire(now)
	h.sharedIPs.expire(now)
}

// handle parses one NFLOG-captured packet, extracts a hostname if it is
// carrying (or completes) a TLS ClientHello, an HTTP request or a QUIC
// Initial, and acts on a route-list match. Best-effort throughout --
// anything that doesn't parse cleanly is simply not a packet this feature
// has a use for, not an error worth logging on every occurrence (this runs
// on every captured packet; a persistent problem would show up as "never
// logs a match", something hardware testing needs to notice directly, not
// a log line per uninteresting packet).
func (h *l7sniHandler) handle(ctx context.Context, raw []byte, snap l7sniSnapshot, logf func(string, ...any)) {
	tcpOn := snap.enabled && len(snap.domains) > 0
	quicOn := snap.quic == config.L7SNIQUICObserve || snap.quic == config.L7SNIQUICAct
	if !tcpOn && !quicOn {
		// Nothing this packet could possibly be used for -- checked before
		// any parsing at all, since with no route lists configured (the
		// common case for an operator who hasn't set any up) every
		// captured packet would otherwise be fully parsed just to be
		// discarded at the match step.
		return
	}
	proto, src, dst, sport, dport, seq, payload, ok := l7sni.ParseIPv4(raw)
	if !ok {
		return
	}
	if len(payload) == 0 {
		// An empty ACK: nothing to parse, and it must not touch the
		// reassembler either. The NFLOG filter's 41-byte bound lets the ones
		// carrying a TCP timestamp (52 bytes) through, so this is the early
		// drop that bound relies on.
		return
	}
	switch {
	case proto == 6 && tcpOn:
		h.handleTCP(ctx, src, dst, sport, dport, seq, payload, snap, logf)
	case proto == 17 && quicOn && dport == 443:
		h.handleQUIC(ctx, src, dst, sport, dport, payload, snap, logf)
	}
}

func (h *l7sniHandler) handleTCP(ctx context.Context, src, dst [4]byte, sport, dport uint16, seq uint32, payload []byte, snap l7sniSnapshot, logf func(string, ...any)) {
	var host, matchStat, actedStat string
	switch dport {
	case 443:
		info, ok := h.extractTLS(l7sni.FlowKey{Src: src, Dst: dst, SPort: sport, DPort: dport}, seq, payload)
		if !ok {
			return
		}
		h.stats.inc(statTLSHello)
		if info.ECH {
			h.stats.inc(statTLSECH)
		}
		if info.Host == "" {
			return
		}
		h.stats.inc(statTLSName)
		h.stats.seenName("tls", info.Host, info.ECH)
		host, matchStat, actedStat = info.Host, statTLSMatch, statTLSActed
	case 80:
		name, ok := l7sni.ExtractHTTPHost(payload)
		if !ok {
			return
		}
		h.stats.inc(statHTTPHost)
		h.stats.seenName("http", name, false)
		host, matchStat, actedStat = name, statHTTPMatch, statHTTPActed
	default:
		return
	}

	// AR-07: note every successfully-extracted hostname, matched or not --
	// what this needs to catch is "does dst also serve something else",
	// which requires seeing every sighting, not just the ones that happen to
	// match a route list.
	previousHost, shared := h.sharedIPs.note(dst, host, h.now())

	if !snap.domains.matches(host) {
		return
	}
	h.stats.inc(matchStat)
	if h.redirectMatch(ctx, "tcp", host, src, dst, sport, dport, previousHost, shared, snap, logf) {
		h.stats.inc(actedStat)
	}
}

func (h *l7sniHandler) handleQUIC(ctx context.Context, src, dst [4]byte, sport, dport uint16, payload []byte, snap l7sniSnapshot, logf func(string, ...any)) {
	h.stats.inc(statQUICDatagram)
	init, st := l7sni.ParseQUICInitial(payload)
	switch st {
	case l7sni.QUICOK:
	case l7sni.QUICNotInitial:
		h.stats.inc(statQUICNotInitial)
		return
	case l7sni.QUICUnsupportedVersion:
		h.stats.inc(statQUICBadVersion)
		return
	case l7sni.QUICMalformed:
		h.stats.inc(statQUICMalformed)
		return
	default: // QUICAuthFailed
		h.stats.inc(statQUICAuthFailed)
		return
	}
	h.stats.inc(statQUICInitial)

	now := h.now()
	key := l7sni.FlowKey{Src: src, Dst: dst, SPort: sport, DPort: dport}
	hs, done := h.qreasm.Feed(key, init.Fragments, now)
	if !done {
		if len(init.Fragments) > 0 {
			h.stats.inc(statQUICWaiting)
		}
		return
	}
	info, ok := l7sni.ParseClientHello(hs)
	if !ok {
		return
	}
	h.stats.inc(statQUICHello)
	if info.ECH {
		h.stats.inc(statQUICECH)
	}
	if info.Host == "" {
		return
	}
	h.stats.inc(statQUICName)
	h.stats.seenName("quic", info.Host, info.ECH)

	previousHost, shared := h.sharedIPs.note(dst, info.Host, now)
	if !snap.domains.matches(info.Host) {
		return
	}
	h.stats.inc(statQUICMatch)
	if snap.quic != config.L7SNIQUICAct || !snap.enabled {
		// Observe: the name would have matched, nothing is done about it.
		dstIP := net.IP(dst[:]).String()
		if l7sniShouldLogExcluded("observe "+info.Host+" "+dstIP, now) {
			logf("l7sni: [наблюдение] QUIC %s -> %s:%d совпало бы со списком маршрутов (quic=observe, ничего не переправляем)",
				info.Host, dstIP, dport)
		}
		return
	}
	if h.redirectMatch(ctx, "udp", info.Host, src, dst, sport, dport, previousHost, shared, snap, logf) {
		h.stats.inc(statQUICActed)
	}
}

// redirectMatch acts on a routes-list match: puts dst into the adaptive-
// routing ipset and tears down the triggering connection's conntrack entry
// so it re-routes at once. proto is "tcp" or "udp" -- for QUIC the next
// datagrams of the flow then meet the UDP/443 REJECT that adaptive routing
// puts in front of promoted addresses, and the browser falls back to TCP,
// which is redirected. It reports whether the address was redirected.
func (h *l7sniHandler) redirectMatch(ctx context.Context, proto, host string, src, dst [4]byte, sport, dport uint16, previousHost string, shared bool, snap l7sniSnapshot, logf func(string, ...any)) bool {
	dstIP := net.IP(dst[:]).String()
	if l7sniBlockedByExclusion(snap, host, dstIP, uint(dport), h.now(), logf) {
		return false
	}
	ttl := snap.ttl
	if shared {
		// A route-list match is only evidence about host itself -- dst
		// having just as recently served previousHost too means this is
		// very likely a shared CDN/hosting IP, and the full-length
		// AdaptiveRoute TTL would route all of that IP's unrelated
		// traffic through the tunnel as well, not just host's. Use a
		// short TTL instead to bound how long that collateral redirect
		// can last; an actively-used blocked domain simply gets
		// re-redirected on its own very next connection.
		ttl = l7sniSharedIPRedirectTTL
	}
	actx, cancel := context.WithTimeout(ctx, adaptiveRouteOpTimeout)
	defer cancel()
	if err := h.redirect(actx, dstIP, ttl); err != nil {
		// L7-01 (part 2/3): a failed redirect means dst was never actually
		// redirected -- deleting the conntrack entry anyway would just
		// tear down a working connection for nothing, since the very
		// next attempt has nowhere new to route to either and goes
		// straight back out DIRECT, identically to the one just killed.
		logf("l7sni: %s -> %s:%d matched a routes list, but redirecting failed: %v", host, dstIP, dport, err)
		return false
	}
	srcIP := net.IP(src[:]).String()
	h.dropFlow(actx, proto, srcIP, dstIP, uint(sport), uint(dport))
	adaptiveroute.NoteAdded(adaptiveroute.Note{
		Addr: dstIP, Tier: adaptiveroute.TierL7SNI, Reason: adaptiveroute.ReasonL7SNI, Host: host,
		Client: srcIP, Proto: proto, DPort: uint(dport), At: h.now(),
	})
	label := ""
	if proto == "udp" {
		label = " (QUIC)"
	}
	if shared {
		logf("l7sni: %s -> %s:%d%s matched a routes list, but this IP also recently served %q -- "+
			"redirecting with a short TTL to limit collateral impact on unrelated traffic sharing the address",
			host, dstIP, dport, label, previousHost)
		return true
	}
	logf("l7sni: %s -> %s:%d%s matched a routes list, redirecting", host, dstIP, dport, label)
	return true
}

// extractTLS tries ExtractTLSInfo directly against payload (the common
// case: the whole ClientHello landed in one captured packet), falling back
// to Reassembler for one already in progress, or starting one when payload
// looks like the start of a ClientHello but TLSRecordLen says more is still
// to come.
func (h *l7sniHandler) extractTLS(key l7sni.FlowKey, seq uint32, payload []byte) (l7sni.ClientHelloInfo, bool) {
	if h.reasm.Lookup(key) {
		full, complete := h.reasm.Feed(key, seq, payload)
		if !complete {
			return l7sni.ClientHelloInfo{}, false
		}
		return l7sni.ExtractTLSInfo(full)
	}
	if info, ok := l7sni.ExtractTLSInfo(payload); ok {
		return info, true
	}
	if l7sni.IsTLSClientHello(payload) {
		if reclen := l7sni.TLSRecordLen(payload); reclen > len(payload) {
			h.reasm.Start(key, seq, payload, reclen)
		}
	}
	return l7sni.ClientHelloInfo{}, false
}
