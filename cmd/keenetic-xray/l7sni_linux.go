//go:build linux

// L7 hostname detection (internal/l7sni + internal/l7capture) needs a
// real AF_NETLINK/NFLOG socket, which only exists on Linux -- see
// internal/l7capture's own nflog.go doc comment. l7sni_other.go is the
// stub every other platform gets instead, same platform-split-file
// precedent as this package's own daemonctl_restart_unix.go/_other.go,
// so main.go can call l7SNIClassifyLoop unconditionally regardless of
// what it's built for.

package main

import (
	"context"
	"net"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7sni"
)

// reconcileL7SNI re-asserts the NFLOG-triggering iptables rules when the
// firmware has dropped them -- l7SNIClassifyLoop's own capture keeps
// running regardless (NFLOG itself doesn't depend on the iptables rule
// that feeds it, only on the rule to actually *receive* anything), but
// without this a firewall rebuild silently stops sending packets its
// way. Same cheap check-then-fix shape as this file's neighbor
// reconcileAdaptiveRoute (cmd/keenetic-xray/adaptiveroute.go).
func reconcileL7SNI(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	if !cfg.L7SNI.Enabled || !keenetic.Available() {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	wan, err := l7capture.ResolveWANInterface("")
	if err != nil {
		logf("l7sni: reconcile WAN detection failed: %v", err)
		return
	}
	opts := l7capture.RuleOptions{WANInterface: wan, Group: l7sniNflogGroup}
	if l7capture.RulesInPlace(cctx, opts) {
		return
	}
	// Found live (2026-09-15): without this, a router where the NFLOG
	// kernel modules never got loaded (l7SNIClassifyLoop's own startup
	// hung before reaching that point -- see l7sniStartupTimeout's doc
	// comment) left reconcile retrying EnsureRules and failing with the
	// same "No chain/target/match by that name" error every
	// reconcileInterval tick forever, never once addressing the actual
	// cause. Same ensure-before-add sequence as l7SNIClassifyLoop's own
	// startup; cheap once the modules are actually loaded (EnsureNFLOGModule
	// is a no-op check against /proc/modules in that case).
	if err := l7capture.EnsureNFLOGModule(cctx); err != nil {
		logf("l7sni: reconcile: loading NFLOG kernel modules failed: %v", err)
		return
	}
	if err := l7capture.EnsureRules(cctx, opts); err != nil {
		logf("l7sni: reconcile failed: %v", err)
		return
	}
	logf("l7sni: re-asserted NFLOG rules on %s (firmware had dropped them)", wan)
}

// l7sniNflogGroup is this project's own NFLOG group number -- picked to
// be distinctive; nothing else on a Keenetic router is expected to
// claim it, and there's no registry to check against, same as any
// other NFLOG consumer's own private choice (HydraRoute Neo's own
// default is 210, a different number, so the two could even coexist on
// one router without conflict).
const l7sniNflogGroup = 4210

// l7sniReassembleMaxAge/l7sniReassembleMaxSize bound the Reassembler's
// memory: an incomplete split ClientHello is dropped after this long (a
// lost segment, or traffic that was never really TLS at all), and this
// is the largest single ClientHello this will ever buffer.
const (
	l7sniReassembleMaxAge  = 5 * time.Second
	l7sniReassembleMaxSize = 16384
)

// l7sniStartupTimeout bounds each individual step of l7SNIClassifyLoop's
// startup sequence below. Found live (2026-09-15): none of these calls
// had a bound before this -- EnsureNFLOGModule and EnsureRules were
// given the raw, never-cancelled daemon context, so a kernel-module
// load or an iptables call that didn't return promptly would hang this
// entire goroutine forever with nothing logged (not even a failure),
// while the independent reconcileL7SNI kept retrying and failing with
// "No chain/target/match by that name" every reconcileInterval tick
// since the goroutine that was supposed to load the module never got
// that far. Each step now gets its own bounded context and its own
// "about to do X" log line, so a future hang is at least immediately
// localized to one step instead of producing total silence again.
const l7sniStartupTimeout = 15 * time.Second

// l7SNIClassifyLoop runs L7 hostname detection end to end: brings up
// the NFLOG capture and its iptables rules once (only if
// cfg.L7SNI.Enabled at startup -- toggling this later needs a daemon
// restart to take effect, same as AdaptiveRoute.Enabled does), then
// reads packets forever, extracts a hostname via internal/l7sni, and on
// a match against the operator's own Routing lists, adds that
// connection's destination straight to the adaptive-routing ipset and
// flushes its own conntrack entry so it re-routes immediately. See
// config.L7SNIConfig's own doc comment for why the adaptive-routing
// ipset, not Routing's own NDM object-groups, is the right dataplane to
// feed a directly-detected IP into.
func l7SNIClassifyLoop(ctx context.Context, logf func(string, ...any)) {
	cfg, err := config.Load(configPath())
	if err != nil {
		logf("l7sni: config load failed, not starting: %v", err)
		return
	}
	if !cfg.L7SNI.Enabled {
		// Deliberately quiet: this is the ordinary "feature is off"
		// case, checked on every daemon start regardless of whether the
		// operator has ever touched l7sni at all -- see
		// adaptiveRouteClassifyLoop's own equivalent check for the same
		// reasoning. Found live (2026-09-15) that going all the way
		// silent here made "did it actually turn on" indistinguishable
		// from every real failure mode below during hardware testing --
		// worth this one line even though it fires on most daemon
		// starts.
		logf("l7sni: disabled (transport l7sni on to enable)")
		return
	}
	if !keenetic.Available() {
		logf("l7sni: ndmc not found, not starting")
		return
	}

	// Found live (2026-09-15): EnsureRules below fails outright with
	// "iptables: No chain/target/match by that name" until the kernel
	// modules NFLOG needs are actually loaded -- this project's opkg
	// feed doesn't carry a separate installable package for either one,
	// see EnsureNFLOGModule's own doc comment for the full story.
	logf("l7sni: loading NFLOG kernel modules")
	mctx, mcancel := context.WithTimeout(ctx, l7sniStartupTimeout)
	err = l7capture.EnsureNFLOGModule(mctx)
	mcancel()
	if err != nil {
		logf("l7sni: loading NFLOG kernel modules failed: %v", err)
		return
	}

	wan, err := l7capture.ResolveWANInterface("")
	if err != nil {
		logf("l7sni: WAN interface detection failed: %v", err)
		return
	}

	logf("l7sni: installing NFLOG rules on %s", wan)
	rctx, rcancel := context.WithTimeout(ctx, l7sniStartupTimeout)
	err = l7capture.EnsureRules(rctx, l7capture.RuleOptions{WANInterface: wan, Group: l7sniNflogGroup})
	rcancel()
	if err != nil {
		logf("l7sni: installing NFLOG rules failed: %v", err)
		return
	}

	logf("l7sni: opening NFLOG capture socket (group %d)", l7sniNflogGroup)
	capture, err := l7capture.Open(l7sniNflogGroup)
	if err != nil {
		logf("l7sni: NFLOG capture unavailable: %v", err)
		return
	}
	defer capture.Close()

	// capture.Read below is a raw blocking syscall with no context
	// awareness at all -- ctx.Err() is only checked *between* reads, so
	// on a quiet NFLOG group (nothing matching the capture rule right
	// now) this loop can sit blocked in the kernel indefinitely, past
	// the point the rest of the daemon has already been told to shut
	// down. Found live (2026-09-16): this daemon's own SIGTERM handler
	// only cancels ctx (cmd/keenetic-xray/main.go) -- Go doesn't wait for
	// other goroutines when main returns, so this alone never blocked
	// process exit, but it does mean capture.Close's own graceful NFLOG
	// unbind (internal/l7capture's Open doc comment) never got a chance
	// to run, leaving the *next* process to clean up an uncleanly-closed
	// binding instead of a tidy one -- a real, if not fully measured,
	// contributor to a self-update that took far longer than normal to
	// come back online. Closing capture here the moment ctx is
	// cancelled unblocks the read with an error, so the main loop below
	// exits through its own ordinary error path instead.
	go func() {
		<-ctx.Done()
		capture.Close()
	}()

	reasm := l7sni.NewReassembler(l7sniReassembleMaxAge, l7sniReassembleMaxSize)
	sharedIPs := newL7SNISharedIPTracker()
	expire := time.NewTicker(l7sniReassembleMaxAge)
	defer expire.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-expire.C:
				now := time.Now()
				reasm.Expire(now)
				sharedIPs.expire(now)
			}
		}
	}()

	logf("l7sni: capturing on %s (NFLOG group %d)", wan, l7sniNflogGroup)
	snap := l7sniLoadSnapshot()
	snapAt := time.Now()
	for {
		if ctx.Err() != nil {
			return
		}
		pkt, err := capture.Read()
		if err != nil {
			logf("l7sni: capture read failed, stopping: %v", err)
			return
		}
		if time.Since(snapAt) >= l7sniConfigRefreshInterval {
			snap = l7sniLoadSnapshot()
			snapAt = time.Now()
		}
		l7SNIHandlePacket(ctx, pkt.Payload, reasm, sharedIPs, snap, logf)
	}
}

// l7sniConfigRefreshInterval is how often the capture loop re-reads
// config, replacing what used to be a config.Load *per captured packet*
// inside l7SNIHandlePacket. Found by reading the hot path (2026-09-16)
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

// l7sniSnapshot is everything l7SNIHandlePacket needs from config,
// resolved once per l7sniConfigRefreshInterval instead of per packet.
// Owned by l7SNIClassifyLoop's own goroutine and passed down by value --
// no atomics or locking needed, since that loop is the only reader.
type l7sniSnapshot struct {
	enabled bool
	ttl     time.Duration
	domains l7sniDomainSet
}

// l7sniLoadSnapshot reads config once and pre-resolves it. A failed read
// yields the zero snapshot (disabled, no domains), which the hot path
// treats as "match nothing" -- the same do-nothing outcome the old
// per-packet config.Load already had on error.
func l7sniLoadSnapshot() l7sniSnapshot {
	cfg, err := config.Load(configPath())
	if err != nil {
		return l7sniSnapshot{}
	}
	return l7sniSnapshot{
		enabled: l7sniEnabled(cfg),
		ttl:     cfg.AdaptiveRoute.EffectiveOKTTL(),
		domains: l7sniDomainsFrom(cfg),
	}
}

// l7SNIHandlePacket parses one NFLOG-captured packet, extracts a
// hostname if it's carrying (or completes) a TLS ClientHello or an HTTP
// request, and acts on a route-list match. Best-effort throughout --
// anything that doesn't parse cleanly is simply not a packet this
// feature has a use for, not an error worth logging on every occurrence
// (this runs on every captured packet; a persistent problem would show
// up as "never logs a match", something hardware testing needs to
// notice directly, not a log line per uninteresting packet).
func l7SNIHandlePacket(ctx context.Context, raw []byte, reasm *l7sni.Reassembler, sharedIPs *l7sniSharedIPTracker, snap l7sniSnapshot, logf func(string, ...any)) {
	if !snap.enabled || len(snap.domains) == 0 {
		// Nothing this packet could possibly match -- checked before any
		// parsing at all, since with no route lists configured (the
		// common case for an operator who hasn't set any up) every
		// captured packet would otherwise be fully parsed just to be
		// discarded at the match step.
		return
	}
	proto, src, dst, sport, dport, seq, payload, ok := l7sni.ParseIPv4(raw)
	if !ok || proto != 6 { // TCP only -- QUIC (UDP) is out of scope, see internal/l7sni's doc comment
		return
	}

	var host string
	switch dport {
	case 443:
		h, ok := l7SNIExtractTLS(reasm, l7sni.FlowKey{Src: src, Dst: dst, SPort: sport, DPort: dport}, seq, payload)
		if !ok {
			return
		}
		host = h
	case 80:
		h, ok := l7sni.ExtractHTTPHost(payload)
		if !ok {
			return
		}
		host = h
	default:
		return
	}

	// AR-07: note every successfully-extracted hostname, matched or not
	// -- what this needs to catch is "does dst also serve something
	// else", which requires seeing every sighting, not just the ones
	// that happen to match a route list.
	previousHost, shared := sharedIPs.note(dst, host, time.Now())

	if !snap.domains.matches(host) {
		return
	}

	dstIP := net.IP(dst[:]).String()
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
	if err := adaptiveroute.AddIP(actx, adaptiveRouteIPSet, dstIP, ttl); err != nil {
		// L7-01 (part 2/3): a failed AddIP means dst was never actually
		// redirected -- deleting the conntrack entry anyway would just
		// tear down a working connection for nothing, since the very
		// next attempt has nowhere new to route to either and goes
		// straight back out DIRECT, identically to the one just killed.
		logf("l7sni: %s -> %s:%d matched a routes list, but redirecting failed: %v", host, dstIP, dport, err)
		return
	}
	keenetic.DeleteConntrackFlow(actx, "tcp", net.IP(src[:]).String(), dstIP, uint(sport), uint(dport))
	if shared {
		logf("l7sni: %s -> %s:%d matched a routes list, but this IP also recently served %q -- "+
			"redirecting with a short TTL to limit collateral impact on unrelated traffic sharing the address",
			host, dstIP, dport, previousHost)
		return
	}
	logf("l7sni: %s -> %s:%d matched a routes list, redirecting", host, dstIP, dport)
}

// l7SNIExtractTLS tries ExtractTLSSNI directly against payload (the
// common case: the whole ClientHello landed in one captured packet),
// falling back to Reassembler for one already in progress, or starting
// one when payload looks like the start of a ClientHello but
// TLSRecordLen says more is still to come.
func l7SNIExtractTLS(reasm *l7sni.Reassembler, key l7sni.FlowKey, seq uint32, payload []byte) (string, bool) {
	if reasm.Lookup(key) {
		full, complete := reasm.Feed(key, seq, payload)
		if !complete {
			return "", false
		}
		return l7sni.ExtractTLSSNI(full)
	}
	if host, ok := l7sni.ExtractTLSSNI(payload); ok {
		return host, true
	}
	if l7sni.IsTLSClientHello(payload) {
		if reclen := l7sni.TLSRecordLen(payload); reclen > len(payload) {
			reasm.Start(key, seq, payload, reclen)
		}
	}
	return "", false
}
