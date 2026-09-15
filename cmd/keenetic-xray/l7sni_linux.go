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
	if err := l7capture.EnsureNFLOGModule(ctx); err != nil {
		logf("l7sni: loading NFLOG kernel modules failed: %v", err)
		return
	}

	wan, err := l7capture.ResolveWANInterface("")
	if err != nil {
		logf("l7sni: WAN interface detection failed: %v", err)
		return
	}
	if err := l7capture.EnsureRules(ctx, l7capture.RuleOptions{WANInterface: wan, Group: l7sniNflogGroup}); err != nil {
		logf("l7sni: installing NFLOG rules failed: %v", err)
		return
	}
	capture, err := l7capture.Open(l7sniNflogGroup)
	if err != nil {
		logf("l7sni: NFLOG capture unavailable: %v", err)
		return
	}
	defer capture.Close()

	reasm := l7sni.NewReassembler(l7sniReassembleMaxAge, l7sniReassembleMaxSize)
	expire := time.NewTicker(l7sniReassembleMaxAge)
	defer expire.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-expire.C:
				reasm.Expire(time.Now())
			}
		}
	}()

	logf("l7sni: capturing on %s (NFLOG group %d)", wan, l7sniNflogGroup)
	for {
		if ctx.Err() != nil {
			return
		}
		pkt, err := capture.Read()
		if err != nil {
			logf("l7sni: capture read failed, stopping: %v", err)
			return
		}
		l7SNIHandlePacket(ctx, pkt.Payload, reasm, logf)
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
func l7SNIHandlePacket(ctx context.Context, raw []byte, reasm *l7sni.Reassembler, logf func(string, ...any)) {
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

	cfg, err := config.Load(configPath())
	if err != nil || !cfg.L7SNI.Enabled || !l7sniMatchesRoutes(cfg, host) {
		return
	}

	dstIP := net.IP(dst[:]).String()
	actx, cancel := context.WithTimeout(ctx, adaptiveRouteOpTimeout)
	defer cancel()
	_ = adaptiveroute.AddIP(actx, adaptiveRouteIPSet, dstIP, cfg.AdaptiveRoute.EffectiveOKTTL())
	keenetic.DeleteConntrackFlow(actx, "tcp", net.IP(src[:]).String(), dstIP, uint(sport), uint(dport))
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
