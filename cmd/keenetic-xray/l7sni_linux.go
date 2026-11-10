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
	"fmt"
	"sync/atomic"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

// reconcileL7SNI re-asserts the NFLOG-triggering iptables rules when the
// firmware has dropped them -- l7SNIClassifyLoop's own capture keeps
// running regardless (NFLOG itself doesn't depend on the iptables rule
// that feeds it, only on the rule to actually *receive* anything), but
// without this a firewall rebuild silently stops sending packets its
// way. Same cheap check-then-fix shape as this file's neighbor
// reconcileAdaptiveRoute (cmd/keenetic-xray/adaptiveroute.go).
//
// Failures are logged here and also returned, for the one caller that has to
// tell the operator whether the rules are in place (`transport l7sni quic`);
// the reconcile loop just tries again on its next tick.
func reconcileL7SNI(ctx context.Context, cfg *config.Config, logf func(string, ...any)) error {
	if !cfg.L7SNI.Enabled || !keenetic.Available() {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	wan, err := l7capture.ResolveWANInterface("")
	if err != nil {
		logf("l7sni: reconcile WAN detection failed: %v", err)
		return err
	}
	opts := l7capture.RuleOptions{WANInterface: wan, Group: l7sniNflogGroup, QUIC: cfg.EffectiveL7SNIQUIC() != config.L7SNIQUICOff}
	if l7capture.RulesInPlace(cctx, opts) {
		return nil
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
		return err
	}
	if err := l7capture.EnsureRules(cctx, opts); err != nil {
		logf("l7sni: reconcile failed: %v", err)
		return err
	}
	logf("l7sni: re-asserted NFLOG rules on %s (they were missing or out of date)", wan)
	return nil
}

// l7sniOptionalDepsTried is set by the first capture session of the process: it
// installs the optional tools (conntrack) too, later sessions do not try again.
var l7sniOptionalDepsTried atomic.Bool

// l7sniNflogGroup is this project's own NFLOG group number -- picked to
// be distinctive; nothing else on a Keenetic router is expected to
// claim it, and there's no registry to check against, same as any
// other NFLOG consumer's own private choice (HydraRoute Neo's own
// default is 210, a different number, so the two could even coexist on
// one router without conflict).
const l7sniNflogGroup = 4210

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

// l7SNIClassifyLoop runs L7 hostname detection end to end, self-healing
// across capture failures (L7-02): a session (l7SNIClassifySession) that
// ends because its NFLOG read failed used to leave L7 SNI silently and
// permanently dead until the whole daemon restarted, with nothing to
// notice short of an operator eventually realizing matches had stopped
// happening at all. reconcileL7SNI (routerReconcileLoop) already
// repairs firewall-rule drift on its own schedule, but never touched
// this read loop itself -- a session that goes down now gets a fresh
// one, with the whole startup sequence (kernel modules, WAN detection,
// rules, socket) run again from scratch.
//
// Startup-level failures (feature disabled, no ndmc, config load
// failed) are deliberately NOT retried here -- l7SNIClassifySession
// reports started=false for all of those, same as it returning at all
// used to mean before this change -- since none of them are expected to
// resolve themselves moments later on their own; toggling L7SNI live,
// or a router only appearing later, already needs a daemon restart to
// be noticed, matching AdaptiveRoute.Enabled's own documented behavior.
func l7SNIClassifyLoop(ctx context.Context, logf func(string, ...any)) {
	for {
		started, err := l7SNIClassifySession(ctx, logf)
		if ctx.Err() != nil {
			return
		}
		if !started {
			return
		}
		logf("l7sni: capture session ended (%v), restarting in %s", err, l7sniRestartDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(l7sniRestartDelay):
		}
	}
}

// l7sniRestartDelay is how long l7SNIClassifyLoop waits before opening a
// fresh capture session after one ends unexpectedly -- long enough that
// a persistent problem doesn't spin a busy retry loop, short enough that
// a transient one (a firewall rebuild racing capture setup, say)
// self-heals in well under a minute.
const l7sniRestartDelay = 5 * time.Second

// l7SNIClassifySession runs one attempt at L7 hostname detection: brings
// up the NFLOG capture and its iptables rules (only if cfg.L7SNI.Enabled
// -- toggling this later needs a daemon restart to take effect, same as
// AdaptiveRoute.Enabled does), then reads packets until either ctx is
// cancelled or the capture itself fails, extracting a hostname via
// internal/l7sni and, on a match against the operator's own Routing
// lists, adding that connection's destination straight to the adaptive-
// routing ipset and flushing its own conntrack entry so it re-routes
// immediately. See config.L7SNIConfig's own doc comment for why the
// adaptive-routing ipset, not Routing's own NDM object-groups, is the
// right dataplane to feed a directly-detected IP into.
//
// started reports whether capture actually got going -- false for every
// startup-declined-or-failed case (feature off, no ndmc, config load
// failed, kernel module load, WAN detection, rule install, or socket
// open); l7SNIClassifyLoop uses this to decide whether retrying the
// session is even worth attempting (see its own doc comment, L7-02).
func l7SNIClassifySession(ctx context.Context, logf func(string, ...any)) (started bool, sessionErr error) {
	cfg, err := config.Load(configPath())
	if err != nil {
		logf("l7sni: config load failed, not starting: %v", err)
		return false, nil
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
		return false, nil
	}
	if !keenetic.Available() {
		logf("l7sni: ndmc not found, not starting")
		return false, nil
	}

	// What the capture needs, before it tries to use it: iptables (the rules
	// below are its first call -- without it the session used to die right
	// there, once, with a line in this log and no second attempt) and the NFLOG
	// kernel modules. Found live (2026-09-15) that EnsureRules fails outright
	// with "iptables: No chain/target/match by that name" until the modules
	// are loaded; the opkg feed has no package for them, so loading is all
	// there is to do -- see EnsureNFLOGModule's doc comment. The same call
	// brings back a tool that /opt lost since L7 SNI was switched on.
	//
	// Everything is ensured on the first start of this process; a restart of the
	// session (every few seconds while the socket keeps failing) only checks what
	// the capture cannot run without, so an optional tool that could not be
	// installed once does not start `opkg update` again on every retry.
	logf("l7sni: checking iptables and the NFLOG kernel modules")
	ensure := featureEnsureRequired
	if l7sniOptionalDepsTried.CompareAndSwap(false, true) {
		ensure = featureEnsure
	}
	dctx, dcancel := context.WithTimeout(ctx, featuredeps.Timeout)
	deps := ensure(dctx, featuredeps.L7SNI)
	dcancel()
	for _, line := range deps.Lines("", "") {
		logf("l7sni: %s", line)
	}
	if err = deps.Err(); err != nil {
		logf("l7sni: not starting: %v", err)
		return false, err
	}

	wan, err := l7capture.ResolveWANInterface("")
	if err != nil {
		logf("l7sni: WAN interface detection failed: %v", err)
		return false, err
	}

	cfgQUIC := cfg.EffectiveL7SNIQUIC()
	ruleOpts := l7capture.RuleOptions{WANInterface: wan, Group: l7sniNflogGroup, QUIC: cfgQUIC != config.L7SNIQUICOff}

	logf("l7sni: installing NFLOG rules on %s (QUIC %s)", wan, cfgQUIC)
	rctx, rcancel := context.WithTimeout(ctx, l7sniStartupTimeout)
	err = l7capture.EnsureRules(rctx, ruleOpts)
	rcancel()
	if err != nil {
		logf("l7sni: installing NFLOG rules failed: %v", err)
		return false, err
	}

	logf("l7sni: opening NFLOG capture socket (group %d)", l7sniNflogGroup)
	capture, err := l7capture.Open(l7sniNflogGroup)
	if err != nil {
		logf("l7sni: NFLOG capture unavailable: %v", err)
		return false, err
	}
	defer capture.Close()

	// sctx is this session's lifetime, which ends when the daemon's does or
	// when the loop below returns on a read error -- and the loop restarts
	// the session after that (l7SNIClassifyLoop). Every goroutine started
	// below waits on sctx rather than on the daemon's ctx: tied to ctx, the
	// ones of a session that had failed stayed parked until shutdown, one
	// more pair for every restart, holding the dead session's tables, and
	// the closer below closed a descriptor number its own session had given
	// back long before.
	sctx, endSession := context.WithCancel(ctx)
	defer endSession()

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
		<-sctx.Done()
		capture.Close()
	}()

	handler := newL7SNIHandler(l7sniStatsState)

	// quicMode is the effective QUIC mode, updated by the capture loop below
	// each time it re-reads config and read by the publisher goroutine.
	var quicMode atomic.Value
	quicMode.Store(config.L7SNIQUICOff)

	expire := time.NewTicker(l7sniReassembleMaxAge)
	defer expire.Stop()
	publish := time.NewTicker(l7sniStatsPublishEvery)
	defer publish.Stop()
	publishStats := func(final bool) {
		reads, msgs := capture.BatchStats()
		l7sniStatsState.setBatches(reads, msgs)
		gap := l7sniStatsMinInterval
		if final {
			gap = 0
		}
		if _, err := l7sniStatsState.publishIfDirty(l7sniStatsPath(), time.Now(), gap, quicMode.Load().(string)); err != nil {
			logf("l7sni: publishing stats failed: %v", err)
		}
	}
	go func() {
		for {
			select {
			case <-sctx.Done():
				return
			case <-expire.C:
				handler.expire(time.Now())
			case <-publish.C:
				publishStats(false)
			}
		}
	}()
	// Deferred in this order so the final publish (which still sees this
	// session's read counters) runs before they are folded into the totals.
	defer l7sniStatsState.endBatches()
	defer publishStats(true)

	logf("l7sni: capturing on %s (NFLOG group %d, QUIC %s)", wan, l7sniNflogGroup, cfgQUIC)
	exclWatch := &adaptiveroute.ExclusionsWatcher{Path: adaptiveroute.ExclusionsPath(configPath())}
	snap := l7sniLoadSnapshot()
	snap.excluded, _ = exclWatch.Get()
	quicMode.Store(snap.quic)
	snapAt := time.Now()
	for {
		if ctx.Err() != nil {
			return true, nil
		}
		pkt, err := capture.Read()
		if err != nil {
			return true, fmt.Errorf("capture read failed: %w", err)
		}
		if time.Since(snapAt) >= l7sniConfigRefreshInterval {
			snap = l7sniLoadSnapshot()
			snap.excluded, _ = exclWatch.Get()
			quicMode.Store(snap.quic)
			snapAt = time.Now()
		}
		handler.handle(ctx, pkt.Payload, snap, logf)
	}
}

// l7sniStatsState is the daemon's counters. One per process, not per capture
// session: a session that ends and restarts (L7-02) keeps counting.
var l7sniStatsState = newL7SNIStats(time.Now())

const (
	// l7sniStatsPublishEvery is how often the publisher looks at the
	// counters; l7sniStatsMinInterval is the least time between two writes of
	// the file. /tmp is RAM, so the write is cheap, but there is no reason to
	// do it more than a few times a minute.
	l7sniStatsPublishEvery = 5 * time.Second
	l7sniStatsMinInterval  = 10 * time.Second
)
