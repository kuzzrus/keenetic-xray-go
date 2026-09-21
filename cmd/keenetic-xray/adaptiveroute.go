package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/knownranges"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// inertExclusionWarnInterval is how often warnIfExclusionInert repeats
// itself while the condition persists.
const inertExclusionWarnInterval = 10 * time.Minute

// exclusionLookupFor returns the ExcludedRangeLookup clsCfg should carry
// for cfg's current DisableRussianExclusion setting (AR-06) -- pulled out
// as its own pure function so this decision is unit-testable without a
// real router: adaptiveRouteClassifyLoop's own loop body is gated behind
// keenetic.Available(), unreachable in this dev/CI environment.
func exclusionLookupFor(cfg *config.Config) func(string) (string, bool) {
	if cfg.AdaptiveRoute.DisableRussianExclusion {
		return nil
	}
	return georanges.Lookup
}

// warnIfExclusionInert says so, in the log the operator actually reads,
// when the Russian-exclusion veto is switched on but has no data behind
// it and is therefore doing nothing at all.
//
// Exists because that exact state went unnoticed for a day (2026-09-16):
// georanges' first fetch timed out, the table stayed empty,
// ExcludedRangeLookup matched nothing, and Russian addresses kept being
// promoted -- while everything *looked* configured and working. The one
// "refresh failed" line scrolls out of `keenetic-xray logs` within
// minutes on a router where xray logs every connection, so a single
// failure message at startup is not enough on its own: a silent safety
// feature has to keep saying it is silent.
func warnIfExclusionInert(clsCfg *classifier.Config, lastWarn *time.Time, logf func(string, ...any)) {
	if clsCfg.ExcludedRangeLookup == nil || georanges.CurrentLen() > 0 {
		return
	}
	if time.Since(*lastWarn) < inertExclusionWarnInterval {
		return
	}
	*lastWarn = time.Now()
	logf("adaptive-route: ВНИМАНИЕ — исключение российских адресов включено, но список не загружен, " +
		"вето сейчас не действует (georanges ещё качается или источник недоступен)")
}

// adaptiveRouteIPSet is the one ipset internal/adaptiveroute's REDIRECT
// rule matches against (internal/adaptiveroute.RedirectSetName -- shared
// with internal/botcontrol's bot screen for the same feature, so both
// point at the exact same set). Unlike upstream Susanin's four (test/ok
// x tcp/udp), this project doesn't need the kernel to distinguish
// test-tier from ok-tier membership -- both need the same REDIRECT
// treatment, and internal/classifier's own State (test/ok/cooldown) is
// what actually tracks which tier an address is in. See
// internal/classifier's package doc comment.
const adaptiveRouteIPSet = adaptiveroute.RedirectSetName

// classifyInterval is how often adaptiveRouteClassifyLoop scans conntrack
// and runs FAST/SOFT/JUDGE. Upstream uses three separate knobs (fast/
// soft/judge_interval, defaulting to 1-2s each); one shared interval is
// simpler and the difference isn't meaningful for what this catches.
//
// 500ms, not upstream's 1-2s: found live on hardware (2026-09-15) that
// the original 2s made a first, cold app launch (Speedtest especially)
// visibly fail before the classifier ever got a chance to react -- a
// SYN's own first retransmit is already ~1s in, so a 2s tick could add
// another full second-plus on top before FAST even looks, well past
// what an impatient app waits for on its first attempt. A relaunch
// then "worked" only because the destination was already promoted by
// then, not because anything was actually fixed. Ticking 4x faster
// directly cuts that reaction latency without changing any detection
// threshold -- nothing becomes a more trigger-happy false positive,
// the same conditions just get checked for sooner. Affordable: a
// conntrack scan measured at 0.01s for 435 entries, nowhere near
// expensive enough to need a slower cadence for its own sake.
const classifyInterval = 500 * time.Millisecond

// healthCheckInterval/healthFailThreshold gate adaptive routing's own
// fail-open to DIRECT: no upstream Susanin equivalent, added 2026-09-15
// after comparing against Fiark/susanin (a sibling project for MikroTik
// RouterOS -- see docs/HANDOFF-susanin.md), which fails open exactly
// this way rather than keep sending already-confirmed-good traffic into
// a dead tunnel. Without this, a single-profile router (no backup to
// fail over to -- see PRs #167/#171-#174's whole theme today) whose
// live egress goes down would leave every redirected destination
// hanging against dead outbound indefinitely, worse than DIRECT would
// have been. Dual-profile routers are naturally covered by failover
// switching to backup already (the dokodemo-door inbound's single
// default outbound rides whatever's newly live) -- this specifically
// closes the no-backup gap, though it applies either way.
//
// 15s / 2 consecutive failures before tripping: frequent enough that an
// outage is caught quickly, not so frequent it hammers the live proxy
// with synthetic requests; 2 rather than 1 so a single slow/rate-limited
// probe doesn't trip it on its own (same reasoning ProbeOptions.Retries
// already applies within one probe attempt). Recovery only needs a
// single successful probe -- staying failed-open a little too long
// after the tunnel is back just delays redirects resuming, whereas
// staying "still redirecting" too long during a real outage means more
// hung connections, so the asymmetry is deliberate.
const (
	healthCheckInterval = 15 * time.Second
	healthFailThreshold = 2
)

// adaptiveRouteFailedOpen mirrors adaptiveRouteHealthCheck's loop-local
// failedOpen for the one consumer outside adaptiveRouteClassifyLoop's own
// goroutine: reconcileAdaptiveRoute (driven by routerReconcileLoop, a
// separate goroutine, every couple of minutes and on-demand via the ndm
// SIGUSR1 hook). AR-09: reconcile's own "is REDIRECT in place" check
// can't distinguish a deliberate fail-open clear from the firmware having
// just dropped the rule on its own -- without this, reconcile silently
// undid an active emergency fail-open within its own next cycle (at most
// ~2 minutes, or immediately if SIGUSR1 fires in between), re-redirecting
// traffic into a tunnel already confirmed dead. Package-level and atomic
// since the two goroutines have no other shared state today; the
// loop-local bool stays as the classify loop's own fast, no-atomic-needed
// check for its own single-goroutine use.
var adaptiveRouteFailedOpen atomic.Bool

// adaptiveRouteOpTimeout bounds every individual ipset/iptables/conntrack
// call adaptiveRouteClassifyLoop's own goroutine makes directly
// (applyAdaptiveRouteActions; adaptiveRouteHealthCheck's recovery path
// uses a longer budget of its own, see there) -- that same goroutine
// also drives the classify ticker and the health-check ticker
// (everything in its select loop runs sequentially), so an unbounded
// external call hanging here doesn't just fail one action, it silently
// freezes classification, health-checking, and logging for as long as
// the hang lasts, with nothing to notice or recover. Found live on
// hardware (2026-09-15): right after a wide known-range promotion swept
// a burst of previously-untracked traffic into the redirect, both the
// daemon's own live log and actual routing appeared to hang -- a
// restart was the only way to recover. 5s is generous for what should
// normally be a single-digit-millisecond ipset/conntrack call, while
// still keeping the loop's own 500ms classifyInterval meaningfully
// self-healing instead of stuck indefinitely on one bad call.
const adaptiveRouteOpTimeout = 5 * time.Second

// transportAdaptive is `keenetic-xray transport adaptive {show|on|off|flush}`
// -- Susanin Phase 2's native per-IP adaptive routing (see
// docs/HANDOFF-susanin.md): a conntrack classifier (internal/classifier)
// feeding an iptables REDIRECT rule (internal/adaptiveroute) into xray's
// dokodemo-door inbound, riding whatever vless/naive profile is already
// the live egress.
func transportAdaptive(cfg *config.Config, args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		printTransport(cfg)
		return nil
	case "on":
		return adaptiveRouteOn(cfg)
	case "off":
		return adaptiveRouteOff(cfg)
	case "flush":
		return adaptiveRouteFlush()
	default:
		return fmt.Errorf("usage: keenetic-xray transport adaptive {show|on|off|flush}")
	}
}

func adaptiveRouteOn(cfg *config.Config) error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adaptiveroute.EnsureIPSetTool(ctx); err != nil {
		return err
	}
	// Best-effort, not fatal like EnsureIPSetTool above: without
	// conntrack, the redirect itself still works (new connection
	// attempts are caught cleanly), it's only an already-established
	// flow's immediate re-route that degrades to "wait for the client's
	// own retry" -- see internal/keenetic/conntrack.go's doc comment.
	if err := keenetic.EnsureConntrackTool(ctx); err != nil {
		fmt.Printf("предупреждение: conntrack недоступен (%v) — уже открытые соединения не будут сразу перенаправляться, только новые попытки\n", err)
	}
	iface, subnet, err := adaptiveRouteLAN(ctx, cfg)
	if err != nil {
		return err
	}
	if err := adaptiveroute.EnsureIPSet(ctx, adaptiveRouteIPSet); err != nil {
		return fmt.Errorf("создание ipset: %w", err)
	}
	if err := adaptiveroute.EnsureRedirect(ctx, adaptiveroute.RedirectOptions{
		SetName:       adaptiveRouteIPSet,
		Port:          cfg.AdaptiveRoute.EffectivePort(),
		LANInterfaces: []string{iface},
	}); err != nil {
		return fmt.Errorf("установка REDIRECT: %w", err)
	}

	cfg.AdaptiveRoute.Enabled = true
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("адаптивная маршрутизация включена: %s (LAN %s), xray слушает :%d\n",
		iface, subnet, cfg.AdaptiveRoute.EffectivePort())
	fmt.Println("⚠️ параллельно с аддоном susanin не запускать — тот же смысл, конфликтующий дата-плейн")
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

// adaptiveRouteOff also flushes the ipset, not just the REDIRECT rule --
// found live (2026-09-15) that without this, "off" left every already-
// confirmed address (an individual entry carries up to
// AdaptiveRoute.EffectiveOKTTL(), 6h by default -- see
// adaptiveroute.AddIP's doc comment) sitting in the set, ready to start
// redirecting again the instant "on" re-adds the REDIRECT rule, even
// addresses that were false positives. A bare off/on toggle silently
// undid nothing.
//
// Deliberately does NOT also clear the classifier's own persisted state
// the way adaptiveRouteFlush does: while AdaptiveRoute.Enabled is false,
// adaptiveRouteClassifyLoop's own ticker branch is a no-op (see its
// `!cfg.AdaptiveRoute.Enabled` check), so a stale in-memory belief just
// sits frozen and harmless until re-enabled -- no redirecting actually
// happens either way while off, which is exactly what "off" promises.
// It only matters again once switched back on, which is what
// adaptiveRouteFlush is for.
func adaptiveRouteOff(cfg *config.Config) error {
	if keenetic.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := adaptiveroute.ClearRedirect(ctx); err != nil {
			fmt.Printf("предупреждение: не удалось убрать REDIRECT-правило: %v\n", err)
		}
		if err := adaptiveroute.Flush(ctx, adaptiveRouteIPSet); err != nil {
			fmt.Printf("предупреждение: не удалось очистить список адресов: %v\n", err)
		}
	}
	cfg.AdaptiveRoute.Enabled = false
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("адаптивная маршрутизация выключена")
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

// adaptiveRouteFlush clears every address/subnet currently redirected,
// without touching AdaptiveRoute.Enabled or the REDIRECT rule itself --
// for when the feature should stay on, but accumulated state (stale
// entries surviving a daemon restart or an off/on toggle; or an ordinary
// false positive that got stuck in the OK tier, see docs/HANDOFF-
// susanin.md) needs clearing right now instead of waiting out each
// entry's own TTL.
//
// Also removes the classifier's own persisted state and restarts the
// daemon -- found live (2026-09-15) that a bare ipset flush isn't
// enough on its own: the *running* classifier's in-memory state (loaded
// once, at daemon startup, into adaptiveRouteClassifyLoop's own local
// variable -- see that function) still believes every flushed address
// is confirmed, and JUDGE only re-adds a confirmed address to the ipset
// once it's close to its own TTL expiry (up to AdaptiveRoute.
// EffectiveOKTTL(), 6h by default, for an individual address; up to 30
// minutes for a block). Left alone, that mismatch silently suppresses
// re-promotion of exactly the ranges that were working fine before the
// flush, for as long as each one's own TTL allows -- observed live as
// "nothing loads" even though individual addresses were visibly being
// caught fresh in the log. Deleting the file alone doesn't help either
// while the daemon keeps running: its own periodic save (every 5
// minutes, see adaptiveRouteClassifyLoop) just writes the same stale
// in-memory state straight back. Only a real restart clears the
// in-memory copy and makes classifier.LoadState fall back to a truly
// empty classifier.NewState().
func adaptiveRouteFlush() error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := adaptiveroute.Flush(ctx, adaptiveRouteIPSet); err != nil {
		return fmt.Errorf("очистка ipset: %w", err)
	}
	if err := os.Remove(adaptiveRouteStatePath()); err != nil && !os.IsNotExist(err) {
		fmt.Printf("предупреждение: не удалось удалить сохранённое состояние классификатора: %v\n", err)
	}
	fmt.Println("адаптивная маршрутизация: список перенаправляемых адресов и состояние классификатора очищены")
	// Not applyDaemonChange: its first try (SIGHUP -> live xray/failover
	// config reload) would report "applied, no restart needed" while
	// leaving the classifier's in-memory state (the actual point of this
	// command) completely untouched -- go straight to offering a real
	// restart instead.
	offerDaemonRestart(bufio.NewReader(os.Stdin))
	return nil
}

// adaptiveRouteLAN resolves the LAN interface (real kernel device name,
// for the REDIRECT rule's -i match) and client subnet (for the
// classifier's from-LAN check). The subnet is cfg.AdaptiveRoute.LANSubnet
// verbatim if set, else a /24 derived from the router's own detected LAN
// IP -- see AdaptiveRouteConfig's doc comment for why that default is
// reasonable but not a guarantee.
func adaptiveRouteLAN(ctx context.Context, cfg *config.Config) (iface string, subnet *net.IPNet, err error) {
	iface, err = keenetic.LANInterfaceOSName(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("определение LAN-интерфейса: %w", err)
	}
	if cfg.AdaptiveRoute.LANSubnet != "" {
		_, n, perr := net.ParseCIDR(cfg.AdaptiveRoute.LANSubnet)
		if perr != nil {
			return "", nil, fmt.Errorf("lan_subnet %q: %w", cfg.AdaptiveRoute.LANSubnet, perr)
		}
		return iface, n, nil
	}
	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		return "", nil, fmt.Errorf("определение LAN IP: %w", err)
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return "", nil, fmt.Errorf("LAN IP %q: не IPv4", ip)
	}
	mask := net.CIDRMask(24, 32)
	return iface, &net.IPNet{IP: v4.Mask(mask), Mask: mask}, nil
}

// applyAdaptiveRouteAtStartup brings up Susanin Phase 2's dataplane
// (ipset + REDIRECT) when the daemon starts, same best-effort pattern as
// applyProxy0AtStartup/applyWGTransportAtStartup. The classifier itself
// starts separately (adaptiveRouteClassifyLoop) -- this is only the
// dataplane xray's inbound needs to actually receive anything.
func applyAdaptiveRouteAtStartup(cfg *config.Config, logf func(string, ...any)) {
	if !cfg.AdaptiveRoute.Enabled || !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := adaptiveroute.EnsureIPSetTool(ctx); err != nil {
		logf("adaptive-route: ipset tool unavailable: %v", err)
		return
	}
	// Best-effort, not fatal like EnsureIPSetTool above -- see
	// adaptiveRouteOn's matching call for why.
	if err := keenetic.EnsureConntrackTool(ctx); err != nil {
		logf("adaptive-route: conntrack unavailable (%v) -- already-open flows won't be redirected immediately, only new attempts", err)
	}
	iface, _, err := adaptiveRouteLAN(ctx, cfg)
	if err != nil {
		logf("adaptive-route: LAN detection failed: %v", err)
		return
	}
	if err := adaptiveroute.EnsureIPSet(ctx, adaptiveRouteIPSet); err != nil {
		logf("adaptive-route: ipset create failed: %v", err)
		return
	}
	if err := adaptiveroute.EnsureRedirect(ctx, adaptiveroute.RedirectOptions{
		SetName:       adaptiveRouteIPSet,
		Port:          cfg.AdaptiveRoute.EffectivePort(),
		LANInterfaces: []string{iface},
	}); err != nil {
		logf("adaptive-route: REDIRECT setup failed: %v", err)
		return
	}
	logf("adaptive-route: %s -> xray :%d", iface, cfg.AdaptiveRoute.EffectivePort())
}

// adaptiveRouteClassifyLoop runs Susanin Phase 2's classifier
// continuously while cfg.AdaptiveRoute.Enabled: scans conntrack, runs
// FAST/SOFT/JUDGE plus block-promotion (internal/classifier -- pure
// logic), and carries out whatever Actions come back via
// internal/adaptiveroute (ipset) and internal/keenetic (conntrack -D).
// Runs on its own ticker, independent of routerReconcileLoop's 2-minute
// cadence -- this needs to run every couple of seconds to mean anything.
//
// LAN subnet/interface are resolved once, on the first tick after the
// feature is (re-)found enabled, and kept for the rest of this process's
// life -- a real LAN topology change mid-run is rare enough that picking
// it up on the next daemon restart (which happens for plenty of other
// reasons already) is an acceptable simplification over re-resolving on
// every single tick.
func adaptiveRouteClassifyLoop(ctx context.Context, logf func(string, ...any)) {
	statePath := adaptiveRouteStatePath()
	var state *classifier.State
	if _, err := os.Stat(adaptiveRouteResetMarkerPath()); err == nil {
		// adaptiveRouteFlush asked for a clean start -- see its own doc
		// comment (internal/botcontrol/adaptiveroute.go) for why this
		// can't just rely on it having deleted statePath directly before
		// triggering the restart that leads here: the *previous*
		// process's own shutdown save (this same select loop's own
		// ctx.Done() case, below) can silently recreate that file from
		// its still-stale in-memory state after the delete already ran.
		// Checking here instead is race-free: by the time this startup
		// code runs, Entware's own stop-then-start restart sequence
		// guarantees the previous process (and any final save it was
		// going to do) has already finished. Remove both the marker
		// (honored) and statePath itself (it may be the just-recreated
		// stale copy) rather than leaving either for a future restart to
		// trip over.
		_ = os.Remove(adaptiveRouteResetMarkerPath())
		_ = os.Remove(statePath)
		state = classifier.NewState()
		logf("adaptive-route: classifier state reset (requested via flush)")
	} else if loaded, err := classifier.LoadState(statePath); err == nil {
		state = loaded
	} else {
		state = classifier.NewState()
	}
	cache := classifier.NewRateCache()
	var clsCfg *classifier.Config
	healthFails := 0
	failedOpen := false
	var inertWarnedAt time.Time

	t := time.NewTicker(classifyInterval)
	defer t.Stop()
	save := time.NewTicker(5 * time.Minute)
	defer save.Stop()
	health := time.NewTicker(healthCheckInterval)
	defer health.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = classifier.SaveState(statePath, state)
			return
		case <-health.C:
			adaptiveRouteHealthCheck(ctx, &healthFails, &failedOpen, logf)
			continue
		case <-save.C:
			_ = classifier.SaveState(statePath, state)
			continue
		case <-t.C:
		}

		cfg, err := config.Load(configPath())
		if err != nil || !cfg.AdaptiveRoute.Enabled || !keenetic.Available() {
			continue
		}
		if failedOpen {
			// The live egress is unhealthy (see adaptiveRouteHealthCheck)
			// -- REDIRECT is already cleared, so there's nothing to catch
			// new destinations *into* right now. Keep classifying nothing
			// rather than accumulating Actions that would just be redone
			// once the health check re-asserts the dataplane.
			continue
		}

		if clsCfg == nil {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, subnet, rerr := adaptiveRouteLAN(rctx, cfg)
			cancel()
			if rerr != nil {
				logf("adaptive-route: classifier LAN detection failed: %v", rerr)
				continue
			}
			c := classifier.DefaultConfig()
			c.LANSubnets = []*net.IPNet{subnet}
			// knownranges.Lookup reads whatever table knownRangesRefreshLoop
			// currently has loaded (cmd/keenetic-xray/knownranges.go) --
			// wiring the function reference once here is enough, no need
			// to re-set it as the table itself refreshes in the background.
			c.KnownRangeLookup = knownranges.Lookup
			// ExcludedRangeLookup is set below, in the per-tick refresh
			// alongside OKTTL/BlockThreshold (AR-06) -- unlike
			// KnownRangeLookup just above, DisableRussianExclusion is a
			// live settings toggle, so it can't just be wired once here.
			clsCfg = &c
			logf("adaptive-route: classifier started (LAN subnet %s)", subnet)
		}
		// Re-applied every tick, unlike LANSubnets above (resolved once
		// -- a real topology change is rare enough to just wait for the
		// next restart, per that block's own comment): OKTTL is meant to
		// be live-tunable from the bot's TTL buttons, and cfg itself is
		// already reloaded from disk above on every tick anyway, so this
		// is free and makes a changed setting apply within one tick
		// instead of needing clsCfg rebuilt (which only happens on
		// AdaptiveRoute.Enabled going false then true again).
		clsCfg.OKTTL = cfg.AdaptiveRoute.EffectiveOKTTL()
		clsCfg.BlockThreshold = cfg.AdaptiveRoute.EffectiveBlockThreshold()
		// AR-06: DisableRussianExclusion is a live settings toggle too
		// (same as OKTTL/BlockThreshold just above), but until now this
		// mirrored only the initial clsCfg==nil build above, not this
		// per-tick refresh -- flipping it in the bot without a full
		// daemon restart (AdaptiveRoute.Enabled off/on again) silently
		// did nothing.
		clsCfg.ExcludedRangeLookup = exclusionLookupFor(cfg)
		warnIfExclusionInert(clsCfg, &inertWarnedAt, logf)

		now := time.Now()
		flows, err := classifier.ScanConntrack("")
		if err != nil {
			logf("adaptive-route: conntrack scan failed: %v", err)
			continue
		}

		var actions []classifier.Action
		actions = append(actions, classifier.ClrFast(clsCfg, state, flows, now)...)
		actions = append(actions, classifier.ClrSoft(clsCfg, state, cache, flows, now)...)
		actions = append(actions, classifier.ClrJudge(clsCfg, state, flows, now)...)
		actions = append(actions, classifier.ClrBlockPromote(clsCfg, state, now)...)
		state.Expire(now)

		applyAdaptiveRouteActions(ctx, actions, logf)
	}
}

// adaptiveRouteHealthCheck is adaptive routing's own fail-open check --
// see healthCheckInterval/healthFailThreshold's doc comment for why this
// exists at all. Probes the live egress through the same local SOCKS
// inbound and the same HealthCheckURL/FallbackURLs/Retries/RetryDelay
// config the failover daemon's own health check already uses (see
// internal/failover's realActions.probeOptions) -- deliberately its own
// independent probe rather than reading failover.Daemon's state,
// because adaptiveRouteClassifyLoop has no reference to the live Daemon
// (it's constructed and run standalone from cmd/keenetic-xray's main),
// and re-probing directly is simpler than threading one through.
//
// failedFails and failedOpen are the caller's own loop-scoped state,
// passed by pointer so this stays a plain function instead of a method
// on some new receiver type just for two counters.
func adaptiveRouteHealthCheck(ctx context.Context, healthFails *int, failedOpen *bool, logf func(string, ...any)) {
	cfg, err := config.Load(configPath())
	if err != nil || !cfg.AdaptiveRoute.Enabled || !keenetic.Available() {
		return
	}

	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	perr := xrayctl.Probe(pctx, xrayctl.ProbeOptions{
		SOCKSAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.Failover.SOCKSPort),
		URL:          cfg.Failover.HealthCheckURL,
		FallbackURLs: cfg.Failover.HealthCheckFallbackURLs,
		Retries:      cfg.Failover.CheckRetries,
		RetryDelay:   time.Duration(cfg.Failover.CheckRetryDelaySeconds) * time.Second,
		Timeout:      8 * time.Second,
	})
	cancel()

	if perr != nil {
		*healthFails++
		if *healthFails < healthFailThreshold || *failedOpen {
			return
		}
		*failedOpen = true
		adaptiveRouteFailedOpen.Store(true) // AR-09: tell reconcileAdaptiveRoute not to undo this
		// 30s, not adaptiveRouteOpTimeout -- same budget as the recovery
		// sequence below and applyAdaptiveRouteAtStartup/
		// reconcileAdaptiveRoute's own equivalent calls, all of which run
		// on this same classify-loop goroutine and must not be able to
		// block it indefinitely (see adaptiveRouteOpTimeout's doc comment
		// for the incident that found this gap).
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := adaptiveroute.ClearRedirect(cctx); err != nil {
			logf("adaptive-route: fail-open to DIRECT: clearing REDIRECT failed: %v", err)
			return
		}
		logf("adaptive-route: live egress unhealthy (%d probe failures) -- failed open to DIRECT", *healthFails)
		return
	}

	*healthFails = 0
	if !*failedOpen {
		return
	}
	*failedOpen = false
	adaptiveRouteFailedOpen.Store(false) // AR-09: reconcileAdaptiveRoute may re-assert again now

	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	iface, _, err := adaptiveRouteLAN(cctx, cfg)
	if err != nil {
		logf("adaptive-route: egress healthy again, but re-asserting REDIRECT failed: %v", err)
		return
	}
	if err := adaptiveroute.EnsureIPSet(cctx, adaptiveRouteIPSet); err != nil {
		logf("adaptive-route: egress healthy again, but ipset recreate failed: %v", err)
		return
	}
	if err := adaptiveroute.EnsureRedirect(cctx, adaptiveroute.RedirectOptions{
		SetName:       adaptiveRouteIPSet,
		Port:          cfg.AdaptiveRoute.EffectivePort(),
		LANInterfaces: []string{iface},
	}); err != nil {
		logf("adaptive-route: egress healthy again, but REDIRECT re-assert failed: %v", err)
		return
	}
	logf("adaptive-route: live egress healthy again -- re-enabled REDIRECT on %s", iface)
}

// applyAdaptiveRouteActions carries out one classification pass's
// Actions. Best-effort throughout, same spirit as
// keenetic.FlushConntrackForGroups' per-IP deletes: a single failed
// ipset/conntrack call isn't worth aborting the rest of the batch over,
// and every one of these is naturally retried on the next tick anyway.
// Logs AddIP/RemoveIP (the two user-meaningful events -- a destination
// started or stopped being redirected) so `keenetic-xray logs`/📜 Логи
// has something real to grep during hardware verification; the matching
// conntrack -D is just plumbing underneath an Add/Remove, not its own
// event.
func applyAdaptiveRouteActions(ctx context.Context, actions []classifier.Action, logf func(string, ...any)) {
	for _, a := range actions {
		actx, cancel := context.WithTimeout(ctx, adaptiveRouteOpTimeout)
		switch a.Kind {
		case classifier.ActionAddIP:
			_ = adaptiveroute.AddIP(actx, adaptiveRouteIPSet, a.IP, a.TTL)
			if strings.Contains(a.IP, "/") {
				logf("adaptive-route: redirecting subnet %s (block-promoted)", a.IP)
			} else {
				logf("adaptive-route: redirecting %s", a.IP)
			}
		case classifier.ActionRemoveIP:
			_ = adaptiveroute.RemoveIP(actx, adaptiveRouteIPSet, a.IP)
			logf("adaptive-route: no longer redirecting %s", a.IP)
		case classifier.ActionDeleteConntrack:
			keenetic.DeleteConntrackFlow(actx, a.Flow.Proto, a.Flow.Src, a.Flow.Dst, a.Flow.SPort, a.Flow.DPort)
		}
		cancel()
	}
}

// reconcileAdaptiveRoute re-asserts the dataplane (ipset + REDIRECT rule)
// when the firmware has dropped it -- the classification loop's own
// ticker keeps running regardless, but it has nothing to redirect into
// without this. Same cheap-check-then-fix shape as the other reconcile
// steps in this file's neighbors (reconcileMSSClamp, reconcileWGTransport).
func reconcileAdaptiveRoute(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	// AR-09: a missing REDIRECT rule isn't always the firmware having
	// dropped it -- adaptiveRouteHealthCheck clears it on purpose when
	// the live egress is confirmed dead, and re-asserting it here would
	// silently send traffic straight back into a tunnel that's still
	// down. Wait for the health check's own recovery probe to confirm
	// egress is healthy and clear this flag instead. Checked first, ahead
	// of Enabled/Available() below, since it's the cheapest possible
	// guard (an atomic load, no syscall) and the outcome (skip entirely)
	// is the same regardless of check order.
	if adaptiveRouteFailedOpen.Load() {
		return
	}
	if !cfg.AdaptiveRoute.Enabled || !keenetic.Available() {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	iface, _, err := adaptiveRouteLAN(cctx, cfg)
	if err != nil {
		logf("adaptive-route: reconcile LAN detection failed: %v", err)
		return
	}
	opts := adaptiveroute.RedirectOptions{
		SetName:       adaptiveRouteIPSet,
		Port:          cfg.AdaptiveRoute.EffectivePort(),
		LANInterfaces: []string{iface},
	}
	if adaptiveroute.RedirectInPlace(cctx, opts) {
		return
	}
	if err := adaptiveroute.EnsureIPSet(cctx, adaptiveRouteIPSet); err != nil {
		logf("adaptive-route: ipset create failed: %v", err)
		return
	}
	if err := adaptiveroute.EnsureRedirect(cctx, opts); err != nil {
		logf("adaptive-route: reconcile failed: %v", err)
		return
	}
	logf("adaptive-route: re-asserted REDIRECT on %s :%d (firmware had dropped it)", iface, opts.Port)
}
