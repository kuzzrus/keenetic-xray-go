package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// adaptiveRouteIPSet is the one ipset internal/adaptiveroute's REDIRECT
// rule matches against. Unlike upstream Susanin's four (test/ok x tcp/
// udp), this project doesn't need the kernel to distinguish test-tier
// from ok-tier membership -- both need the same REDIRECT treatment, and
// internal/classifier's own State (test/ok/cooldown) is what actually
// tracks which tier an address is in. See internal/classifier's package
// doc comment.
const adaptiveRouteIPSet = "keenetic_xray_adaptive"

// classifyInterval is how often adaptiveRouteClassifyLoop scans conntrack
// and runs FAST/SOFT/JUDGE. Upstream uses three separate knobs (fast/
// soft/judge_interval, defaulting to 1-2s each); one shared interval is
// simpler and the difference isn't meaningful for what this catches.
const classifyInterval = 2 * time.Second

// transportAdaptive is `keenetic-xray transport adaptive {show|on|off}`
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
	default:
		return fmt.Errorf("usage: keenetic-xray transport adaptive {show|on|off}")
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

func adaptiveRouteOff(cfg *config.Config) error {
	if keenetic.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := adaptiveroute.ClearRedirect(ctx); err != nil {
			fmt.Printf("предупреждение: не удалось убрать REDIRECT-правило: %v\n", err)
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
// FAST/SOFT/JUDGE (internal/classifier -- pure logic), and carries out
// whatever Actions come back via internal/adaptiveroute (ipset) and
// internal/keenetic (conntrack -D). Runs on its own ticker, independent
// of routerReconcileLoop's 2-minute cadence -- this needs to run every
// couple of seconds to mean anything.
//
// LAN subnet/interface are resolved once, on the first tick after the
// feature is (re-)found enabled, and kept for the rest of this process's
// life -- a real LAN topology change mid-run is rare enough that picking
// it up on the next daemon restart (which happens for plenty of other
// reasons already) is an acceptable simplification over re-resolving on
// every single tick.
func adaptiveRouteClassifyLoop(ctx context.Context, logf func(string, ...any)) {
	statePath := adaptiveRouteStatePath()
	state, err := classifier.LoadState(statePath)
	if err != nil {
		state = classifier.NewState()
	}
	cache := classifier.NewRateCache()
	var clsCfg *classifier.Config

	t := time.NewTicker(classifyInterval)
	defer t.Stop()
	save := time.NewTicker(5 * time.Minute)
	defer save.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = classifier.SaveState(statePath, state)
			return
		case <-save.C:
			_ = classifier.SaveState(statePath, state)
			continue
		case <-t.C:
		}

		cfg, err := config.Load(configPath())
		if err != nil || !cfg.AdaptiveRoute.Enabled || !keenetic.Available() {
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
			clsCfg = &c
			logf("adaptive-route: classifier started (LAN subnet %s)", subnet)
		}

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
		state.Expire(now)

		applyAdaptiveRouteActions(ctx, actions)
	}
}

// applyAdaptiveRouteActions carries out one classification pass's
// Actions. Best-effort throughout, same spirit as
// keenetic.FlushConntrackForGroups' per-IP deletes: a single failed
// ipset/conntrack call isn't worth aborting the rest of the batch over,
// and every one of these is naturally retried on the next tick anyway.
func applyAdaptiveRouteActions(ctx context.Context, actions []classifier.Action) {
	for _, a := range actions {
		switch a.Kind {
		case classifier.ActionAddIP:
			_ = adaptiveroute.AddIP(ctx, adaptiveRouteIPSet, a.IP, a.TTL)
		case classifier.ActionRemoveIP:
			_ = adaptiveroute.RemoveIP(ctx, adaptiveRouteIPSet, a.IP)
		case classifier.ActionDeleteConntrack:
			keenetic.DeleteConntrackFlow(ctx, a.Flow.Proto, a.Flow.Src, a.Flow.Dst, a.Flow.SPort, a.Flow.DPort)
		}
	}
}

// reconcileAdaptiveRoute re-asserts the dataplane (ipset + REDIRECT rule)
// when the firmware has dropped it -- the classification loop's own
// ticker keeps running regardless, but it has nothing to redirect into
// without this. Same cheap-check-then-fix shape as the other reconcile
// steps in this file's neighbors (reconcileMSSClamp, reconcileWGTransport).
func reconcileAdaptiveRoute(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
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
