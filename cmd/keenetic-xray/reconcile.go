package main

import (
	"context"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// reconcileInterval is how often the daemon re-checks that its
// router-side config -- the Proxy0 upstream, the DNS-route lists, the
// forwarded-TCP MSS-clamp rule, the WG-transport interface -- is still
// what config.json says. `ndm` rewrites large parts of the
// firewall/routing on all sorts of events (a policy edit, a schedule, an
// interface flap) and silently drops anything it didn't add, so each of
// those pieces works right after `... on` and then quietly stops "some
// time later". Only the MSS rule used to self-heal; this loop covers the
// rest too.
const reconcileInterval = 2 * time.Minute

// routerReconcileLoop periodically runs reconcileOnce. It's the fallback:
// the netfilter.d hook (packaging/ndm/netfilter.d) makes ndm signal the
// daemon (SIGUSR1 -> reconcileOnce) the moment it rebuilds the firewall,
// so drift is normally fixed within a second, not up to two minutes.
func routerReconcileLoop(ctx context.Context, logf func(string, ...any)) {
	if !keenetic.Available() {
		return
	}
	t := time.NewTicker(reconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		reconcileOnce(ctx, logf)
	}
}

// reconcileOnce re-asserts every router-side setting once, cheaply: each
// step reads the live state first and only issues ndmc / iptables
// commands (and logs) when it finds drift. Config is reloaded so a change
// applied over SIGHUP (`proxy0 off`, `transport wg off`, a route edit) is
// respected.
func reconcileOnce(ctx context.Context, logf func(string, ...any)) {
	if !keenetic.Available() {
		return
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return
	}
	reconcileProxy0(ctx, cfg, logf)
	applyRoutesAtStartup(cfg, logf) // already drift-based and quiet-when-clean
	reconcileWGTransport(ctx, cfg, logf)
	reconcileMSSClamp(ctx, cfg, logf)
}

// reconcileProxy0 re-points the Proxy interface at the local inbound only
// when its upstream has drifted from the detected LAN IP / configured
// port.
func reconcileProxy0(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	if !cfg.Proxy0.Enabled {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(cctx, cfg.Proxy0.LANIP)
	if err != nil {
		return
	}
	host, port, ok, err := keenetic.Proxy0Upstream(cctx, cfg.Proxy0.Interface)
	if err != nil {
		return
	}
	if ok && host == ip && port == cfg.Proxy0Port() {
		return
	}
	if err := keenetic.ConfigureProxy0(cctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: cfg.Proxy0Port(),
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		logf("proxy0: reconcile failed: %v", err)
		return
	}
	logf("proxy0: re-asserted %s -> %s:%d (firmware had dropped it)", cfg.Proxy0.IfaceName(), ip, cfg.Proxy0Port())
}

// reconcileWGTransport rebuilds the WG-transport interface only when it's
// missing or down; the healthy path is a single `show interface` read.
func reconcileWGTransport(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	w := cfg.WGTransport
	if !w.Enabled || w.Iface == "" {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if keenetic.WGInterfaceUp(cctx, w.Iface) {
		return
	}
	logf("wg-transport: %s is down, rebuilding", w.Iface)
	applyWGTransportAtStartup(cfg, logf)
}

// reconcileMSSClamp re-adds this project's forwarded-TCP MSS-clamp rule
// when the firmware has flushed it -- the fix for the video stalls
// "coming back after a while".
func reconcileMSSClamp(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	mss := cfg.Proxy0.MSSClampValue()
	if !cfg.Proxy0.Enabled || mss <= 0 || !keenetic.IptablesPresent() {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if keenetic.MSSClampInPlace(cctx, mss) {
		return
	}
	if err := keenetic.SetMSSClamp(cctx, mss); err != nil {
		logf("mss-clamp: re-assert failed: %v", err)
		return
	}
	logf("mss-clamp: re-asserted MSS %d (firmware had dropped the rule)", mss)
}
