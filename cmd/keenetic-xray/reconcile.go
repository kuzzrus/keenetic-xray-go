package main

import (
	"context"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
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
// the ndm hooks (packaging/ndm/*) make ndm signal the daemon (SIGUSR1 ->
// reconcileOnce) the moment it rebuilds the firewall (netfilter.d), the
// LAN IP moves (ifipchanged.d) or a tracked interface comes back up
// (ifstatechanged.d), so drift is normally fixed within a second, not up
// to two minutes.
func routerReconcileLoop(ctx context.Context, d *failover.Daemon, logf func(string, ...any)) {
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
		reconcileOnce(ctx, d, logf)
	}
}

// reconcileOnce re-asserts every router-side setting once, cheaply: each
// step reads the live state first and only issues ndmc / iptables
// commands (and logs) when it finds drift. Config is reloaded so a change
// applied over SIGHUP (`proxy0 off`, `transport wg off`, a route edit) is
// respected. d is the live daemon, threaded through to reconcileWGTransport
// (WG-01) so a re-key it finds can reach the running xray-core, not just
// config.json; nil is fine (some callers -- tests, mainly -- have no
// daemon to push into), it just means that specific push is skipped.
func reconcileOnce(ctx context.Context, d *failover.Daemon, logf func(string, ...any)) {
	if !keenetic.Available() {
		return
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return
	}
	reconcileProxy0(ctx, cfg, logf)
	applyRoutesAtStartup(cfg, logf) // already drift-based and quiet-when-clean
	reconcileWGTransport(ctx, d, cfg, logf)
	reconcileMSSClamp(ctx, cfg, logf)
	reconcileDNS(ctx, cfg, logf)
	reconcileSusanin(ctx, logf)
	reconcileAdaptiveRoute(ctx, cfg, logf)
	reconcileL7SNI(ctx, cfg, logf)
	reconcileWatchdog(logf)
}

// reconcileWatchdog re-establishes cron when the watchdog's own crontab
// entry exists but nothing is actually running to fire it. Found live
// (2026-09-15): a router whose very first cron install silently failed
// at postinst time (best-effort, only ever printed a warning to a
// terminal nobody was watching -- and during a self-update specifically,
// printed from a process that's already been killed by the old
// package's own prerm by the time postinst runs, so there was never
// anyone to see it even in principle) kept the watchdog's crontab
// *entry* forever regardless -- SetWatchdogCron just writes a text file,
// it doesn't need a cron daemon to do that part. Completely inert:
// `keenetic-xray watchdog show` reported the entry as present the whole
// time, and the operator's only safety net for "the daemon didn't come
// back after a self-update" silently did nothing, discovered only when
// it was actually needed and didn't fire.
//
// Unlike the other reconcile steps here, cron has nothing to do with
// ndmc -- this only rides reconcileOnce's existing keenetic.Available()
// gate rather than running on its own schedule because this project
// only ever runs on Keenetic hardware anyway, not because it's Keenetic-
// specific in any real sense.
func reconcileWatchdog(logf func(string, ...any)) {
	enabled, err := install.WatchdogEnabled(cronFilePath())
	if err != nil || !enabled {
		return // never turned on -- an explicit choice, not drift to fix
	}
	if install.CronRunning() {
		return
	}
	logf("watchdog: cron daemon not running, entry is inert -- reinstalling cron")
	if _, err := watchdogEnable(); err != nil {
		logf("watchdog: could not re-establish cron: %v", err)
		return
	}
	logf("watchdog: cron reinstalled and running again")
}

// reconcileSusanin gets susanin running again if the operator has it
// installed but it's currently either stopped or never got its first
// egress configure (see addons.EnsureSusaninRunning) -- unlike the other
// reconcile steps this needs no cfg: susanin's own state lives entirely in
// its own susanin.conf, addons deliberately have no *config.Config access
// (see internal/addons/susanin.go), so addons.EnsureSusaninRunning reads
// that state itself and no-ops when susanin isn't installed or is already
// up and running.
func reconcileSusanin(ctx context.Context, logf func(string, ...any)) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	acted, err := addons.EnsureSusaninRunning(cctx)
	if err != nil {
		logf("susanin: reconcile failed: %v", err)
		return
	}
	if acted {
		logf("susanin: was unconfigured or stopped, self-healed")
	}
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
//
// WG-01: rebuilding can re-key the Keenetic side -- the firmware hands
// out a fresh keypair for an interface it had to recreate from scratch,
// same as applyWGTransportAtStartup's own "re-keyed by firmware" log
// line already anticipates. That call persists the new
// KeeneticPublicKey to config.json, but this function runs on
// routerReconcileLoop's own goroutine against its own independently-
// loaded cfg -- it was never the same *config.Config the daemon holds,
// and never called Daemon.ReloadConfig either, so the already-running
// xray-core (which baked the *old* key into its own generated config
// whenever it last started) never found out. The WG tunnel then stays
// broken until something unrelated happens to trigger a reload, or a
// manual restart. Push the fresh key into the live daemon here instead.
func reconcileWGTransport(ctx context.Context, d *failover.Daemon, cfg *config.Config, logf func(string, ...any)) {
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
	prevKey := cfg.WGTransport.KeeneticPublicKey
	applyWGTransportAtStartup(cfg, logf)
	if cfg.WGTransport.KeeneticPublicKey != prevKey {
		pushRekeyedWGConfig(ctx, d, cfg, logf)
	}
}

// pushRekeyedWGConfig is split out from reconcileWGTransport so its own
// plumbing (call ReloadConfig, log which outcome) is testable without a
// real router -- keenetic.Available() gates everything upstream of this
// call in this dev/CI environment, so a real key change can never be
// produced here without hardware; this is exercised directly instead,
// against a Daemon that's deliberately never had Run started.
func pushRekeyedWGConfig(ctx context.Context, d *failover.Daemon, cfg *config.Config, logf func(string, ...any)) {
	if d == nil {
		return
	}
	if d.ReloadConfig(ctx, cfg) {
		logf("wg-transport: re-keyed by firmware, pushed the new config to the live daemon")
	} else {
		logf("wg-transport: re-keyed by firmware, but the daemon wasn't ready to reload -- will need a restart to pick it up")
	}
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
