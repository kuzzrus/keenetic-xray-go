package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

// Without ndmc (CI / dev), every reconcile step must be a safe no-op --
// no panic, no crash, whatever the config asks for. Guards against a
// future nil-deref in the drift checks.
func TestReconcileSteps_NoRouterIsNoop(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)

	cfg := config.Default()
	cfg.Proxy0.Enabled = true
	cfg.Proxy0.MSSClamp = 1360
	cfg.WGTransport = config.WGTransportConfig{Enabled: true, Iface: "Wireguard4"}
	if _, err := cfg.WGTransport.EnsureKeys(); err != nil {
		t.Fatal(err)
	}
	cfg.WGTransport.KeeneticPublicKey = cfg.WGTransport.XrayPublicKey // any valid key
	cfg.AdaptiveRoute = config.AdaptiveRouteConfig{Enabled: true}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	logf := func(string, ...any) {}
	ctx := context.Background()
	reconcileProxy0(ctx, cfg, logf)
	reconcileWGTransport(ctx, nil, cfg, logf)
	reconcileMSSClamp(ctx, cfg, logf)
	reconcileSusanin(ctx, logf)
	reconcileAdaptiveRoute(ctx, cfg, logf)
	reconcileWatchdog(logf)
}

// TestPushRekeyedWGConfig_NoDaemonIsNoop confirms the nil-daemon guard --
// reconcileWGTransport's own tests run with no daemon reference (no
// router in this environment), so pushRekeyedWGConfig must tolerate that
// cleanly rather than assuming a live one always exists.
func TestPushRekeyedWGConfig_NoDaemonIsNoop(t *testing.T) {
	pushRekeyedWGConfig(context.Background(), nil, config.Default(), func(string, ...any) {
		t.Error("must not log anything when d is nil")
	})
}

// TestPushRekeyedWGConfig_DaemonNotReady is WG-01's regression test for
// pushRekeyedWGConfig's own plumbing: given a Daemon whose Run was never
// started (do() then blocks until the caller's ctx gives up, exactly as
// it would on a real router if Run genuinely wasn't servicing commands
// yet), it must call ReloadConfig and report the "wasn't ready" outcome
// -- not silently drop the re-keyed config. The "successfully pushed to
// a live daemon" outcome needs either real hardware or a heavier
// re-exec'd-Run test harness (see internal/failover's own tests for that
// pattern); this covers what's reachable without either.
func TestPushRekeyedWGConfig_DaemonNotReady(t *testing.T) {
	d := failover.NewDaemon(failover.Paths{}, config.Default())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var logged []string
	pushRekeyedWGConfig(ctx, d, config.Default(), func(format string, args ...any) {
		logged = append(logged, format)
	})
	if len(logged) != 1 || !strings.Contains(logged[0], "wasn't ready to reload") {
		t.Errorf("logged = %v, want one line reporting the daemon wasn't ready to reload", logged)
	}
}

// TestReconcileAdaptiveRoute_SkipsWhenFailedOpen is AR-09's regression
// test: reconcileAdaptiveRoute must not re-assert REDIRECT while
// adaptiveRouteHealthCheck has deliberately cleared it for a confirmed-
// dead egress -- that used to be indistinguishable from the firmware
// having simply dropped the rule, so reconcile silently undid an active
// emergency fail-open within its own next cycle. This environment has no
// real router to prove the *positive* case against (a real
// keenetic.Available()), so what's actually checked here is what's
// checkable without one: the flag genuinely gates the function (no
// panic either way) and defaults to false so every other reconcile path
// is unaffected by this change. The full behavioral guarantee -- that a
// missing REDIRECT rule stays missing while this flag is set -- can only
// be confirmed on real hardware.
func TestReconcileAdaptiveRoute_SkipsWhenFailedOpen(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)

	cfg := config.Default()
	cfg.AdaptiveRoute = config.AdaptiveRouteConfig{Enabled: true}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	adaptiveRouteFailedOpen.Store(true)
	t.Cleanup(func() { adaptiveRouteFailedOpen.Store(false) })

	var logged []string
	reconcileAdaptiveRoute(context.Background(), cfg, func(format string, args ...any) { logged = append(logged, format) })
	if len(logged) != 0 {
		t.Errorf("logged %v, want nothing while failed open", logged)
	}
}

// TestReconcileWatchdog_NotEnabledIsNoop is the regression test for a
// real incident (2026-09-15): a router whose very first cron install
// silently failed kept the watchdog's crontab *entry* forever (writing
// it doesn't need a cron daemon), completely inert -- `watchdog show`
// reported it present the whole time, but nothing was ever running to
// fire it. reconcileWatchdog's fix path only matters once the entry
// actually exists; this proves the "never turned on at all" case (a
// deliberate choice, not drift) stays a true no-op regardless -- it
// must never try to install cron on a router that never asked for the
// watchdog in the first place.
func TestReconcileWatchdog_NotEnabledIsNoop(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(t.TempDir(), "crontabs-root")) // deliberately absent

	var logged []string
	reconcileWatchdog(func(format string, args ...any) { logged = append(logged, format) })
	if len(logged) != 0 {
		t.Errorf("logged %v, want no action when the watchdog entry was never enabled", logged)
	}
}

// Same as above for the classifier's own loop: without ndmc it must sit
// idle (config.AdaptiveRoute.Enabled is true, but keenetic.Available()
// gates every tick's real work) and still return promptly on cancel --
// no panic, no hang, even though its ticker is running.
func TestAdaptiveRouteClassifyLoop_NoRouterStopsOnContextCancel(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	t.Setenv("KEENETIC_XRAY_ADAPTIVE_ROUTE_STATE", filepath.Join(t.TempDir(), "state.json"))

	cfg := config.Default()
	cfg.AdaptiveRoute = config.AdaptiveRouteConfig{Enabled: true}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { adaptiveRouteClassifyLoop(ctx, func(string, ...any) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("adaptiveRouteClassifyLoop did not return after context cancel")
	}
}

// TestAdaptiveRouteClassifyLoop_HonorsResetMarker covers the race found
// live (2026-09-16): adaptiveRouteFlush (both this package's own CLI
// version and internal/botcontrol's, see AR-10) can't reliably os.Remove
// the state file directly, since this loop's own still-running (in some
// other process) copy would just write its stale in-memory state
// straight back over the deletion moments later, via its own shutdown
// save below. A marker file next to the state path is what actually
// gets honored -- checked here directly: a pre-existing OK entry must
// NOT survive a startup that finds the marker, even though nothing here
// calls either adaptiveRouteFlush at all.
func TestAdaptiveRouteClassifyLoop_HonorsResetMarker(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	statePath := filepath.Join(t.TempDir(), "state.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	t.Setenv("KEENETIC_XRAY_ADAPTIVE_ROUTE_STATE", statePath)

	cfg := config.Default()
	cfg.AdaptiveRoute = config.AdaptiveRouteConfig{Enabled: true}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	stale := classifier.NewState()
	stale.OK[0]["138.124.255.106"] = time.Now().Add(time.Hour)
	if err := classifier.SaveState(statePath, stale); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath+".reset", nil, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { adaptiveRouteClassifyLoop(ctx, func(string, ...any) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("adaptiveRouteClassifyLoop did not return after context cancel")
	}

	if _, err := os.Stat(statePath + ".reset"); !os.IsNotExist(err) {
		t.Errorf("reset marker should have been removed, stat err = %v", err)
	}
	reloaded, err := classifier.LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState after reset: %v", err)
	}
	if len(reloaded.OK[0]) != 0 {
		t.Errorf("OK[0] = %v, want empty -- the stale entry survived a reset", reloaded.OK[0])
	}
}

// TestAdaptiveRouteHealthCheck_NoRouterIsNoop mirrors
// TestReconcileSteps_NoRouterIsNoop: without ndmc, the fail-open health
// check must return immediately and touch neither counter, the same as
// every other keenetic.Available()-gated step in this file. The "trips
// fail-open" / "recovers" branches need a real probe + real iptables,
// so they're not exercisable here -- hardware verification, not a unit
// test, covers those.
func TestAdaptiveRouteHealthCheck_NoRouterIsNoop(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)

	cfg := config.Default()
	cfg.AdaptiveRoute = config.AdaptiveRouteConfig{Enabled: true}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	fails, failedOpen := 0, false
	adaptiveRouteHealthCheck(context.Background(), &fails, &failedOpen, func(string, ...any) {})
	if fails != 0 || failedOpen {
		t.Errorf("healthFails=%d failedOpen=%v, want both untouched without ndmc", fails, failedOpen)
	}
}

// The loop returns promptly on a cancelled context and never ticks
// without ndmc.
func TestRouterReconcileLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { routerReconcileLoop(ctx, nil, func(string, ...any) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("routerReconcileLoop did not return after context cancel")
	}
}
