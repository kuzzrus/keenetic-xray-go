package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
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
	reconcileWGTransport(ctx, cfg, logf)
	reconcileMSSClamp(ctx, cfg, logf)
	reconcileSusanin(ctx, logf)
	reconcileAdaptiveRoute(ctx, cfg, logf)
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

// The loop returns promptly on a cancelled context and never ticks
// without ndmc.
func TestRouterReconcileLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { routerReconcileLoop(ctx, func(string, ...any) {}); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("routerReconcileLoop did not return after context cancel")
	}
}
