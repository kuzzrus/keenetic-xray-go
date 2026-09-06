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
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	logf := func(string, ...any) {}
	ctx := context.Background()
	reconcileProxy0(ctx, cfg, logf)
	reconcileWGTransport(ctx, cfg, logf)
	reconcileMSSClamp(ctx, cfg, logf)
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
