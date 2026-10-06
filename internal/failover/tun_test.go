package failover

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// tunDeviceStub makes the OpkgTun kernel device exist or not, per the
// returned switch, for as long as the test runs.
func tunDeviceStub(t *testing.T, present bool) *atomic.Bool {
	t.Helper()
	var p atomic.Bool
	p.Store(present)
	orig := tunDevicePresent
	tunDevicePresent = func(string) bool { return p.Load() }
	t.Cleanup(func() { tunDevicePresent = orig })
	return &p
}

func tunTestConfig() *config.Config {
	cfg := inboundTestConfig()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun3", MTU: 1400}
	return cfg
}

// productionTun returns the tun inbound of the production config, or nil
// when it carries none.
func productionTun(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading production config: %v", err)
	}
	var decoded struct {
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, in := range decoded.Inbounds {
		if in["protocol"] == "tun" {
			return in
		}
	}
	return nil
}

func TestTunInboundOpts(t *testing.T) {
	device := tunDeviceStub(t, true)
	a := newRealActions(inboundTestPaths(t), tunTestConfig())

	got := a.tunInboundOpts()
	if got == nil || got.Name != "opkgtun3" || got.MTU != 1400 {
		t.Fatalf("tunInboundOpts = %+v, want opkgtun3 / 1400", got)
	}

	// MTU left at its default.
	a.cfg.TunTransport.MTU = 0
	if got := a.tunInboundOpts(); got == nil || got.MTU != config.DefaultTunMTU {
		t.Errorf("default MTU: %+v", got)
	}
	a.cfg.TunTransport.MTU = 1400

	// Each reason for no inbound.
	for name, mutate := range map[string]func(){
		"transport off":       func() { a.cfg.TunTransport.Enabled = false },
		"interface not set":   func() { a.cfg.TunTransport.Iface = "" },
		"not an OpkgTun name": func() { a.cfg.TunTransport.Iface = "Wireguard4" },
		"no kernel device":    func() { device.Store(false) },
		"breaker tripped":     func() { a.tunTrippedAt.Store(time.Now().UnixNano()) },
	} {
		t.Run(name, func(t *testing.T) {
			saved := a.cfg.TunTransport
			defer func() { a.cfg.TunTransport = saved; device.Store(true); a.tunTrippedAt.Store(0) }()
			mutate()
			if got := a.tunInboundOpts(); got != nil {
				t.Errorf("tunInboundOpts = %+v, want nil", got)
			}
		})
	}

	// The breaker lets go after tunRetryAfter.
	a.tunTrippedAt.Store(time.Now().Add(-tunRetryAfter - time.Minute).UnixNano())
	if got := a.tunInboundOpts(); got == nil {
		t.Error("the inbound stayed out past the retry window")
	}
}

func TestRealActions_SwitchLiveTo_TunInbound(t *testing.T) {
	device := tunDeviceStub(t, true)
	cfg := tunTestConfig()
	paths := inboundTestPaths(t)
	a := newRealActions(paths, cfg)
	defer a.prod.Stop()

	if err := a.SwitchLiveTo(context.Background(), RolePrimary); err != nil {
		t.Fatal(err)
	}
	tun := productionTun(t, paths.ProductionConfig)
	if tun == nil {
		t.Fatal("production config has no tun inbound although the device exists")
	}
	if tun["tag"] != "tun-in" || tun["settings"].(map[string]any)["name"] != "opkgtun3" {
		t.Errorf("tun inbound = %#v", tun)
	}
	if !a.tunLive.Load() {
		t.Error("tunLive = false after writing a config with the inbound")
	}

	// The device went away: the next config has no inbound, and says so.
	device.Store(false)
	if err := a.SwitchLiveTo(context.Background(), RolePrimary); err != nil {
		t.Fatal(err)
	}
	if productionTun(t, paths.ProductionConfig) != nil {
		t.Error("tun inbound kept although its device is gone")
	}
	if a.tunLive.Load() {
		t.Error("tunLive = true after writing a config without the inbound")
	}
}

// TestDaemon_RefreshTunInbound: the OpkgTun device appears after xray
// started (boot order, the reconcile loop re-created the interface) -- the
// inbound is added; the device goes away -- it is taken out; nothing
// changed -- xray is left alone.
func TestDaemon_RefreshTunInbound(t *testing.T) {
	device := tunDeviceStub(t, false)
	cfg := tunTestConfig()
	paths := inboundTestPaths(t)
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()

	waitUntil(t, 5*time.Second, d.actions.prod.Running)
	if productionTun(t, paths.ProductionConfig) != nil || d.TunInboundLive() {
		t.Fatal("tun inbound present although the device did not exist at start")
	}
	if d.RefreshTunInbound(ctx) {
		t.Error("RefreshTunInbound restarted xray with nothing to change")
	}

	device.Store(true)
	if !d.RefreshTunInbound(ctx) {
		t.Fatal("RefreshTunInbound = false although the device appeared")
	}
	if productionTun(t, paths.ProductionConfig) == nil || !d.TunInboundLive() {
		t.Error("the inbound was not added")
	}
	if d.RefreshTunInbound(ctx) {
		t.Error("second RefreshTunInbound restarted xray with the inbound already in")
	}

	device.Store(false)
	if !d.RefreshTunInbound(ctx) {
		t.Fatal("RefreshTunInbound = false although the device went away")
	}
	if productionTun(t, paths.ProductionConfig) != nil || d.TunInboundLive() {
		t.Error("the inbound was not taken out")
	}
}

// TestDaemon_TunBreaker is the point of the whole file: an xray that cannot
// bring the TUN inbound up must not stay in a crash loop. The fake xray
// exits at once when its config has the inbound; after tunCrashLimit
// crashes the daemon rewrites the config without it, xray stays up, and the
// operator is told. After the retry window one more attempt is made, and
// the breaker can fire again -- a retry does not disarm it.
func TestDaemon_TunBreaker(t *testing.T) {
	tunDeviceStub(t, true)
	cfg := tunTestConfig()
	paths := inboundTestPaths(t)
	paths.Env = []string{"FAILOVER_TEST_HELPER=crash-on-tun"}
	d := NewDaemon(paths, cfg)
	d.actions.prod.BackoffMin = 5 * time.Millisecond
	d.actions.prod.BackoffMax = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()

	tripped := func() bool { return d.actions.tunTrippedAt.Load() != 0 }
	stable := func() bool {
		return tripped() && !d.TunInboundLive() && d.actions.prod.Running() && productionTun(t, paths.ProductionConfig) == nil
	}
	waitUntil(t, 10*time.Second, stable)
	waitForEvent(t, d, EventTunSuspended)

	// The fake stays up now, with no inbound; give a crash loop that failed
	// to stop a moment to show itself.
	time.Sleep(150 * time.Millisecond)
	if !stable() {
		t.Fatal("xray is not stable on the config without the inbound")
	}

	// While the breaker holds, a refresh must not put the inbound back.
	if d.RefreshTunInbound(ctx) {
		t.Fatal("RefreshTunInbound re-added the inbound inside the retry window")
	}

	// The retry window runs out: one more attempt, which fails the same way
	// and trips the breaker again.
	d.actions.tunTrippedAt.Store(time.Now().Add(-tunRetryAfter - time.Minute).UnixNano())
	if !d.RefreshTunInbound(ctx) {
		t.Fatal("RefreshTunInbound did not retry after the window")
	}
	first := d.actions.tunTrippedAt.Load()
	waitUntil(t, 10*time.Second, func() bool {
		return d.actions.tunTrippedAt.Load() > first && stable()
	})
	waitForEvent(t, d, EventTunSuspended)
}

func waitForEvent(t *testing.T, d *Daemon, kind EventKind) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ev := <-d.Events():
			if ev.Kind == kind {
				if ev.Detail == "" {
					t.Errorf("event %v has no Detail", kind)
				}
				return
			}
		case <-deadline:
			t.Fatalf("no event of kind %v", kind)
		}
	}
}

// Crashes that have nothing to do with the inbound -- a config without it,
// or ones long after the write -- never count.
func TestNoteTunCrash_Ignores(t *testing.T) {
	cfg := tunTestConfig()
	d := NewDaemon(inboundTestPaths(t), cfg)
	a := d.actions

	for i := 0; i < 2*tunCrashLimit; i++ { // config without the inbound
		a.noteTunWritten(false)
		d.noteTunCrash()
	}
	if a.tunTrippedAt.Load() != 0 {
		t.Error("tripped on crashes of a config that had no tun inbound")
	}

	a.noteTunWritten(true)
	a.tunWrittenAt.Store(time.Now().Add(-2 * tunCrashWindow).UnixNano()) // a long time ago
	for i := 0; i < 2*tunCrashLimit; i++ {
		d.noteTunCrash()
	}
	if a.tunTrippedAt.Load() != 0 {
		t.Error("tripped on crashes long after the config was written")
	}

	// Fewer than the limit, right after the write: still no trip.
	a.noteTunWritten(true)
	for i := 0; i < tunCrashLimit-1; i++ {
		d.noteTunCrash()
	}
	if a.tunTrippedAt.Load() != 0 {
		t.Error("tripped before the crash limit")
	}
}

// A change of the transport in config.json is an operator's fresh
// attempt: it lets the inbound back in at once. An unrelated reload does not.
func TestReloadConfig_ResetsBreakerOnTunChange(t *testing.T) {
	tunDeviceStub(t, false)
	cfg := tunTestConfig()
	d := NewDaemon(inboundTestPaths(t), cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()
	waitUntil(t, 5*time.Second, d.actions.prod.Running)

	trip := time.Now().UnixNano()
	d.actions.tunTrippedAt.Store(trip)

	same := tunTestConfig()
	if !d.ReloadConfig(ctx, same) {
		t.Fatal("ReloadConfig reported the daemon not ready")
	}
	if got := d.actions.tunTrippedAt.Load(); got != trip {
		t.Errorf("an unrelated reload changed the breaker: %d -> %d", trip, got)
	}

	changed := tunTestConfig()
	changed.TunTransport.Enabled = false
	if !d.ReloadConfig(ctx, changed) {
		t.Fatal("ReloadConfig reported the daemon not ready")
	}
	if got := d.actions.tunTrippedAt.Load(); got != 0 {
		t.Errorf("breaker still tripped after the transport was switched off: %d", got)
	}
}
