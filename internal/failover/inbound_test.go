package failover

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// inboundTestConfig is a one-profile config with every flag that would
// bind the inbound to the LAN by itself turned off -- config.Default()
// has proxy0.enabled on.
func inboundTestConfig() *config.Config {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "solo"},
	}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 0
	cfg.Proxy0.Enabled = false
	cfg.WGTransport.Enabled = false
	return cfg
}

func inboundTestPaths(t *testing.T) Paths {
	dir := t.TempDir()
	return Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
}

// productionListen returns the listen address of every inbound in the
// production config.
func productionListen(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading production config: %v", err)
	}
	var decoded struct {
		Inbounds []struct {
			Listen string `json:"listen"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	var out []string
	for _, in := range decoded.Inbounds {
		out = append(out, in.Listen)
	}
	return out
}

func wantListen(t *testing.T, path, want string) {
	t.Helper()
	got := productionListen(t, path)
	if len(got) == 0 {
		t.Fatal("production config has no inbounds")
	}
	for _, l := range got {
		if l != want {
			t.Fatalf("inbound listen = %v, want all %q", got, want)
		}
	}
}

// TestRealActions_SwitchLiveTo_InboundBind: the production inbound goes
// on all interfaces whenever Proxy0 points at it, proxy0.enabled or not
// -- the setup confirmed live on 2026-09-27 (proxy0.enabled false, Proxy0
// up at the inbound's port) worked only for as long as the WG transport
// kept the inbound off loopback. When the router can't answer, the last
// decision stands; the config flags never need to ask it.
func TestRealActions_SwitchLiveTo_InboundBind(t *testing.T) {
	errNoRouter := errors.New("ndmc: timeout")
	cases := []struct {
		name    string
		proxy0  bool // proxy0.enabled
		wg      bool // wg_transport.enabled
		answers []error
		inUse   []bool
		want    []string // listen after each SwitchLiveTo
	}{
		{"proxy0 points here", false, false, []error{nil}, []bool{true}, []string{"0.0.0.0"}},
		{"proxy0 elsewhere or absent", false, false, []error{nil}, []bool{false}, []string{"127.0.0.1"}},
		{"router unreadable at start", false, false, []error{errNoRouter}, []bool{false}, []string{"127.0.0.1"}},
		{"router unreadable later keeps LAN", false, false, []error{nil, errNoRouter}, []bool{true, false}, []string{"0.0.0.0", "0.0.0.0"}},
		{"proxy0 removed", false, false, []error{nil, nil}, []bool{true, false}, []string{"0.0.0.0", "127.0.0.1"}},
		{"proxy0.enabled", true, false, nil, nil, []string{"0.0.0.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := inboundTestConfig()
			cfg.Proxy0.Enabled = tc.proxy0
			cfg.WGTransport.Enabled = tc.wg
			paths := inboundTestPaths(t)
			a := newRealActions(paths, cfg)
			defer a.prod.Stop()

			call := 0
			a.proxyInUse = func(ctx context.Context, got *config.Config) (bool, error) {
				if tc.answers == nil {
					t.Error("asked the router although a config flag already decides")
					return false, nil
				}
				if got != cfg {
					t.Error("hook got a config other than the daemon's")
				}
				i := call
				call++
				return tc.inUse[i], tc.answers[i]
			}
			for i, want := range tc.want {
				if err := a.SwitchLiveTo(context.Background(), RolePrimary); err != nil {
					t.Fatalf("SwitchLiveTo #%d: %v", i+1, err)
				}
				wantListen(t, paths.ProductionConfig, want)
				if got := a.inboundOnLAN.Load(); got != (want == "0.0.0.0") {
					t.Errorf("inboundOnLAN after #%d = %v, want %v", i+1, got, want == "0.0.0.0")
				}
			}
		})
	}
}

// TestDaemon_RebindInbound: Proxy0 set up on the router after xray
// started on loopback is picked up by RebindInbound (the reconcile loop's
// call), which regenerates the config on the live role; a second call,
// with the inbound already on the LAN, leaves xray alone.
func TestDaemon_RebindInbound(t *testing.T) {
	cfg := inboundTestConfig()
	paths := inboundTestPaths(t)
	d := NewDaemon(paths, cfg)
	var inUse atomic.Bool
	var asked atomic.Int32
	d.SetProxyInUse(func(context.Context, *config.Config) (bool, error) {
		asked.Add(1)
		return inUse.Load(), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()
	defer func() {
		cancel()
		<-runErr
	}()

	waitUntil(t, 5*time.Second, d.actions.prod.Running)
	wantListen(t, paths.ProductionConfig, "127.0.0.1")
	if d.InboundOnLAN() {
		t.Fatal("InboundOnLAN = true with Proxy0 not pointing here")
	}

	inUse.Store(true)
	if !d.RebindInbound(ctx) {
		t.Fatal("RebindInbound = false, want the inbound moved to all interfaces")
	}
	wantListen(t, paths.ProductionConfig, "0.0.0.0")
	if !d.InboundOnLAN() {
		t.Error("InboundOnLAN = false after the rebind")
	}

	before := asked.Load()
	if d.RebindInbound(ctx) {
		t.Error("second RebindInbound = true, want a no-op with the inbound already on all interfaces")
	}
	if asked.Load() != before {
		t.Error("second RebindInbound regenerated the config, want xray left alone")
	}
}
