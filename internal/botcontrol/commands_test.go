package botcontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
)

// TestMain lets `go test` re-exec the test binary itself as a stand-in
// xray process for the status/switchTo tests below, which need a real
// running failover.Daemon. Mirrors the same pattern in
// internal/failover's and internal/xrayctl's own tests.
func TestMain(m *testing.M) {
	if os.Getenv("BOTCONTROL_TEST_HELPER") == "1" {
		time.Sleep(time.Hour)
		return
	}
	os.Exit(m.Run())
}

func testProfile(remark, addr string) config.Profile {
	return config.Profile{
		Remark: remark, UUID: "u-" + remark, Address: addr, Port: 443,
		Network: "tcp", Security: "none", Encryption: "none",
	}
}

func TestRouterHandler_ProfileList(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a.example.com"), testProfile("backup", "b.example.com")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	h := &RouterHandler{Config: cfg}

	out, err := h.Handle(context.Background(), Command{Action: ActionProfileList})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !strings.Contains(out, "[primary]") || !strings.Contains(out, "[backup]") {
		t.Errorf("output missing role markers: %q", out)
	}
}

func TestRouterHandler_ProfileList_Empty(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	out, err := h.Handle(context.Background(), Command{Action: ActionSubList})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if out != "no profiles configured" {
		t.Errorf("out = %q", out)
	}
}

func TestRouterHandler_SubSetURLThenRefresh(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=tcp&security=none#alpha\n"+
			"vless://22222222-3333-4444-5555-666666666666@b.example.com:443?type=tcp&security=none#beta\n")
	}))
	defer backend.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	h := &RouterHandler{Config: cfg, ConfigPath: configPath}

	out, err := h.Handle(context.Background(), Command{Action: ActionSubSetURL, Args: []string{backend.URL}})
	if err != nil {
		t.Fatalf("sub_seturl: %v", err)
	}
	if !strings.Contains(out, "subscription URL set") {
		t.Errorf("out = %q", out)
	}

	out, err = h.Handle(context.Background(), Command{Action: ActionSubRefresh})
	if err != nil {
		t.Fatalf("sub_refresh: %v", err)
	}
	if !strings.Contains(out, "подписка: 2 профилей") {
		t.Errorf("out = %q", out)
	}

	saved, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(saved.Profiles) != 2 {
		t.Fatalf("saved Profiles = %#v, want 2 entries", saved.Profiles)
	}
}

func TestRouterHandler_ScrubsSubscriptionURLFromErrors(t *testing.T) {
	const secret = "http://127.0.0.1:1/sub/SUPERSECRETTOKEN"
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: secret}
	h := &RouterHandler{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "c.json")}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := h.Handle(ctx, Command{Action: ActionSubRefresh})
	if err == nil {
		t.Fatal("expected refresh against a dead endpoint to fail")
	}
	if strings.Contains(err.Error(), "SUPERSECRETTOKEN") || strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked the subscription URL: %v", err)
	}
	if !strings.Contains(err.Error(), "<источник-URL>") {
		t.Errorf("error should carry the redaction placeholder, got: %v", err)
	}
}

func TestRouterHandler_SubRefresh_NoURLErrors(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	if _, err := h.Handle(context.Background(), Command{Action: ActionSubRefresh}); err == nil {
		t.Error("expected error refreshing with no subscription URL set")
	}
}

func TestRouterHandler_SubSetPrimaryBackup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("a", "a.example.com"), testProfile("b", "b.example.com")}
	h := &RouterHandler{Config: cfg, ConfigPath: configPath}

	if _, err := h.Handle(context.Background(), Command{Action: ActionSubSetPrimary, Args: []string{"0"}}); err != nil {
		t.Fatalf("sub_setprimary: %v", err)
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionSubSetBackup, Args: []string{"1"}}); err != nil {
		t.Fatalf("sub_setbackup: %v", err)
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Errorf("PrimaryIndex/BackupIndex = %d/%d, want 0/1", cfg.PrimaryIndex, cfg.BackupIndex)
	}

	if _, err := h.Handle(context.Background(), Command{Action: ActionSubSetPrimary, Args: []string{"9"}}); err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestRouterHandler_UnknownAction(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	if _, err := h.Handle(context.Background(), Command{Action: "not_a_real_action"}); err == nil {
		t.Error("expected error for unknown action")
	}
}

// newTestDaemon builds a failover.Daemon backed by the re-exec'd test
// binary as a stand-in xray process (see TestMain), started via Run in a
// background goroutine. Returns the daemon and a cleanup func.
func newTestDaemon(t *testing.T) *failover.Daemon {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "primary.invalid"), testProfile("backup", "backup.invalid")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 60 // slow ticks -- this test doesn't need real health-check cycles

	paths := failover.Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"BOTCONTROL_TEST_HELPER=1"},
	}
	d := failover.NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = d.Run(ctx) }()

	// Give Run a moment to reach its select loop before returning --
	// State/ForceSwitch would otherwise just block until it does anyway,
	// but this keeps the tests below from depending on that.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ran := d.State(ctx); ran {
			return d
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready in time")
	return nil
}

func TestRouterHandler_Status(t *testing.T) {
	d := newTestDaemon(t)
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a"), testProfile("backup", "b")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	h := &RouterHandler{Daemon: d, Config: cfg}

	out, err := h.Handle(context.Background(), Command{Action: ActionStatus})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !strings.Contains(out, "ACTIVE_PRIMARY") {
		t.Errorf("status output = %q, want it to mention ACTIVE_PRIMARY", out)
	}
}

func TestRouterHandler_Status_RichFields(t *testing.T) {
	d := newTestDaemon(t)
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a"), testProfile("backup", "b")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Proxy0.Enabled = false // this test is about status rendering, not the proxy0 default
	h := &RouterHandler{Daemon: d, Config: cfg, OptPath: t.TempDir()}

	// Poll: under full-repo `go test` parallelism the re-exec'd fake-xray
	// helper is slow to schedule, so the daemon can take a beat to reach a
	// state where status() renders every field.
	waitStatus(t, h, "uptime:", "в эфире: primary", "xray:", "proxy0: выкл")

	if err := d.ForceSwitch(context.Background(), failover.RoleBackup); err != nil {
		t.Fatalf("ForceSwitch: %v", err)
	}
	waitStatus(t, h, "в эфире: backup", "последнее переключение:")
}

// waitStatus polls ActionStatus until its output contains every wanted
// substring, or fails after a few seconds naming what's still missing.
func waitStatus(t *testing.T, h *RouterHandler, want ...string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	var out string
	for time.Now().Before(deadline) {
		o, err := h.Handle(context.Background(), Command{Action: ActionStatus})
		if err != nil {
			t.Fatalf("Handle(status): %v", err)
		}
		out = o
		missing := false
		for _, w := range want {
			if !strings.Contains(out, w) {
				missing = true
				break
			}
		}
		if !missing {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("status output still missing %q:\n%s", w, out)
		}
	}
}

func TestRouterHandler_Status_TransportLines(t *testing.T) {
	d := newTestDaemon(t)
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a"), testProfile("backup", "b")}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.Proxy0.Enabled = true
	cfg.Proxy0.Protocol = "http"
	cfg.WGTransport = config.WGTransportConfig{Enabled: true, Iface: "Wireguard4"}
	h := &RouterHandler{Daemon: d, Config: cfg, OptPath: t.TempDir()}

	out, err := h.Handle(context.Background(), Command{Action: ActionStatus})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(socks5)", "(http)", // both inbounds named
		"proxy0: вкл → Proxy0/http",      // protocol is now explicit
		"wg-транспорт: вкл → Wireguard4", // second transport shown
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
}

func TestRouterHandler_Doctor(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a.example.com"), testProfile("backup", "b.example.com")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	h := &RouterHandler{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "c.json"), OptPath: t.TempDir()}

	out, err := h.Handle(context.Background(), Command{Action: ActionDoctor})
	if err != nil {
		t.Fatalf("Handle(doctor): %v", err)
	}
	if !strings.Contains(out, "выбран primary") || !strings.Contains(out, "✅") {
		t.Errorf("doctor output missing pass lines:\n%s", out)
	}
	if !strings.Contains(out, "проблем:") && !strings.Contains(out, "пройдены") {
		t.Errorf("doctor output missing a trailing summary:\n%s", out)
	}
}

func TestRouterHandler_Proxy0_WithoutNdmc(t *testing.T) {
	// CI / dev machines have no ndmc: show is informational, on/off error.
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}

	out, err := h.Handle(context.Background(), Command{Action: ActionProxy0Show})
	if err != nil {
		t.Fatalf("proxy0_show: %v", err)
	}
	if !strings.Contains(out, "proxy0:") {
		t.Errorf("proxy0_show output = %q", out)
	}

	if _, err := h.Handle(context.Background(), Command{Action: ActionProxy0On}); err == nil {
		t.Error("proxy0_on should error without ndmc")
	}
}

func TestRouterHandler_Proxy0Config(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	cfg := config.Default()
	cfg.Proxy0.Enabled = false // disabled -> the change is only saved, no ndmc needed
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	// Protocol only; interface slot left as "keep".
	out, err := h.Handle(context.Background(), Command{Action: ActionProxy0Config, Args: []string{"http", ""}})
	if err != nil {
		t.Fatalf("proxy0_config http: %v", err)
	}
	if !strings.Contains(out, "http") || !strings.Contains(out, "сохранено") {
		t.Errorf("out = %q, want it to confirm http and that it was saved", out)
	}

	// Interface only; protocol kept from the previous call.
	if _, err := h.Handle(context.Background(), Command{Action: ActionProxy0Config, Args: []string{"", "Proxy2"}}); err != nil {
		t.Fatalf("proxy0_config Proxy2: %v", err)
	}
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Proxy0.Protocol != "http" || saved.Proxy0.Interface != "Proxy2" {
		t.Errorf("saved proxy0 = %+v, want protocol http / interface Proxy2", saved.Proxy0)
	}

	// Validation: bad protocol, bad interface, and nothing-to-do.
	for _, args := range [][]string{{"ftp", ""}, {"", "eth0"}, {"", ""}} {
		if _, err := h.Handle(context.Background(), Command{Action: ActionProxy0Config, Args: args}); err == nil {
			t.Errorf("args %v: expected an error", args)
		}
	}
}

func TestRouterHandler_SetMSS(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	cfg := config.Default()
	cfg.Proxy0.Enabled = false // disabled -> only persisted, no iptables needed
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	out, err := h.Handle(context.Background(), Command{Action: ActionSetMSS, Args: []string{"1400"}})
	if err != nil {
		t.Fatalf("set_mss 1400: %v", err)
	}
	if !strings.Contains(out, "1400") || !strings.Contains(out, "применится при включении") {
		t.Errorf("out = %q", out)
	}
	if saved, _ := config.Load(cfgPath); saved.Proxy0.MSSClamp != 1400 {
		t.Errorf("saved MSSClamp = %d, want 1400", saved.Proxy0.MSSClamp)
	}

	if _, err := h.Handle(context.Background(), Command{Action: ActionSetMSS, Args: []string{"off"}}); err != nil {
		t.Fatalf("set_mss off: %v", err)
	}
	if saved, _ := config.Load(cfgPath); saved.Proxy0.MSSClamp != -1 {
		t.Errorf("saved MSSClamp = %d, want -1", saved.Proxy0.MSSClamp)
	}

	for _, bad := range [][]string{{"9000"}, {"abc"}, {}} {
		if _, err := h.Handle(context.Background(), Command{Action: ActionSetMSS, Args: bad}); err == nil {
			t.Errorf("args %v: expected an error", bad)
		}
	}
}

func TestRouterHandler_WGTransport_WithoutNdmc(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}

	// show is informational and never fails.
	out, err := h.Handle(context.Background(), Command{Action: ActionWGTransportShow})
	if err != nil {
		t.Fatalf("wg_show: %v", err)
	}
	if !strings.Contains(out, "WG-транспорт") {
		t.Errorf("wg_show output = %q", out)
	}

	// on requires ndmc; off just flips the flag + saves.
	if _, err := h.Handle(context.Background(), Command{Action: ActionWGTransportOn}); err == nil {
		t.Error("wg_on should error without ndmc")
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionWGTransportOff}); err != nil {
		t.Fatalf("wg_off: %v", err)
	}
	if saved, _ := config.Load(h.ConfigPath); saved.WGTransport.Enabled {
		t.Error("wg_off left WGTransport.Enabled true")
	}
}

func TestRouterHandler_UpdateCore(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.json")
	xrayBin := filepath.Join(dir, "xray")

	var gotOpts xraycore.Options
	h := &RouterHandler{
		Config:     config.Default(),
		ConfigPath: cfgPath,
		XrayBinary: xrayBin,
		ensureCoreFn: func(_ context.Context, o xraycore.Options) (string, error) {
			gotOpts = o
			if err := os.WriteFile(o.Dest, []byte("core-"+o.Tag), 0o755); err != nil {
				return "", err
			}
			return "vendored", nil
		},
	}

	// Switch onto a specific tag -> fetched with Force, and the pin persists.
	out, err := h.Handle(context.Background(), Command{Action: ActionUpdateCore, Args: []string{"v26.7.28"}})
	if err != nil {
		t.Fatalf("update_core v26.7.28: %v", err)
	}
	if !strings.Contains(out, "v26.7.28") {
		t.Errorf("out = %q, want it to name the new pin", out)
	}
	if gotOpts.Tag != "v26.7.28" || !gotOpts.Force || gotOpts.Prefer != "vendored" {
		t.Errorf("Ensure opts = %+v, want Tag=v26.7.28 Force=true Prefer=vendored", gotOpts)
	}
	if saved, _ := config.Load(cfgPath); saved.XrayCoreTag != "v26.7.28" {
		t.Errorf("saved XrayCoreTag = %q, want v26.7.28", saved.XrayCoreTag)
	}

	// "stable" clears the pin back to the default.
	if _, err := h.Handle(context.Background(), Command{Action: ActionUpdateCore, Args: []string{"stable"}}); err != nil {
		t.Fatalf("update_core stable: %v", err)
	}
	if gotOpts.Tag != "" {
		t.Errorf("Ensure Tag = %q, want empty for stable", gotOpts.Tag)
	}
	if saved, _ := config.Load(cfgPath); saved.XrayCoreTag != "" {
		t.Errorf("saved XrayCoreTag = %q, want empty after stable", saved.XrayCoreTag)
	}

	// A junk tag errors, never calls Ensure, and leaves the pin as-is.
	h.Config.XrayCoreTag = "v26.7.28"
	gotOpts = xraycore.Options{}
	if _, err := h.Handle(context.Background(), Command{Action: ActionUpdateCore, Args: []string{"nightly"}}); err == nil {
		t.Error("update_core nightly: expected an error for a malformed tag")
	}
	if gotOpts.Dest != "" {
		t.Error("Ensure was called despite a malformed tag")
	}
	if h.Config.XrayCoreTag != "v26.7.28" {
		t.Errorf("XrayCoreTag = %q, want it unchanged after a rejected tag", h.Config.XrayCoreTag)
	}
}

func TestRouterHandler_UpdateCore_DownloadFailureKeepsPin(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	cfg := config.Default()
	cfg.XrayCoreTag = "v1.0.0"
	h := &RouterHandler{
		Config:     cfg,
		ConfigPath: cfgPath,
		XrayBinary: filepath.Join(t.TempDir(), "xray"),
		ensureCoreFn: func(context.Context, xraycore.Options) (string, error) {
			return "", fmt.Errorf("asset not published yet")
		},
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionUpdateCore, Args: []string{"v2.0.0"}}); err == nil {
		t.Fatal("expected an error when the core can't be fetched")
	}
	if h.Config.XrayCoreTag != "v1.0.0" {
		t.Errorf("XrayCoreTag = %q, want the switch NOT recorded after a failed download", h.Config.XrayCoreTag)
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("config.json was written despite the failed switch")
	}
}

func TestProbeSummary(t *testing.T) {
	now := time.Date(2026, 9, 6, 21, 45, 0, 0, time.UTC)
	if probeSummary(nil, now) != "" {
		t.Error("empty history should render nothing")
	}

	probes := []failover.ProbeResult{
		{At: now.Add(-3 * time.Minute), Live: true, OK: true, Latency: 150 * time.Millisecond},
		{At: now.Add(-2 * time.Minute), Live: true, OK: false, Reason: "таймаут"},
		{At: now.Add(-90 * time.Second), Live: true, OK: true, Latency: 450 * time.Millisecond},
		{At: now.Add(-60 * time.Second), Live: true, OK: false, Reason: "таймаут"},
		{At: now.Add(-30 * time.Second), Live: true, OK: false, Reason: "HTTP 503"},
	}
	got := probeSummary(probes, now)
	for _, want := range []string{"5 посл.", "2 ✅ / 3 ❌", "таймаут ×2", "HTTP 503 ×1", "300мс средн", "450мс макс"} {
		if !strings.Contains(got, want) {
			t.Errorf("probeSummary missing %q in:\n%s", want, got)
		}
	}
}

func TestCountPrimaryDrops(t *testing.T) {
	now := time.Now()
	trs := []failover.Transition{
		{At: now.Add(-90 * time.Minute), From: failover.StateActivePrimary, To: failover.StateCooldown}, // too old
		{At: now.Add(-40 * time.Minute), From: failover.StateActivePrimary, To: failover.StateCooldown},
		{At: now.Add(-30 * time.Minute), From: failover.StateCooldown, To: failover.StateActivePrimary}, // not a drop
		{At: now.Add(-20 * time.Minute), From: failover.StateActivePrimary, To: failover.StateCooldown},
		{At: now.Add(-5 * time.Minute), From: failover.StateConfirmingRecovery, To: failover.StateActiveBackup}, // rollback, not a drop
	}
	if n := countPrimaryDrops(trs, now.Add(-time.Hour)); n != 2 {
		t.Errorf("countPrimaryDrops = %d, want 2 (only ActivePrimary->Cooldown within the window)", n)
	}
}

func TestRouterHandler_Routes(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	h := &RouterHandler{Config: config.Default(), ConfigPath: cfgPath}
	ctx := context.Background()

	// Create a list; one private subnet is rejected, the rest accepted.
	out, err := h.Handle(ctx, Command{Action: ActionRoutesAdd, Args: []string{
		"media", "netflix.com, youtube.com\n192.168.0.0/16 1.2.3.0/24",
	}})
	if err != nil {
		t.Fatalf("routes_add: %v", err)
	}
	if !strings.Contains(out, "+3 записей") || !strings.Contains(out, "отклонено 1") {
		t.Errorf("routes_add reply = %q", out)
	}
	saved, _ := config.Load(cfgPath)
	if len(saved.Routing.Lists) != 1 || saved.Routing.Lists[0].Name != "media" {
		t.Fatalf("saved lists = %+v", saved.Routing.Lists)
	}
	if got := strings.Join(saved.Routing.Lists[0].Entries, ","); got != "1.2.3.0/24,netflix.com,youtube.com" {
		t.Errorf("entries = %q", got)
	}

	// Add to the same list (dedupe youtube.com).
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesAdd, Args: []string{"media", "youtube.com disneyplus.com"}}); err != nil {
		t.Fatal(err)
	}
	if n := len(h.Config.Routing.Lists[0].Entries); n != 4 {
		t.Errorf("after re-add: %d entries, want 4 (disneyplus.com only)", n)
	}

	// Remove entries.
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesDel, Args: []string{"media", "netflix.com"}}); err != nil {
		t.Fatal(err)
	}
	if slicesContains(h.Config.Routing.Lists[0].Entries, "netflix.com") {
		t.Error("netflix.com should be gone")
	}

	// Toggle off / on.
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesToggle, Args: []string{"media", "off"}}); err != nil {
		t.Fatal(err)
	}
	if !h.Config.Routing.Lists[0].Disabled {
		t.Error("list should be Disabled after off")
	}

	// Point the list at a WireGuard interface.
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesSetIface, Args: []string{"media", "Wireguard4"}}); err != nil {
		t.Fatalf("routes_setiface: %v", err)
	}
	if h.Config.Routing.Lists[0].Interface != "Wireguard4" {
		t.Errorf("interface = %q, want Wireguard4", h.Config.Routing.Lists[0].Interface)
	}
	for _, bad := range [][]string{{"media", "wg0"}, {"media", ""}, {"nope", "Proxy0"}} {
		if _, err := h.Handle(ctx, Command{Action: ActionRoutesSetIface, Args: bad}); err == nil {
			t.Errorf("routes_setiface %v: expected an error", bad)
		}
	}

	// List text.
	txt, _ := h.Handle(ctx, Command{Action: ActionRoutesList})
	if !strings.Contains(txt, "📁 media") || !strings.Contains(txt, "⛔") {
		t.Errorf("routes_list = %q", txt)
	}

	// Remove the whole list.
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesRemoveList, Args: []string{"media"}}); err != nil {
		t.Fatal(err)
	}
	if len(h.Config.Routing.Lists) != 0 {
		t.Errorf("list not removed: %+v", h.Config.Routing.Lists)
	}

	// Bad name / missing list errors.
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesAdd, Args: []string{"", "a.io"}}); err == nil {
		t.Error("empty list name should error")
	}
	if _, err := h.Handle(ctx, Command{Action: ActionRoutesDel, Args: []string{"nope", "a.io"}}); err == nil {
		t.Error("del on a missing list should error")
	}
}

func slicesContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestRouterHandler_DaemonRestart(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}

	if _, err := h.Handle(context.Background(), Command{Action: ActionDaemonRestart}); err == nil {
		t.Error("daemon_restart with no InitScript should error")
	}

	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH to exercise the restart spawn")
	}
	h.InitScript = "/bin/true"
	out, err := h.Handle(context.Background(), Command{Action: ActionDaemonRestart})
	if err != nil {
		t.Fatalf("daemon_restart: %v", err)
	}
	if !strings.Contains(out, "перезапуск") {
		t.Errorf("daemon_restart output = %q", out)
	}
}

func TestRouterHandler_SetSlotSource(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	// A vless:// link -> primary slot.
	out, err := h.Handle(context.Background(), Command{
		Action: ActionSetPrimarySource,
		Args:   []string{"vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=tcp&security=none#RU-1"},
	})
	if err != nil {
		t.Fatalf("set_primary_source (vless): %v", err)
	}
	if !strings.Contains(out, "primary ← RU-1") {
		t.Errorf("out = %q", out)
	}
	if len(cfg.Profiles) != 1 || cfg.PrimaryIndex != 0 || cfg.PrimarySource == nil {
		t.Fatalf("after primary: profiles=%d primaryIdx=%d src=%v", len(cfg.Profiles), cfg.PrimaryIndex, cfg.PrimarySource)
	}

	// A 2-profile subscription with a selector -> backup slot, distinct profile.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "vless://22222222-3333-4444-5555-666666666666@b.example.com:443?type=tcp&security=none#NL-1\n"+
			"vless://33333333-4444-5555-6666-777777777777@c.example.com:443?type=tcp&security=none#DE-1\n")
	}))
	defer backend.Close()

	out, err = h.Handle(context.Background(), Command{
		Action: ActionSetBackupSource,
		Args:   []string{backend.URL, "DE"},
	})
	if err != nil {
		t.Fatalf("set_backup_source (sub): %v", err)
	}
	if !strings.Contains(out, "backup ← DE-1") {
		t.Errorf("out = %q", out)
	}
	if len(cfg.Profiles) != 2 || cfg.BackupIndex != 1 {
		t.Fatalf("after backup: profiles=%d backupIdx=%d", len(cfg.Profiles), cfg.BackupIndex)
	}
	if cfg.PrimaryIndex == cfg.BackupIndex {
		t.Error("primary and backup ended up the same slot")
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.BackupSource == nil || saved.BackupSource.Selector != "DE" {
		t.Errorf("saved BackupSource = %+v", saved.BackupSource)
	}
}

// TestRouterHandler_SubRefresh_RefetchesSlotSources is the regression
// test for a live incident: a slot fed by its own PrimarySource/
// BackupSource is deliberately left alone by a shared-subscription
// refresh, but there was no other way to re-fetch it -- so a provider's
// node changes (and the xhttp_extra parsing added in v0.12.0) never
// landed without re-pasting the URL by hand. sub_refresh now re-resolves
// each independent slot source too.
func TestRouterHandler_SubRefresh_RefetchesSlotSources(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// The source starts serving a link WITHOUT the xhttp extra blob...
	extra := ""
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "vless://11111111-2222-3333-4444-555555555555@a.example:443?type=xhttp&security=none&mode=auto%s#RU-1\n", extra)
	}))
	defer backend.Close()

	cfg := config.Default()
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}
	if _, err := h.Handle(context.Background(), Command{Action: ActionSetPrimarySource, Args: []string{backend.URL}}); err != nil {
		t.Fatalf("set_primary_source: %v", err)
	}
	if len(cfg.Profiles[0].XHTTPExtra) != 0 {
		t.Fatal("precondition: profile should have no extra yet")
	}

	// ...then the provider adds it. A refresh must pick it up.
	extra = "&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D"
	out, err := h.Handle(context.Background(), Command{Action: ActionSubRefresh})
	if err != nil {
		t.Fatalf("sub_refresh: %v", err)
	}
	if !strings.Contains(out, "источник (основной) ← RU-1") {
		t.Errorf("out = %q", out)
	}
	if len(cfg.Profiles) != 1 || len(cfg.Profiles[0].XHTTPExtra) == 0 {
		t.Errorf("slot source not re-fetched: profiles=%d extra=%q", len(cfg.Profiles), cfg.Profiles[0].XHTTPExtra)
	}
	if cfg.PrimaryIndex != 0 {
		t.Errorf("PrimaryIndex = %d, want 0", cfg.PrimaryIndex)
	}
}

// TestRouterHandler_SetSlotSource_NeverMirrorsIntoEmptyOtherSlot is the
// regression test for a live incident: primary had gone unset (an
// unrelated subscription refresh couldn't re-match it), and setting
// backup's source afterward silently mirrored that same profile into
// primary too -- "so the daemon can run" -- leaving primary and backup
// on the identical profile with no real redundancy, discovered only
// later via the bot's own "primary и backup — один профиль" warning.
// Setting one slot must only ever warn about an empty other slot, never
// fill it in. Covers both directions.
func TestRouterHandler_SetSlotSource_NeverMirrorsIntoEmptyOtherSlot(t *testing.T) {
	t.Run("primary set while backup empty", func(t *testing.T) {
		cfg := config.Default() // PrimaryIndex/BackupIndex both -1
		h := &RouterHandler{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "config.json")}

		out, err := h.Handle(context.Background(), Command{
			Action: ActionSetPrimarySource,
			Args:   []string{"vless://11111111-2222-3333-4444-555555555555@a.example:443?type=tcp&security=none#RU-1"},
		})
		if err != nil {
			t.Fatalf("set_primary_source: %v", err)
		}
		if cfg.PrimaryIndex != 0 {
			t.Errorf("PrimaryIndex = %d, want 0", cfg.PrimaryIndex)
		}
		if cfg.BackupIndex != -1 {
			t.Errorf("BackupIndex = %d, want -1 (setting primary must never fill in backup)", cfg.BackupIndex)
		}
		if !strings.Contains(out, "backup не задан") {
			t.Errorf("out = %q, want a note that backup still needs its own source", out)
		}
	})

	t.Run("backup set while primary empty", func(t *testing.T) {
		cfg := config.Default() // PrimaryIndex/BackupIndex both -1
		h := &RouterHandler{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "config.json")}

		out, err := h.Handle(context.Background(), Command{
			Action: ActionSetBackupSource,
			Args:   []string{"vless://11111111-2222-3333-4444-555555555555@a.example:443?type=tcp&security=none#RU-1"},
		})
		if err != nil {
			t.Fatalf("set_backup_source: %v", err)
		}
		if cfg.BackupIndex != 0 {
			t.Errorf("BackupIndex = %d, want 0", cfg.BackupIndex)
		}
		if cfg.PrimaryIndex != -1 {
			t.Errorf("PrimaryIndex = %d, want -1 (setting backup must never fill in primary)", cfg.PrimaryIndex)
		}
		if !strings.Contains(out, "primary не задан") {
			t.Errorf("out = %q, want a note that primary still needs its own source", out)
		}
	})
}

func TestRouterHandler_RebindRestartsIdleDaemon(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH")
	}
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("p", "a"), testProfile("b", "b")}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	// A daemon that was never Run(): Snapshot reports not-running, so
	// rebindXray takes the idle-restart branch.
	d := failover.NewDaemon(failover.Paths{}, cfg)
	h := &RouterHandler{Daemon: d, Config: cfg, InitScript: "/bin/true"}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	h.rebindXray(ctx) // must return promptly (spawns detached restart), not hang
}

func TestRouterHandler_ScrubsSlotSourceURLs(t *testing.T) {
	cfg := config.Default()
	cfg.PrimarySource = &config.SlotSource{URL: "https://p.example/sub/PRIMTOKEN"}
	cfg.BackupSource = &config.SlotSource{URL: "https://b.example/sub/BAKTOKEN"}
	h := &RouterHandler{Config: cfg}

	got := h.scrubSecrets("primary from https://p.example/sub/PRIMTOKEN and backup from https://b.example/sub/BAKTOKEN")
	if strings.Contains(got, "PRIMTOKEN") || strings.Contains(got, "BAKTOKEN") {
		t.Errorf("slot source URLs leaked: %q", got)
	}
}

func TestRouterHandler_FailoverShow(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	out, err := h.Handle(context.Background(), Command{Action: ActionFailoverShow})
	if err != nil {
		t.Fatalf("failover_show: %v", err)
	}
	if !strings.Contains(out, "failures_required: 3") {
		t.Errorf("out = %q", out)
	}
}

func TestRouterHandler_FailoverSet(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	if _, err := exec.LookPath("sh"); err == nil {
		h.InitScript = "/bin/true"
	}

	out, err := h.Handle(context.Background(), Command{
		Action: ActionFailoverSet,
		Args:   []string{"failures_required", "6"},
	})
	if err != nil {
		t.Fatalf("failover_set: %v", err)
	}
	if !strings.Contains(out, "failures_required = 6") {
		t.Errorf("out = %q", out)
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.Failover.FailuresRequired != 6 {
		t.Errorf("saved FailuresRequired = %d, want 6", saved.Failover.FailuresRequired)
	}
}

func TestRouterHandler_FailoverSet_RejectsBadValue(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
	if _, err := h.Handle(context.Background(), Command{
		Action: ActionFailoverSet,
		Args:   []string{"failures_required", "0"},
	}); err == nil {
		t.Error("expected an error for a non-positive failures_required")
	}
}

func TestRouterHandler_WatchdogShow_NotConfigured(t *testing.T) {
	h := &RouterHandler{Config: config.Default()} // CronFile empty
	if _, err := h.Handle(context.Background(), Command{Action: ActionWatchdogShow}); err == nil {
		t.Error("expected an error when CronFile isn't wired for this agent")
	}
}

func TestRouterHandler_WatchdogShow(t *testing.T) {
	h := &RouterHandler{
		Config:     config.Default(),
		CronFile:   filepath.Join(t.TempDir(), "cron", "root"),
		InitScript: "/opt/etc/init.d/S99keenetic-xray",
	}
	out, err := h.Handle(context.Background(), Command{Action: ActionWatchdogShow})
	if err != nil {
		t.Fatalf("watchdog_show: %v", err)
	}
	if !strings.Contains(out, "вотчдог: false") {
		t.Errorf("out = %q, want it to report the entry as not yet present", out)
	}
	if !strings.Contains(out, "cron:") {
		t.Errorf("out = %q, want it to also report cron daemon status", out)
	}
}

// TestRouterHandler_WatchdogEnable_FailsCleanlyWithoutRealCron mirrors
// the CLI-level test: this test environment has no real Entware cron or
// opkg, so EnsureCron cannot succeed, and enable must fail rather than
// pretend it worked -- critically, without writing the cron entry
// first, since a written-but-inert entry is exactly the silent-failure
// mode this feature exists to avoid.
func TestRouterHandler_WatchdogEnable_FailsCleanlyWithoutRealCron(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "cron", "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")
	h := &RouterHandler{
		Config:         config.Default(),
		CronFile:       cronFile,
		WatchdogScript: scriptPath,
		InitScript:     "/opt/etc/init.d/S99keenetic-xray",
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionWatchdogEnable}); err == nil {
		t.Fatal("expected an error: no real cron/opkg is available in this environment")
	}
	if _, err := os.Stat(cronFile); !os.IsNotExist(err) {
		t.Errorf("cron file should not have been written when EnsureCron failed first, stat err = %v", err)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Errorf("script should not have been written when EnsureCron failed first, stat err = %v", err)
	}
}

func TestRouterHandler_WatchdogDisable(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "cron", "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")
	if err := os.MkdirAll(filepath.Dir(cronFile), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := "0 3 * * * /opt/bin/some-other-job # unrelated-marker\n" +
		"*/2 * * * * " + scriptPath + " # keenetic-xray-watchdog\n"
	if err := os.WriteFile(cronFile, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &RouterHandler{
		Config:         config.Default(),
		CronFile:       cronFile,
		WatchdogScript: scriptPath,
		InitScript:     "/opt/etc/init.d/S99keenetic-xray",
	}

	out, err := h.Handle(context.Background(), Command{Action: ActionWatchdogDisable})
	if err != nil {
		t.Fatalf("watchdog_disable: %v", err)
	}
	if !strings.Contains(out, "выключен") {
		t.Errorf("out = %q", out)
	}
	data, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "keenetic-xray-watchdog") {
		t.Errorf("cron file = %q, want the watchdog entry gone", data)
	}
	if !strings.Contains(string(data), "unrelated-marker") {
		t.Errorf("cron file = %q, want the unrelated entry preserved", data)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Errorf("script should be removed on disable, stat err = %v", err)
	}
}

func TestRouterHandler_WatchdogLog_EmptyWhenNoFile(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), WatchdogLog: filepath.Join(t.TempDir(), "watchdog.log")}
	out, err := h.Handle(context.Background(), Command{Action: ActionWatchdogLog})
	if err != nil {
		t.Fatalf("watchdog_log: %v", err)
	}
	if out != "перезапусков не зафиксировано" {
		t.Errorf("out = %q, want the no-restarts message for a missing file", out)
	}
}

func TestRouterHandler_WatchdogLog_ReturnsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdog.log")
	if err := os.WriteFile(path, []byte("2026-09-05 09:04:00 restarting -- status check failed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &RouterHandler{Config: config.Default(), WatchdogLog: path}
	out, err := h.Handle(context.Background(), Command{Action: ActionWatchdogLog})
	if err != nil {
		t.Fatalf("watchdog_log: %v", err)
	}
	if !strings.Contains(out, "2026-09-05 09:04:00") {
		t.Errorf("out = %q, want the seeded line", out)
	}
}

func TestRouterHandler_DaemonLog(t *testing.T) {
	// Not configured -> error.
	h0 := &RouterHandler{Config: config.Default()}
	if _, err := h0.Handle(context.Background(), Command{Action: ActionDaemonLog}); err == nil {
		t.Error("daemon_log without DaemonLog set should error")
	}

	// Missing file -> "лог пуст".
	path := filepath.Join(t.TempDir(), "daemon.log")
	h := &RouterHandler{Config: config.Default(), DaemonLog: path}
	if out, err := h.Handle(context.Background(), Command{Action: ActionDaemonLog}); err != nil || out != "лог пуст" {
		t.Errorf("missing file: out=%q err=%v", out, err)
	}

	// Tail respects the line-count arg.
	var buf strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&buf, "line %d\n", i)
	}
	if err := os.WriteFile(path, []byte(buf.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := h.Handle(context.Background(), Command{Action: ActionDaemonLog, Args: []string{"3"}})
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(out, "\n"); len(lines) != 3 || lines[2] != "line 49" {
		t.Errorf("daemon_log 3 = %q", out)
	}
}

func TestRouterHandler_SetPorts(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := config.Default()
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	out, err := h.Handle(context.Background(), Command{Action: ActionSetPorts, Args: []string{"1090", "1091"}})
	if err != nil {
		t.Fatalf("set_ports: %v", err)
	}
	if !strings.Contains(out, "SOCKS: 1090") || !strings.Contains(out, "HTTP: 1091") {
		t.Errorf("out = %q", out)
	}
	if cfg.Failover.SOCKSPort != 1090 || cfg.Failover.HTTPPort != 1091 {
		t.Errorf("SOCKSPort/HTTPPort = %d/%d, want 1090/1091", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	}

	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if saved.Failover.SOCKSPort != 1090 || saved.Failover.HTTPPort != 1091 {
		t.Errorf("saved SOCKSPort/HTTPPort = %d/%d, want 1090/1091", saved.Failover.SOCKSPort, saved.Failover.HTTPPort)
	}
}

func TestRouterHandler_SetPorts_RejectsSamePort(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
	if _, err := h.Handle(context.Background(), Command{Action: ActionSetPorts, Args: []string{"1090", "1090"}}); err == nil {
		t.Error("expected an error when SOCKS and HTTP ports are the same")
	}
}

func TestRouterHandler_SetPorts_RejectsOutOfRange(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
	cases := [][2]string{{"0", "1091"}, {"70000", "1091"}, {"abc", "1091"}}
	for _, c := range cases {
		if _, err := h.Handle(context.Background(), Command{Action: ActionSetPorts, Args: []string{c[0], c[1]}}); err == nil {
			t.Errorf("socks=%q: expected an error", c[0])
		}
	}
}

func TestRouterHandler_SetPorts_RejectsWrongArgCount(t *testing.T) {
	h := &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
	if _, err := h.Handle(context.Background(), Command{Action: ActionSetPorts, Args: []string{"1090"}}); err == nil {
		t.Error("expected an error for a single argument")
	}
}

func TestRouterHandler_SelfUpdate(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH to exercise the update spawn")
	}
	// SelfUpdateMarker set: the marker write is best-effort (needs opkg to
	// detect the arch) and must never block the update -- the base
	// message is always returned, with at most a parenthetical note.
	h := &RouterHandler{
		Config:           config.Default(),
		InstallURL:       "file:///dev/null",
		SelfUpdateMarker: filepath.Join(t.TempDir(), "self-update.json"),
	}
	out, err := h.Handle(context.Background(), Command{Action: ActionSelfUpdate})
	if err != nil {
		t.Fatalf("self_update: %v", err)
	}
	if !strings.HasPrefix(out, "обновление агента запущено") {
		t.Errorf("self_update output = %q", out)
	}
}

func TestRouterHandler_SwitchTo(t *testing.T) {
	d := newTestDaemon(t)
	h := &RouterHandler{Daemon: d, Config: config.Default()}

	out, err := h.Handle(context.Background(), Command{Action: ActionSwitchBackup})
	if err != nil {
		t.Fatalf("Handle(switch_backup): %v", err)
	}
	if !strings.Contains(out, "backup") {
		t.Errorf("out = %q, want it to mention backup", out)
	}

	state, ran := d.State(context.Background())
	if !ran || state != failover.StateActiveBackup {
		t.Errorf("state = %v (ran=%v), want StateActiveBackup", state, ran)
	}
}

func TestRouterHandler_Diag(t *testing.T) {
	origExe, origRun := selfExe, runSelf
	selfExe = func() (string, error) { return "/opt/sbin/keenetic-xray", nil }
	runSelf = func(_ context.Context, exe string, args ...string) ([]byte, error) {
		if exe != "/opt/sbin/keenetic-xray" || len(args) != 1 || args[0] != "diag" {
			t.Fatalf("runSelf called with %q %v", exe, args)
		}
		return []byte("==== keenetic-xray diag ====\nagent: test\n==== end ===="), nil
	}
	t.Cleanup(func() { selfExe, runSelf = origExe, origRun })

	h := &RouterHandler{Config: config.Default()}
	out, err := h.Handle(context.Background(), Command{Action: ActionDiag})
	if err != nil {
		t.Fatalf("diag: %v", err)
	}
	if !strings.Contains(out, "keenetic-xray diag") || !strings.Contains(out, "end") {
		t.Errorf("diag passthrough = %q", out)
	}
}
