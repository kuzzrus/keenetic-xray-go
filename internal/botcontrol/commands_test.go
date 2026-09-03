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
	if !strings.Contains(out, "refreshed: 2 profiles") {
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

	out, err := h.Handle(context.Background(), Command{Action: ActionStatus})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	for _, want := range []string{"uptime:", "в эфире: primary", "xray:", "proxy0: выкл"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}

	if err := d.ForceSwitch(context.Background(), failover.RoleBackup); err != nil {
		t.Fatalf("ForceSwitch: %v", err)
	}
	out, err = h.Handle(context.Background(), Command{Action: ActionStatus})
	if err != nil {
		t.Fatalf("Handle after switch: %v", err)
	}
	if !strings.Contains(out, "в эфире: backup") {
		t.Errorf("after switch, status should show backup live:\n%s", out)
	}
	if !strings.Contains(out, "последнее переключение:") {
		t.Errorf("after switch, status should show the last transition:\n%s", out)
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

func TestPickProfile(t *testing.T) {
	ps := []config.Profile{
		{Remark: "🇷🇺 RU-1"}, {Remark: "🇳🇱 NL-1"}, {Remark: "🇩🇪 DE-1"},
	}
	cases := []struct {
		sel     string
		want    string
		wantErr bool
	}{
		{"", "🇷🇺 RU-1", false},
		{"first", "🇷🇺 RU-1", false},
		{"1", "🇳🇱 NL-1", false},
		{"9", "", true},
		{"nl", "🇳🇱 NL-1", false},
		{"de-1", "🇩🇪 DE-1", false},
		{"xx", "", true},
		{"1", "🇳🇱 NL-1", false},
	}
	for _, c := range cases {
		got, err := pickProfile(ps, c.sel)
		if c.wantErr {
			if err == nil {
				t.Errorf("pickProfile(%q): want error", c.sel)
			}
			continue
		}
		if err != nil || got.Remark != c.want {
			t.Errorf("pickProfile(%q) = %q, %v; want %q", c.sel, got.Remark, err, c.want)
		}
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

func TestRouterHandler_SetSlotSource_MirrorsEmptyOtherSlot(t *testing.T) {
	cfg := config.Default() // PrimaryIndex/BackupIndex both -1
	h := &RouterHandler{Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "config.json")}

	out, err := h.Handle(context.Background(), Command{
		Action: ActionSetPrimarySource,
		Args:   []string{"vless://11111111-2222-3333-4444-555555555555@a.example:443?type=tcp&security=none#RU-1"},
	})
	if err != nil {
		t.Fatalf("set_primary_source: %v", err)
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 0 {
		t.Errorf("indices = %d/%d, want 0/0 (backup mirrored so the daemon can run)", cfg.PrimaryIndex, cfg.BackupIndex)
	}
	if !strings.Contains(out, "backup тоже") {
		t.Errorf("out = %q, want a note that backup was mirrored", out)
	}
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

func TestRouterHandler_SelfUpdate(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH to exercise the update spawn")
	}
	h := &RouterHandler{Config: config.Default(), InstallURL: "file:///dev/null"}
	out, err := h.Handle(context.Background(), Command{Action: ActionSelfUpdate})
	if err != nil {
		t.Fatalf("self_update: %v", err)
	}
	if !strings.Contains(out, "обновление агента запущено") {
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
