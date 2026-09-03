package botcontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	if !strings.Contains(err.Error(), "<подписка-URL>") {
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
