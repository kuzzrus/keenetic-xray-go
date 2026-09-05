package failover

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestMain lets `go test` re-exec the test binary itself as a stand-in
// for the xray binary Daemon supervises via xrayctl.Supervisor -- avoids
// needing a real xray-core binary in CI. Mirrors the pattern in
// internal/xrayctl's own tests. The fake doesn't need to act as a real
// proxy for the tests here: ForceSwitch/State bypass health-check probing
// entirely, and the concurrency property under test doesn't depend on
// probes succeeding.
func TestMain(m *testing.M) {
	if os.Getenv("FAILOVER_TEST_HELPER") == "1" {
		time.Sleep(time.Hour)
		return
	}
	os.Exit(m.Run())
}

// TestDaemon_Run_IdlesWithoutProfiles covers the fresh-install case: no
// primary/backup configured yet, which is always true the first time
// postinst starts the daemon via init.d, before the user has run
// `keenetic-xray setup`. Run must not error out here -- an immediate
// error made the daemon process exit almost instantly, which made
// init.d's post-start "is it still running" check report failure and
// the whole opkg installation register as failed (confirmed on real
// hardware). It must instead idle until ctx is cancelled.
func TestDaemon_Run_IdlesWithoutProfiles(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"no profiles at all", config.Default()},
		{"primary only", func() *config.Config {
			c := config.Default()
			c.Profiles = []config.Profile{{
				UUID: "u", Address: "a", Port: 443, Network: "tcp", Security: "none", Encryption: "none",
			}}
			c.PrimaryIndex = 0
			return c
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDaemon(Paths{}, tc.cfg)

			ctx, cancel := context.WithCancel(context.Background())
			runErr := make(chan error, 1)
			go func() { runErr <- d.Run(ctx) }()

			// Run must still be idling, not already returned, a short
			// moment after starting -- this is what actually caught the
			// bug: the old code returned an error near-instantly here.
			select {
			case err := <-runErr:
				t.Fatalf("Run returned early (%v) instead of idling without primary/backup configured", err)
			case <-time.After(100 * time.Millisecond):
			}

			cancel()
			select {
			case err := <-runErr:
				if err != context.Canceled {
					t.Errorf("Run returned %v after cancellation, want context.Canceled", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not return after ctx cancellation")
			}
		})
	}
}

func TestFailoverConfig_CopiesFromConfigPackage(t *testing.T) {
	src := config.FailoverConfig{
		FailuresRequired:          3,
		RecoverySuccessesRequired: 3,
		CooldownCycles:            2,
		RollbackBackoffSeconds:    300,
	}
	got := failoverConfig(src)
	want := Config{FailuresRequired: 3, RecoverySuccessesRequired: 3, CooldownCycles: 2, RollbackBackoffSeconds: 300}
	if got != want {
		t.Errorf("failoverConfig(%+v) = %+v, want %+v", src, got, want)
	}
}

// TestRealActions_ProbeLive_BoundedByCheckInterval is the regression
// test for a real incident: a router went silent for 17+ minutes with
// no recovery. One contributing cause was that Probe's own
// Retries/RetryDelay/FallbackURLs have no ceiling on their *sum* -- a
// single ProbeLive call, and so a single Tick, could run for several
// times CheckIntervalSeconds. Since Daemon.Run is one goroutine that
// also services Snapshot/ForceSwitch between ticks (and the bot-control
// agent's heartbeat reads Snapshot), a slow Tick delayed everything else
// the daemon does. ProbeLive/ProbeIsolated now wrap the whole call in a
// context.WithTimeout(ctx, probeTimeout()) -- this proves that actually
// bounds it, using a retry/fallback config that would take 30+ seconds
// if that wrap were removed.
func TestRealActions_ProbeLive_BoundedByCheckInterval(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	freeSOCKSAddr := ln.Addr().String()
	ln.Close() // freed -- guaranteed nothing answers on it

	_, portStr, _ := net.SplitHostPort(freeSOCKSAddr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parsing port %q: %v", portStr, err)
	}

	cfg := config.Default()
	cfg.Failover.CheckIntervalSeconds = 1 // the ceiling under test
	cfg.Failover.SOCKSPort = port
	cfg.Failover.HealthCheckURL = "https://example.invalid/"
	cfg.Failover.HealthCheckFallbackURLs = []string{"https://example2.invalid/", "https://example3.invalid/"}
	cfg.Failover.CheckRetries = 5
	cfg.Failover.CheckRetryDelaySeconds = 2 // retries alone: 10s+ per URL, 30s+ across all 3 if unbounded

	actions := newRealActions(Paths{}, cfg)

	start := time.Now()
	err = actions.ProbeLive(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error -- nothing is listening on the SOCKS port")
	}
	if elapsed > 5*time.Second {
		t.Errorf("ProbeLive took %v, want it bounded by ~CheckIntervalSeconds (1s), not by Retries*RetryDelay*len(URLs) (30s+)", elapsed)
	}
}

func TestDaemon_ForceSwitchAndState_NotRunning(t *testing.T) {
	cfg := config.Default()
	cfg.Profiles = []config.Profile{{UUID: "u", Address: "a", Port: 443, Network: "tcp", Security: "none", Encryption: "none"}}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0
	d := NewDaemon(Paths{}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := d.ForceSwitch(ctx, RolePrimary); err == nil {
		t.Error("expected ForceSwitch to error when Run is not active")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if _, ran := d.State(ctx2); ran {
		t.Error("expected State to report not-running when Run is not active")
	}
}

func TestDaemon_ReloadConfig_NotRunning(t *testing.T) {
	cfg := config.Default()
	d := NewDaemon(Paths{}, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if d.ReloadConfig(ctx, config.Default()) {
		t.Error("expected ReloadConfig to report not-running when Run is not active")
	}
}

// TestDaemon_ReloadConfig is the regression test for a documented, known
// gap (daemon.go's own Run doc comment): a CLI command like `keenetic-
// xray setup` runs as its own process, saves config.json, and exits --
// the *running* daemon process never notices unless it's fully
// restarted. This proves ReloadConfig actually applies a config saved
// by someone else: the daemon's shared *config.Config (same pointer the
// test's own cfg variable holds -- ReloadConfig doesn't hand back a new
// one, it mutates in place) reflects the reloaded backup profile, the
// SOCKS port realActions caches at startup gets refreshed, and -- since
// this test forces itself onto backup first -- the supervised xray-core
// process actually gets regenerated and restarted against the *new*
// backup profile, not silently left running the stale one.
func TestDaemon_ReloadConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "primary"},
		{UUID: "b1", Address: "backup1.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup1"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 60  // quiet: no automatic ticks during the test
	cfg.Failover.FailuresRequired = 1 << 30 // and never fail over on its own anyway

	prodPath := filepath.Join(dir, "production.json")
	paths := Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: prodPath,
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Force onto backup1 first, so the reload below has to actually
	// regenerate xray-production.json for the change to show up there.
	if err := d.ForceSwitch(ctx, RoleBackup); err != nil {
		t.Fatalf("ForceSwitch(backup): %v", err)
	}

	fresh := config.Default()
	fresh.Profiles = []config.Profile{
		cfg.Profiles[0],
		{UUID: "b2", Address: "backup2.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup2"},
	}
	fresh.PrimaryIndex, fresh.BackupIndex = 0, 1
	fresh.Failover = cfg.Failover
	fresh.Failover.SOCKSPort = 19191 // distinct from Default's 1080 -- proves the derived field refreshes too

	if !d.ReloadConfig(ctx, fresh) {
		t.Fatal("ReloadConfig reported the daemon not running")
	}

	if b := cfg.Backup(); b == nil || b.Remark != "backup2" {
		t.Errorf("cfg.Backup() after reload = %+v, want backup2 -- ReloadConfig mutates the shared *Config in place", b)
	}
	if got := d.actions.socks; got != "127.0.0.1:19191" {
		t.Errorf("actions.socks = %q, want it refreshed to the reloaded SOCKS port", got)
	}

	data, err := os.ReadFile(prodPath)
	if err != nil {
		t.Fatalf("reading production config: %v", err)
	}
	if !strings.Contains(string(data), "backup2.invalid") {
		t.Errorf("production config = %s, want it regenerated for the reloaded backup profile (backup2.invalid)", data)
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

func TestDaemon_Snapshot(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "primary"},
		{UUID: "b", Address: "backup.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 60  // quiet: no automatic ticks during the test
	cfg.Failover.FailuresRequired = 1 << 30 // and never fail over on its own anyway

	paths := Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Snapshot blocks on the command channel until Run's select loop is
	// live, which is after Run's initial SwitchLiveTo(primary) -- so
	// LiveRole is already primary here without an explicit wait.
	snap, ran := d.Snapshot(ctx)
	if !ran {
		t.Fatal("Snapshot: daemon reported not running")
	}
	if snap.State != StateActivePrimary {
		t.Errorf("State = %v, want ACTIVE_PRIMARY", snap.State)
	}
	if snap.LiveRole != RolePrimary {
		t.Errorf("LiveRole = %v, want primary", snap.LiveRole)
	}
	if snap.StartedAt.IsZero() {
		t.Error("StartedAt is zero")
	}

	if err := d.ForceSwitch(ctx, RoleBackup); err != nil {
		t.Fatalf("ForceSwitch(backup): %v", err)
	}
	snap, _ = d.Snapshot(ctx)
	if snap.LiveRole != RoleBackup {
		t.Errorf("after ForceSwitch(backup), LiveRole = %v, want backup", snap.LiveRole)
	}
	if len(snap.Transitions) == 0 {
		t.Fatal("no transitions recorded after a forced switch")
	}
	last := snap.Transitions[len(snap.Transitions)-1]
	if last.To != StateActiveBackup {
		t.Errorf("last transition To = %v, want ACTIVE_BACKUP", last.To)
	}
	if last.At.IsZero() {
		t.Error("transition timestamp is zero")
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

func TestDaemon_EmitsEvents(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "primary"},
		{UUID: "b", Address: "backup.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 60
	cfg.Failover.FailuresRequired = 1 << 30

	paths := Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	select {
	case ev := <-d.Events():
		if ev.Kind != EventDaemonStart {
			t.Errorf("first event Kind = %v, want EventDaemonStart", ev.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EventDaemonStart emitted")
	}

	if err := d.ForceSwitch(ctx, RoleBackup); err != nil {
		t.Fatalf("ForceSwitch(backup): %v", err)
	}
	select {
	case ev := <-d.Events():
		if ev.Kind != EventFailover || ev.To != StateActiveBackup {
			t.Errorf("event after switch = %+v, want EventFailover -> ACTIVE_BACKUP", ev)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EventFailover emitted after ForceSwitch")
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

// TestDaemon_ForceSwitchAndStateConcurrentWithRun is the actual
// concurrency-safety test: it calls ForceSwitch/State from a separate
// goroutine while Run's own tick loop is simultaneously live (fast
// ticks, so real concurrent activity happens, not just a single quiet
// moment) -- this is what `go test -race` is for. Machine's fields must
// never be touched by two goroutines at once; if a future change breaks
// that, this test is what would catch it.
//
// The failover config below is tuned so the state stays put across those
// overlapping ticks: the assertions check that a force command took
// effect, not tick timing. FailuresRequired is effectively infinite so
// tickActivePrimary never fails over on its own, and forceBackup arms
// RollbackBackoffSeconds so tickActiveBackup never starts recovery
// testing for the duration of the test.
func TestDaemon_ForceSwitchAndStateConcurrentWithRun(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "primary"},
		{UUID: "b", Address: "backup.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 1   // fast ticks so Tick() genuinely overlaps the test's own calls
	cfg.Failover.FailuresRequired = 1 << 30 // effectively never fail over automatically (see doc comment)

	paths := Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	for i := 0; i < 6; i++ {
		role, want := RolePrimary, StateActivePrimary
		if i%2 == 1 {
			role, want = RoleBackup, StateActiveBackup
		}
		if err := d.ForceSwitch(ctx, role); err != nil {
			t.Fatalf("ForceSwitch(%v): %v", role, err)
		}
		state, ran := d.State(ctx)
		if !ran {
			t.Fatal("State: daemon reported not running while Run is active")
		}
		if state != want {
			t.Errorf("after ForceSwitch(%v), State() = %v, want %v", role, state, want)
		}
		time.Sleep(50 * time.Millisecond) // let a few ticks land in between
	}

	cancel()
	select {
	case err := <-runErr:
		if err != context.Canceled {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(20 * time.Second): // generous: platforms without SIGTERM (Windows) wait out xrayctl's 5s kill grace on each Stop()
		t.Fatal("Run did not return after ctx cancellation")
	}
}
