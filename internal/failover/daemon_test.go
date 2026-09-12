package failover

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// naiveProfile is a minimal valid naive profile for the sidecar-lifecycle
// tests below. The FAILOVER_TEST_HELPER fake process (see TestMain) never
// inspects argv, so it stands in for the `naive` binary exactly as it
// already does for xray-core -- no real naive binary needed in CI.
func naiveProfile(remark string) config.Profile {
	return config.Profile{
		Protocol: "naive",
		Remark:   remark,
		Address:  "naive.invalid",
		Port:     8443,
		User:     "alice",
		Password: "s3cret",
	}
}

// waitUntil polls cond until it's true or timeout elapses. Supervisor.Start
// (internal/xrayctl) returns as soon as its supervising goroutine is
// launched, before that goroutine has necessarily reached the point of
// recording the child process -- so Running() can still read false for a
// moment right after Start() returns. Same pattern as xrayctl's own test
// helper of the same name (a plain immediate check flaked under CI's
// -race, which slows and reorders goroutine scheduling enough to make
// that window land).
func waitUntil(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v", timeout)
}

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
	d := NewDaemon(Paths{}, config.Default()) // no profiles at all

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	// Run must still be idling, not already returned, a short moment
	// after starting -- this is what actually caught the bug: the old
	// code returned an error near-instantly here.
	select {
	case err := <-runErr:
		t.Fatalf("Run returned early (%v) instead of idling without a primary configured", err)
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
}

// TestDaemon_Run_SingleProfile: a config with a primary but no distinct
// backup (BackupIndex == PrimaryIndex, the "skip backup" setup path)
// must actually start serving -- production instance up, Snapshot works,
// LiveRole primary -- and just supervise it, no failover loop.
func TestDaemon_Run_SingleProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "p", Address: "primary.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "solo"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0 // no separate backup

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

	snap, ran := d.Snapshot(ctx)
	if !ran {
		t.Fatal("Snapshot: daemon reported not running in single-profile mode")
	}
	if snap.State != StateActivePrimary || snap.LiveRole != RolePrimary {
		t.Errorf("single-profile: State=%v LiveRole=%v, want ACTIVE_PRIMARY/primary", snap.State, snap.LiveRole)
	}
	if _, err := os.Stat(paths.PretestConfig); err == nil {
		t.Error("single-profile mode should not have spun an isolated pretest")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != context.Canceled {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(20 * time.Second): // prod.Stop() on the fake xray can be slow to reap
		t.Fatal("Run did not return after cancel")
	}
}

// TestDaemon_Run_SingleNaiveProfile is TestDaemon_Run_SingleProfile's
// sibling for a naive primary: proves Run's real end-to-end wiring --
// SwitchLiveTo at startup, the shutdown defer added alongside
// d.actions.prod.Stop() -- actually starts and stops a production naive
// sidecar, not just that the lower-level realActions methods do in
// isolation.
func TestDaemon_Run_SingleNaiveProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{naiveProfile("solo")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0 // no separate backup

	paths := Paths{
		XrayBinary:       os.Args[0],
		NaiveBinary:      os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	d := NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	snap, ran := d.Snapshot(ctx)
	if !ran {
		t.Fatal("Snapshot: daemon reported not running in single-profile mode")
	}
	if snap.State != StateActivePrimary || snap.LiveRole != RolePrimary {
		t.Errorf("single-profile: State=%v LiveRole=%v, want ACTIVE_PRIMARY/primary", snap.State, snap.LiveRole)
	}
	if d.actions.prodNaive == nil {
		t.Fatal("expected a naive sidecar for the naive primary profile")
	}
	waitUntil(t, time.Second, d.actions.prodNaive.Running)

	cancel()
	select {
	case err := <-runErr:
		if err != context.Canceled {
			t.Errorf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Run did not return after cancel")
	}

	if d.actions.prodNaive != nil && d.actions.prodNaive.Running() {
		t.Error("expected the naive sidecar to be stopped once Run returned (Run's shutdown defer)")
	}
}

// TestRealActions_SwitchLiveTo_NaiveProfile_StartsSidecarAndPointsXrayAtIt
// covers the actual sidecar wiring: a naive primary starts a `naive`
// sidecar, and the generated production xray config carries a plain socks
// outbound pointed at that sidecar's local port -- not the naive server's
// own address/credentials, which must never reach xray's config at all.
func TestRealActions_SwitchLiveTo_NaiveProfile_StartsSidecarAndPointsXrayAtIt(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{naiveProfile("primary")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0

	paths := Paths{
		XrayBinary:       os.Args[0],
		NaiveBinary:      os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	a := newRealActions(paths, cfg)
	defer a.prod.Stop()
	defer a.stopProdNaive()

	if err := a.SwitchLiveTo(context.Background(), RolePrimary); err != nil {
		t.Fatalf("SwitchLiveTo: %v", err)
	}
	if a.prodNaive == nil {
		t.Fatal("expected a naive sidecar for a naive primary profile")
	}
	waitUntil(t, time.Second, a.prodNaive.Running)

	data, err := os.ReadFile(paths.ProductionConfig)
	if err != nil {
		t.Fatalf("reading production config: %v", err)
	}
	var decoded struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Servers []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Outbounds) == 0 || decoded.Outbounds[0].Protocol != "socks" {
		t.Fatalf("first outbound = %#v, want a socks outbound to the sidecar", decoded.Outbounds)
	}
	server := decoded.Outbounds[0].Settings.Servers[0]
	if server.Address != "127.0.0.1" || server.Port != a.naiveProdPort() {
		t.Errorf("outbound socks server = %s:%d, want 127.0.0.1:%d", server.Address, server.Port, a.naiveProdPort())
	}
	if strings.Contains(string(data), "naive.invalid") || strings.Contains(string(data), "s3cret") {
		t.Errorf("naive server address/credentials leaked into the xray config: %s", data)
	}
}

// TestRealActions_SwitchLiveTo_LeavingNaiveStopsSidecar covers the reverse
// direction: switching production from a naive profile to a vless one
// must stop the now-unneeded sidecar, not leak it.
func TestRealActions_SwitchLiveTo_LeavingNaiveStopsSidecar(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		naiveProfile("primary"),
		{UUID: "b", Address: "backup.invalid", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "backup"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1

	paths := Paths{
		XrayBinary:       os.Args[0],
		NaiveBinary:      os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	a := newRealActions(paths, cfg)
	defer a.prod.Stop()
	defer a.stopProdNaive()

	if err := a.SwitchLiveTo(context.Background(), RolePrimary); err != nil {
		t.Fatalf("SwitchLiveTo(primary): %v", err)
	}
	sidecar := a.prodNaive
	if sidecar == nil {
		t.Fatal("expected a naive sidecar after switching to the naive primary")
	}

	if err := a.SwitchLiveTo(context.Background(), RoleBackup); err != nil {
		t.Fatalf("SwitchLiveTo(backup): %v", err)
	}
	if a.prodNaive != nil {
		t.Error("expected prodNaive to be cleared after switching to a vless profile")
	}
	if sidecar.Running() {
		t.Error("expected the old naive sidecar to be stopped after switching to a vless profile")
	}
}

// TestRealActions_SwitchLiveTo_NaiveProfile_MissingBinaryErrors: an unset
// NaiveBinary must fail clearly before touching the production xray
// process at all -- not fall through to writing a config with no working
// egress and restarting xray onto it.
func TestRealActions_SwitchLiveTo_NaiveProfile_MissingBinaryErrors(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{naiveProfile("primary")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 0

	paths := Paths{
		XrayBinary:       os.Args[0],
		NaiveBinary:      "", // deliberately unset
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"FAILOVER_TEST_HELPER=1"},
	}
	a := newRealActions(paths, cfg)

	err := a.SwitchLiveTo(context.Background(), RolePrimary)
	if err == nil {
		t.Fatal("expected an error when NaiveBinary isn't configured")
	}
	if !strings.Contains(err.Error(), "naive") {
		t.Errorf("error = %q, want it to mention naive", err.Error())
	}
	if a.prod.Running() {
		t.Error("production xray should not have been started after a failed naive sidecar start")
	}
}

// TestRealActions_StartIsolatedPretest_NaiveProfile covers the pretest
// (recovery-testing) side: a naive primary gets its own sidecar on the
// distinct pretest port, and StopIsolatedPretest tears it down alongside
// the pretest xray instance.
func TestRealActions_StartIsolatedPretest_NaiveProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{naiveProfile("primary")}
	cfg.PrimaryIndex = 0

	paths := Paths{
		XrayBinary:    os.Args[0],
		NaiveBinary:   os.Args[0],
		PretestConfig: filepath.Join(dir, "pretest.json"),
		Env:           []string{"FAILOVER_TEST_HELPER=1"},
	}
	a := newRealActions(paths, cfg)
	defer func() { _ = a.StopIsolatedPretest(context.Background()) }()

	if err := a.StartIsolatedPretest(context.Background()); err != nil {
		t.Fatalf("StartIsolatedPretest: %v", err)
	}
	if a.pretestNaive == nil {
		t.Fatal("expected a naive sidecar for the pretest instance")
	}
	waitUntil(t, time.Second, a.pretestNaive.Running)
	if a.naivePretestPort() == a.naiveProdPort() {
		t.Fatal("test invariant broken: pretest and production naive ports must differ")
	}

	data, err := os.ReadFile(paths.PretestConfig)
	if err != nil {
		t.Fatalf("reading pretest config: %v", err)
	}
	if !strings.Contains(string(data), strconv.Itoa(a.naivePretestPort())) {
		t.Errorf("pretest config does not reference the naive pretest sidecar port %d:\n%s", a.naivePretestPort(), data)
	}

	if err := a.StopIsolatedPretest(context.Background()); err != nil {
		t.Fatalf("StopIsolatedPretest: %v", err)
	}
	if a.pretestNaive != nil {
		t.Error("expected pretestNaive to be cleared after StopIsolatedPretest")
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

	// The failed probe was recorded for the doctor history.
	if len(actions.probes) != 1 {
		t.Fatalf("probes recorded = %d, want 1", len(actions.probes))
	}
	if p := actions.probes[0]; p.OK || !p.Live || p.Reason == "" {
		t.Errorf("recorded probe = %+v, want OK=false Live=true and a non-empty Reason", p)
	}
}

func TestClassifyProbeErr(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, "таймаут"},
		{errors.New("probe request failed: dial tcp: i/o timeout"), "таймаут"},
		{errors.New("probe request failed: connect: connection refused"), "отказ соединения"},
		{errors.New("probe request failed: dial tcp: lookup x: no such host"), "DNS"},
		{errors.New("connecting to SOCKS5 proxy 127.0.0.1:1080: connection refused"), "SOCKS"},
		{errors.New("probe returned status 503 Service Unavailable"), "HTTP 503"},
		{errors.New("read: connection reset by peer"), "сброс соединения"},
		{errors.New("something else entirely"), "ошибка"},
	}
	for _, c := range cases {
		if got := classifyProbeErr(c.err); got != c.want {
			t.Errorf("classifyProbeErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestRecordProbe_BoundsHistory(t *testing.T) {
	a := &realActions{}
	for i := 0; i < maxProbes+15; i++ {
		a.recordProbe(true, time.Now(), nil)
	}
	if len(a.probes) != maxProbes {
		t.Errorf("probes len = %d, want it capped at %d", len(a.probes), maxProbes)
	}
}

func TestRecordTransition_AttachesLastProbeReason(t *testing.T) {
	a := &realActions{}
	a.recordProbe(true, time.Now(), errors.New("probe request failed: dial tcp: i/o timeout"))
	d := &Daemon{actions: a, events: make(chan Event, 1)}

	d.recordTransition(StateActivePrimary, StateCooldown)

	select {
	case ev := <-d.events:
		if ev.Detail != "таймаут" {
			t.Errorf("Detail = %q, want таймаут", ev.Detail)
		}
	default:
		t.Fatal("no event emitted")
	}

	// A transition not triggered by a probe failure (the last probe was
	// OK) carries no Detail.
	a.recordProbe(true, time.Now(), nil)
	d.recordTransition(StateConfirmingRecovery, StateCooldown)
	select {
	case ev := <-d.events:
		if ev.Detail != "" {
			t.Errorf("Detail = %q, want empty after a successful probe", ev.Detail)
		}
	default:
		t.Fatal("no event emitted")
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

func TestDaemon_XrayCrashLoop(t *testing.T) {
	d := NewDaemon(Paths{}, config.Default())

	// crashLoopCount crashes inside the window -> exactly one advisory.
	for i := 0; i < crashLoopCount+2; i++ {
		d.noteXrayCrash()
	}
	select {
	case ev := <-d.Events():
		if ev.Kind != EventXrayCrashLoop || ev.Detail == "" {
			t.Fatalf("event = %+v, want EventXrayCrashLoop with a Detail", ev)
		}
	default:
		t.Fatal("no crash-loop event emitted after a burst of crashes")
	}
	select {
	case ev := <-d.Events():
		t.Fatalf("a second advisory was emitted while still looping: %+v", ev)
	default:
	}

	// Simulate a full quiet window, then a fresh burst -> re-armed.
	d.crashes = []time.Time{time.Now().Add(-2 * crashLoopWindow)}
	for i := 0; i < crashLoopCount; i++ {
		d.noteXrayCrash()
	}
	select {
	case ev := <-d.Events():
		if ev.Kind != EventXrayCrashLoop {
			t.Fatalf("re-armed event = %+v", ev)
		}
	default:
		t.Fatal("crash-loop detector did not re-arm after a quiet window")
	}
}
