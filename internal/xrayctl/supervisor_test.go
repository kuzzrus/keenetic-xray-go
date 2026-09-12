package xrayctl

import (
	"os"
	"testing"
	"time"
)

// TestMain lets `go test` re-exec the test binary itself as a stand-in
// for the xray binary Supervisor supervises, selected via
// XRAYCTL_TEST_HELPER -- avoids needing a real xray-core binary in CI.
func TestMain(m *testing.M) {
	if os.Getenv("XRAYCTL_TEST_HELPER") == "1" {
		runTestHelperProcess()
		return
	}
	os.Exit(m.Run())
}

func runTestHelperProcess() {
	switch os.Getenv("XRAYCTL_TEST_BEHAVIOR") {
	case "sleep":
		time.Sleep(time.Hour) // blocks until killed by the supervisor
	case "exit0":
		os.Exit(0)
	case "exit1":
		os.Exit(1)
	default:
		os.Exit(2)
	}
}

func helperEnv(behavior string) []string {
	return []string{"XRAYCTL_TEST_HELPER=1", "XRAYCTL_TEST_BEHAVIOR=" + behavior}
}

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

func TestSupervisor_StartStop(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		ConfigPath: "unused",
		Env:        helperEnv("sleep"),
		BackoffMin: 10 * time.Millisecond,
		BackoffMax: 50 * time.Millisecond,
	}

	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitUntil(t, time.Second, sup.Running)

	sup.Stop()
	if sup.Running() {
		t.Error("expected Running() to be false after Stop")
	}
}

func TestSupervisor_ArgsMode(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		Args:       []string{"--listen=socks://127.0.0.1:0", "--proxy=https://u:p@h:443"},
		Env:        helperEnv("sleep"),
		BackoffMin: 10 * time.Millisecond,
		BackoffMax: 50 * time.Millisecond,
	}

	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitUntil(t, time.Second, sup.Running)

	sup.Stop()
	if sup.Running() {
		t.Error("expected Running() to be false after Stop")
	}
}

func TestSupervisor_DoubleStartErrors(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		ConfigPath: "unused",
		Env:        helperEnv("sleep"),
	}
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()

	if err := sup.Start(); err == nil {
		t.Error("expected second Start to error")
	}
}

func TestSupervisor_StopBeforeStartIsSafe(t *testing.T) {
	sup := &Supervisor{BinaryPath: os.Args[0], ConfigPath: "unused"}
	sup.Stop() // must not panic or block
}

func TestSupervisor_StopIsIdempotent(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		ConfigPath: "unused",
		Env:        helperEnv("sleep"),
	}
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	sup.Stop()
	sup.Stop() // must not panic or block the second time
}

func TestSupervisor_RestartsOnCrash(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		ConfigPath: "unused",
		Env:        helperEnv("exit0"),
		BackoffMin: 5 * time.Millisecond,
		BackoffMax: 20 * time.Millisecond,
	}
	restarts := make(chan struct{}, 10)
	sup.OnRestart = func() {
		select {
		case restarts <- struct{}{}:
		default:
		}
	}

	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()

	// Generous timeout: this is normally well under 1s (5-20ms backoff x
	// 3 restarts), but -race instrumentation adds enough process-spawn
	// overhead to make a tight bound flaky.
	timeout := time.After(15 * time.Second)
	for seen := 0; seen < 3; {
		select {
		case <-restarts:
			seen++
		case <-timeout:
			t.Fatalf("only saw %d restarts within timeout, want at least 3", seen)
		}
	}
}

func TestSupervisor_Restart(t *testing.T) {
	sup := &Supervisor{
		BinaryPath: os.Args[0],
		ConfigPath: "unused",
		Env:        helperEnv("sleep"),
	}
	if err := sup.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sup.Stop()
	waitUntil(t, time.Second, sup.Running)

	if err := sup.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	waitUntil(t, time.Second, sup.Running)
}
