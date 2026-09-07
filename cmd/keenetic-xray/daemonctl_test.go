package main

import (
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// withProcessName overrides processName for the duration of the test.
func withProcessName(t *testing.T, fn func(pid int) string) {
	t.Helper()
	old := processName
	processName = fn
	t.Cleanup(func() { processName = old })
}

// withProcStartToken overrides procStartToken for the duration of the test.
func withProcStartToken(t *testing.T, fn func(pid int) string) {
	t.Helper()
	old := procStartToken
	procStartToken = fn
	t.Cleanup(func() { procStartToken = old })
}

func writePIDFile(t *testing.T, pid int) string {
	t.Helper()
	return writePIDFileLines(t, strconv.Itoa(pid))
}

// writePIDFileLines writes an arbitrary pidfile body (one arg per line)
// so tests can exercise both the legacy single-line format and the
// pid+start-token format writeDaemonPIDFile now produces.
func writePIDFileLines(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keenetic-xray.pid")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("writing pidfile: %v", err)
	}
	t.Setenv("KEENETIC_XRAY_PID_FILE", path)
	return path
}

func TestRunningDaemonPID_MissingPidfile(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_PID_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	if _, err := runningDaemonPID(); err == nil {
		t.Error("expected an error for a missing pidfile")
	}
}

func TestRunningDaemonPID_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keenetic-xray.pid")
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0o600); err != nil {
		t.Fatalf("writing pidfile: %v", err)
	}
	t.Setenv("KEENETIC_XRAY_PID_FILE", path)
	if _, err := runningDaemonPID(); err == nil {
		t.Error("expected an error for a pidfile that isn't a number")
	}
}

func TestRunningDaemonPID_ProcessGone(t *testing.T) {
	writePIDFile(t, 999999)
	withProcessName(t, func(pid int) string { return "" }) // simulates /proc/<pid>/comm: no such process
	if _, err := runningDaemonPID(); err == nil {
		t.Error("expected an error when the pid isn't running")
	}
}

// TestRunningDaemonPID_StalePidReusedByOtherProcess is the regression
// test for the actual safety property here: a pidfile pointing at a PID
// that's alive but is now something else entirely (the daemon died and
// the OS reused its PID) must be rejected, not trusted -- SIGHUP
// terminates a process that hasn't installed its own handler for it, by
// POSIX default, so signaling blindly would risk killing an unrelated
// process rather than harmlessly no-op'ing.
func TestRunningDaemonPID_StalePidReusedByOtherProcess(t *testing.T) {
	writePIDFile(t, 42)
	withProcessName(t, func(pid int) string { return "some-other-program" })
	if _, err := runningDaemonPID(); err == nil {
		t.Error("expected an error when the pid now belongs to a different program")
	}
}

func TestRunningDaemonPID_Matches(t *testing.T) {
	writePIDFile(t, 42)
	withProcessName(t, func(pid int) string {
		if pid == 42 {
			return "keenetic-xray"
		}
		return "wrong"
	})
	got, err := runningDaemonPID()
	if err != nil {
		t.Fatalf("runningDaemonPID: %v", err)
	}
	if got != 42 {
		t.Errorf("pid = %d, want 42", got)
	}
}

// TestRunningDaemonPID_StartTokenMismatch: the PID is alive and still
// named keenetic-xray, but its start time doesn't match the token the
// daemon recorded -- the OS handed our old PID to a fresh keenetic-xray
// invocation after a reboot. Must be rejected.
func TestRunningDaemonPID_StartTokenMismatch(t *testing.T) {
	writePIDFileLines(t, "42", "111111")
	withProcessName(t, func(int) string { return "keenetic-xray" })
	withProcStartToken(t, func(int) string { return "999999" })
	if _, err := runningDaemonPID(); err == nil {
		t.Error("expected an error when the start-time token doesn't match (recycled pid)")
	}
}

func TestRunningDaemonPID_StartTokenMatches(t *testing.T) {
	writePIDFileLines(t, "42", "111111")
	withProcessName(t, func(int) string { return "keenetic-xray" })
	withProcStartToken(t, func(int) string { return "111111" })
	got, err := runningDaemonPID()
	if err != nil {
		t.Fatalf("runningDaemonPID: %v", err)
	}
	if got != 42 {
		t.Errorf("pid = %d, want 42", got)
	}
}

// A legacy single-line pidfile (no token) keeps working: the token
// check is skipped, only the process-name check gates.
func TestRunningDaemonPID_LegacyNoToken(t *testing.T) {
	writePIDFile(t, 42)
	withProcessName(t, func(int) string { return "keenetic-xray" })
	withProcStartToken(t, func(int) string {
		t.Error("procStartToken must not be consulted for a tokenless pidfile")
		return ""
	})
	if _, err := runningDaemonPID(); err != nil {
		t.Fatalf("runningDaemonPID: %v", err)
	}
}

func TestParseProcStatStartTime(t *testing.T) {
	// comm with a space and comm with an embedded ')': parsing must
	// resume after the *last* ')'.
	cases := []struct {
		name, stat, want string
	}{
		{
			"plain",
			"1234 (keeneticxray) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 8675309 99",
			"8675309",
		},
		{
			"comm has space",
			"1234 (keen xray) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 4242 99",
			"4242",
		},
		{
			"comm has close paren",
			"1234 (we)ird) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 5150 99",
			"5150",
		},
		{"truncated", "1234 (x) S 1 1234", ""},
		{"garbage", "not a stat line", ""},
	}
	for _, c := range cases {
		if got := parseProcStatStartTime(c.stat); got != c.want {
			t.Errorf("%s: parseProcStatStartTime = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSignalDaemonReload_DeliversSIGHUP proves the whole chain actually
// sends a real signal: it points the pidfile at this test process's own
// pid (with processName faked to match), installs a SIGHUP handler
// (without one, the default action would terminate the test process --
// exactly the hazard runningDaemonPID's process-name check guards
// against for an unintended target), and checks the handler fires.
func TestSignalDaemonReload_DeliversSIGHUP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGHUP delivery via os.Process.Signal is a Unix-only path -- this project only ever runs the daemon on Linux (routers, VPS)")
	}
	self := os.Getpid()
	writePIDFile(t, self)
	withProcessName(t, func(pid int) string {
		if pid == self {
			return "keenetic-xray"
		}
		return ""
	})

	got := make(chan os.Signal, 1)
	signal.Notify(got, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(got) })

	if !signalDaemonReload() {
		t.Fatal("signalDaemonReload returned false, want true")
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("SIGHUP was not delivered to this process")
	}
}

func TestWriteDaemonPIDFile_WriteAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "keenetic-xray.pid")
	t.Setenv("KEENETIC_XRAY_PID_FILE", path)

	cleanup, err := writeDaemonPIDFile()
	if err != nil {
		t.Fatalf("writeDaemonPIDFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading pidfile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if got, _ := strconv.Atoi(strings.TrimSpace(lines[0])); got != os.Getpid() {
		t.Errorf("pidfile line 1 = %q, want this process's own pid %d", lines[0], os.Getpid())
	}
	// Line 2 (the start-time token) is present on Linux, absent where
	// /proc/<pid>/stat can't be read (the Windows dev box). Round-trip it:
	// whatever writeDaemonPIDFile recorded, runningDaemonPID must accept.
	withProcessName(t, func(int) string { return "keenetic-xray" })
	if _, err := runningDaemonPID(); err != nil {
		t.Errorf("runningDaemonPID rejected a pidfile writeDaemonPIDFile just wrote: %v", err)
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("pidfile still exists after cleanup: err=%v", err)
	}
}

func TestSignalDaemonReload_NoPidfile(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_PID_FILE", filepath.Join(t.TempDir(), "does-not-exist"))
	if signalDaemonReload() {
		t.Error("signalDaemonReload = true with no pidfile, want false")
	}
}
