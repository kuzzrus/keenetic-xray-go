package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testInitScript = "/opt/etc/init.d/S99keenetic-xray"
const testWatchdogLog = "/opt/var/log/keenetic-xray/watchdog.log"

func TestSetWatchdogCron_EnableOnFreshFile(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")

	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron: %v", err)
	}

	data, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, WatchdogSchedule) {
		t.Errorf("cron file = %q, want schedule %q", got, WatchdogSchedule)
	}
	// The crontab line is just the schedule, the script path and the
	// marker -- no inline shell, so busybox crond has nothing verbose to
	// echo to syslog every tick.
	if !strings.Contains(got, scriptPath) {
		t.Errorf("cron file = %q, want it to invoke the script at %s", got, scriptPath)
	}
	if strings.Contains(got, "status >/dev/null") || strings.Contains(got, testWatchdogLog) {
		t.Errorf("cron file = %q, want the check/restart logic in the script, not inline", got)
	}
	if !strings.HasSuffix(strings.TrimRight(got, "\n"), "# "+WatchdogMarker) {
		t.Errorf("cron file = %q, want the line to end with the marker", got)
	}

	script, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("reading the watchdog script: %v", err)
	}
	s := string(script)
	if !strings.Contains(s, testInitScript+" status") || !strings.Contains(s, testInitScript+" start") {
		t.Errorf("script = %q, want both a status check and a start fallback", s)
	}
	if !strings.Contains(s, testWatchdogLog) {
		t.Errorf("script = %q, want it to log restarts to %s", s, testWatchdogLog)
	}
	if fi, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("Stat script: %v", err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("script mode = %v, want the owner-execute bit set", fi.Mode().Perm())
	}

	enabled, err := WatchdogEnabled(cronFile)
	if err != nil {
		t.Fatalf("WatchdogEnabled: %v", err)
	}
	if !enabled {
		t.Error("WatchdogEnabled = false, want true")
	}
}

func TestSetWatchdogCron_PreservesOtherEntries(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")
	other := "0 3 * * * /opt/bin/some-other-job # unrelated-marker\n"
	if err := os.WriteFile(cronFile, []byte(other), 0o600); err != nil {
		t.Fatalf("seeding cron file: %v", err)
	}

	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron: %v", err)
	}

	data, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "unrelated-marker") {
		t.Errorf("cron file = %q, want the pre-existing unrelated entry preserved", got)
	}
	if !strings.Contains(got, WatchdogMarker) {
		t.Errorf("cron file = %q, want our own entry added", got)
	}
}

func TestSetWatchdogCron_ReplacesOwnEntryIdempotently(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")

	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron (1st): %v", err)
	}
	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron (2nd): %v", err)
	}

	data, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	count := 0
	for _, l := range lines {
		if strings.HasSuffix(l, "# "+WatchdogMarker) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("watchdog entries after two enables = %d, want exactly 1 (no duplicates)", count)
	}
}

func TestSetWatchdogCron_Disable(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")
	other := "0 3 * * * /opt/bin/some-other-job # unrelated-marker\n"
	if err := os.WriteFile(cronFile, []byte(other), 0o600); err != nil {
		t.Fatalf("seeding cron file: %v", err)
	}

	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron (enable): %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("script should exist after enable: %v", err)
	}
	if err := SetWatchdogCron(cronFile, scriptPath, testInitScript, testWatchdogLog, false); err != nil {
		t.Fatalf("SetWatchdogCron (disable): %v", err)
	}

	data, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	if strings.Contains(got, WatchdogMarker) {
		t.Errorf("cron file = %q, want our entry removed after disable", got)
	}
	if !strings.Contains(got, "unrelated-marker") {
		t.Errorf("cron file = %q, want the unrelated entry still preserved", got)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Errorf("script should be gone after disable, stat err = %v", err)
	}

	enabled, err := WatchdogEnabled(cronFile)
	if err != nil {
		t.Fatalf("WatchdogEnabled: %v", err)
	}
	if enabled {
		t.Error("WatchdogEnabled = true, want false after disable")
	}
}

// TestSetWatchdogCron_DisableWithoutPriorScriptIsOK covers the plain
// case where disable runs and no script was ever written (a fresh box,
// or `watchdog disable` before any enable): removing a file that isn't
// there must not be an error.
func TestSetWatchdogCron_DisableWithoutPriorScriptIsOK(t *testing.T) {
	dir := t.TempDir()
	if err := SetWatchdogCron(filepath.Join(dir, "root"), filepath.Join(dir, "watchdog.sh"), testInitScript, testWatchdogLog, false); err != nil {
		t.Fatalf("SetWatchdogCron (disable, nothing to remove): %v", err)
	}
}

func TestWatchdogEnabled_MissingFileIsNotEnabled(t *testing.T) {
	dir := t.TempDir()
	enabled, err := WatchdogEnabled(filepath.Join(dir, "does-not-exist"))
	if err != nil {
		t.Fatalf("WatchdogEnabled: %v", err)
	}
	if enabled {
		t.Error("WatchdogEnabled = true for a missing file, want false")
	}
}

// withCronHooks overrides all four of CronRunning/EnsureCron's system
// touchpoints for the duration of the test, restoring the originals on
// cleanup -- same convention as internal/keenetic's fakeNdmc.
func withCronHooks(t *testing.T, status, enable, start func() error, viaPS func() bool) {
	t.Helper()
	origStatus, origEnable, origStart, origPS := cronInitStatus, cronInitEnable, cronInitStart, cronRunningViaPS
	cronInitStatus, cronInitEnable, cronInitStart, cronRunningViaPS = status, enable, start, viaPS
	t.Cleanup(func() {
		cronInitStatus, cronInitEnable, cronInitStart, cronRunningViaPS = origStatus, origEnable, origStart, origPS
	})
}

func ok() error  { return nil }
func bad() error { return errors.New("nope") }

func TestCronRunning_TrueViaInitScript(t *testing.T) {
	psCalled := false
	withCronHooks(t, ok, bad, bad, func() bool { psCalled = true; return false })
	if !CronRunning() {
		t.Error("CronRunning() = false, want true when the init script reports status ok")
	}
	if psCalled {
		t.Error("the ps fallback ran even though the init script status already succeeded")
	}
}

func TestCronRunning_TrueViaPSFallback(t *testing.T) {
	withCronHooks(t, bad, bad, bad, func() bool { return true })
	if !CronRunning() {
		t.Error("CronRunning() = false, want true via the ps fallback")
	}
}

func TestCronRunning_FalseWhenNeitherWorks(t *testing.T) {
	withCronHooks(t, bad, bad, bad, func() bool { return false })
	if CronRunning() {
		t.Error("CronRunning() = true, want false when both checks fail")
	}
}

func TestEnsureCron_AlreadyRunningIsNoOp(t *testing.T) {
	installCalled := false
	origInstall := cronOpkgInstall
	cronOpkgInstall = func() error { installCalled = true; return nil }
	t.Cleanup(func() { cronOpkgInstall = origInstall })

	withCronHooks(t, ok, bad, bad, func() bool { return false }) // status ok -> already running
	if err := EnsureCron(); err != nil {
		t.Fatalf("EnsureCron: %v", err)
	}
	if installCalled {
		t.Error("opkg install ran even though cron was already reported running")
	}
}

func TestEnsureCron_InstallsEnablesAndStarts(t *testing.T) {
	installCalled, enableCalled, startCalled := false, false, false
	origInstall := cronOpkgInstall
	cronOpkgInstall = func() error { installCalled = true; return nil }
	t.Cleanup(func() { cronOpkgInstall = origInstall })

	// Not running at first (status fails, ps fails); becomes running
	// only once start has actually been called -- lets CronRunning's
	// second call (EnsureCron's final verification) reflect a genuine
	// state change from the simulated install+enable+start, the same
	// way a real router would go from "nothing running" to "running".
	withCronHooks(t,
		bad,
		func() error { enableCalled = true; return nil },
		func() error { startCalled = true; return nil },
		func() bool { return startCalled },
	)

	if err := EnsureCron(); err != nil {
		t.Fatalf("EnsureCron: %v", err)
	}
	if !installCalled || !enableCalled || !startCalled {
		t.Errorf("install/enable/start = %v/%v/%v, want all true", installCalled, enableCalled, startCalled)
	}
}

func TestEnsureCron_OpkgInstallFails_StopsThere(t *testing.T) {
	enableCalled := false
	origInstall := cronOpkgInstall
	cronOpkgInstall = bad
	t.Cleanup(func() { cronOpkgInstall = origInstall })

	withCronHooks(t, bad, func() error { enableCalled = true; return nil }, bad, func() bool { return false })

	if err := EnsureCron(); err == nil {
		t.Fatal("expected an error when opkg install fails")
	}
	if enableCalled {
		t.Error("enable ran even though opkg install had already failed")
	}
}

func TestEnsureCron_StillNotRunningAfterStart(t *testing.T) {
	origInstall := cronOpkgInstall
	cronOpkgInstall = ok
	t.Cleanup(func() { cronOpkgInstall = origInstall })

	// Everything reports success, but CronRunning stays false throughout
	// -- e.g. the package installed but the binary doesn't actually run
	// on this router. Must be surfaced as an error, not silently "ok".
	withCronHooks(t, bad, ok, ok, func() bool { return false })

	if err := EnsureCron(); err == nil {
		t.Fatal("expected an error when cron still isn't running after start")
	}
}
