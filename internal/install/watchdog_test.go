package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testInitScript = "/opt/etc/init.d/S99keenetic-xray"
const testWatchdogLog = "/opt/var/log/keenetic-xray/watchdog.log"

func TestSetWatchdogCron_EnableOnFreshFile(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")

	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, true); err != nil {
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
	if !strings.Contains(got, testInitScript+" status") || !strings.Contains(got, testInitScript+" start") {
		t.Errorf("cron file = %q, want both a status check and a start fallback", got)
	}
	if !strings.Contains(got, testWatchdogLog) {
		t.Errorf("cron file = %q, want it to log restarts to %s", got, testWatchdogLog)
	}
	if !strings.HasSuffix(strings.TrimRight(got, "\n"), "# "+WatchdogMarker) {
		t.Errorf("cron file = %q, want the line to end with the marker", got)
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
	other := "0 3 * * * /opt/bin/some-other-job # unrelated-marker\n"
	if err := os.WriteFile(cronFile, []byte(other), 0o600); err != nil {
		t.Fatalf("seeding cron file: %v", err)
	}

	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, true); err != nil {
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

	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron (1st): %v", err)
	}
	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, true); err != nil {
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
	other := "0 3 * * * /opt/bin/some-other-job # unrelated-marker\n"
	if err := os.WriteFile(cronFile, []byte(other), 0o600); err != nil {
		t.Fatalf("seeding cron file: %v", err)
	}

	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, true); err != nil {
		t.Fatalf("SetWatchdogCron (enable): %v", err)
	}
	if err := SetWatchdogCron(cronFile, testInitScript, testWatchdogLog, false); err != nil {
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

	enabled, err := WatchdogEnabled(cronFile)
	if err != nil {
		t.Fatalf("WatchdogEnabled: %v", err)
	}
	if enabled {
		t.Error("WatchdogEnabled = true, want false after disable")
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
