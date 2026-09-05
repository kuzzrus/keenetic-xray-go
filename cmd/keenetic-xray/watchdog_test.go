package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

func TestCmdWatchdog_Disable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(dir, "cron", "root"))
	t.Setenv("KEENETIC_XRAY_WATCHDOG_SCRIPT", filepath.Join(dir, "watchdog.sh"))

	if err := cmdWatchdog([]string{"disable"}); err != nil {
		t.Fatalf("watchdog disable: %v", err)
	}
	if enabled, err := install.WatchdogEnabled(cronFilePath()); err != nil || enabled {
		t.Errorf("after disable: enabled=%v err=%v, want false/nil", enabled, err)
	}
}

func TestCmdWatchdog_Show_DoesNotError(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(t.TempDir(), "cron", "root"))
	// show reports both the entry (none yet) and whether a cron daemon
	// is running (environment-dependent -- this machine has no real
	// one, and that's fine to report either way); just check it doesn't
	// error and mentions both halves.
	if err := cmdWatchdog([]string{"show"}); err != nil {
		t.Fatalf("watchdog show: %v", err)
	}
	text := watchdogStatusText()
	if !strings.Contains(text, "watchdog entry:") || !strings.Contains(text, "cron daemon:") {
		t.Errorf("watchdogStatusText() = %q, want it to cover both the entry and the cron daemon", text)
	}
}

// TestCmdWatchdog_Enable_FailsCleanlyWithoutRealCron is the realistic
// case for a dev box (and CI): there's no real Entware cron or opkg
// here, so EnsureCron cannot succeed, and enable must fail rather than
// pretend it worked -- critically, without having written the cron
// entry first, since a written-but-inert entry (cron enabled but no
// daemon to run it) is exactly the silent-failure mode this whole
// feature exists to avoid.
func TestCmdWatchdog_Enable_FailsCleanlyWithoutRealCron(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "cron", "root")
	scriptPath := filepath.Join(dir, "watchdog.sh")
	t.Setenv("KEENETIC_XRAY_CRON_FILE", cronFile)
	t.Setenv("KEENETIC_XRAY_WATCHDOG_SCRIPT", scriptPath)

	if err := cmdWatchdog([]string{"enable"}); err == nil {
		t.Fatal("expected an error: no real cron/opkg is available in this environment")
	}
	if _, err := os.Stat(cronFile); !os.IsNotExist(err) {
		t.Errorf("cron file should not have been written when EnsureCron failed first, stat err = %v", err)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Errorf("script should not have been written when EnsureCron failed first, stat err = %v", err)
	}
}

func TestCmdWatchdog_Log_EmptyWhenNoFile(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_WATCHDOG_LOG", filepath.Join(t.TempDir(), "watchdog.log"))
	got := watchdogLogText()
	if got != "no restarts logged yet" {
		t.Errorf("watchdogLogText() = %q, want the no-restarts message for a missing file", got)
	}
}

func TestCmdWatchdog_Log_ReturnsContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdog.log")
	t.Setenv("KEENETIC_XRAY_WATCHDOG_LOG", path)
	if err := os.WriteFile(path, []byte("2026-09-05 09:04:00 restarting -- status check failed\n"), 0o600); err != nil {
		t.Fatalf("seeding watchdog log: %v", err)
	}
	got := watchdogLogText()
	if !strings.Contains(got, "2026-09-05 09:04:00") {
		t.Errorf("watchdogLogText() = %q, want the seeded line", got)
	}
}

func TestCmdWatchdog_UnknownAction(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(t.TempDir(), "cron", "root"))
	if err := cmdWatchdog([]string{"bogus"}); err == nil {
		t.Error("expected an error for an unknown watchdog action")
	}
}
