package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetWatchdogCron_EnableOnFreshFile(t *testing.T) {
	dir := t.TempDir()
	cronFile := filepath.Join(dir, "root")

	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", true); err != nil {
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
	if !strings.Contains(got, "/opt/etc/init.d/S99keenetic-xray status") || !strings.Contains(got, "/opt/etc/init.d/S99keenetic-xray start") {
		t.Errorf("cron file = %q, want both a status check and a start fallback", got)
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

	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", true); err != nil {
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

	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", true); err != nil {
		t.Fatalf("SetWatchdogCron (1st): %v", err)
	}
	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", true); err != nil {
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

	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", true); err != nil {
		t.Fatalf("SetWatchdogCron (enable): %v", err)
	}
	if err := SetWatchdogCron(cronFile, "/opt/etc/init.d/S99keenetic-xray", false); err != nil {
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
