package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

func TestCmdWatchdog_ShowEnableDisable(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(t.TempDir(), "cron", "root"))

	// Fresh: not enabled.
	if enabled, err := install.WatchdogEnabled(cronFilePath()); err != nil || enabled {
		t.Fatalf("fresh watchdog state: enabled=%v err=%v, want false/nil", enabled, err)
	}

	if err := cmdWatchdog([]string{"enable"}); err != nil {
		t.Fatalf("watchdog enable: %v", err)
	}
	if enabled, err := install.WatchdogEnabled(cronFilePath()); err != nil || !enabled {
		t.Errorf("after enable: enabled=%v err=%v, want true/nil", enabled, err)
	}

	if err := cmdWatchdog([]string{"show"}); err != nil {
		t.Fatalf("watchdog show: %v", err)
	}

	if err := cmdWatchdog([]string{"disable"}); err != nil {
		t.Fatalf("watchdog disable: %v", err)
	}
	if enabled, err := install.WatchdogEnabled(cronFilePath()); err != nil || enabled {
		t.Errorf("after disable: enabled=%v err=%v, want false/nil", enabled, err)
	}
}

func TestCmdWatchdog_UnknownAction(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CRON_FILE", filepath.Join(t.TempDir(), "cron", "root"))
	if err := cmdWatchdog([]string{"bogus"}); err == nil {
		t.Error("expected an error for an unknown watchdog action")
	}
}
