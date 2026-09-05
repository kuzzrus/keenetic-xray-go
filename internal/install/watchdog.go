package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WatchdogMarker tags the cron line this package manages, so it can be
// found and replaced idempotently across repeated installs/upgrades --
// same convention the reference project uses for its own scheduled
// recovery entries (a trailing "# marker" comment on the crontab line).
const WatchdogMarker = "keenetic-xray-watchdog"

// WatchdogSchedule is how often the cron entry checks the daemon is
// alive. Every 2 minutes: frequent enough that a crash is caught well
// within DefaultOfflineThreshold (90s, see internal/botcontrol --
// OfflineWatcher is what actually notices for the operator), rare
// enough that spawning a shell process every couple of minutes is no
// real load on router hardware.
const WatchdogSchedule = "*/2 * * * *"

// SetWatchdogCron ensures cronFile contains exactly one entry (enabled)
// or none (disabled) for periodically checking the daemon via
// initScript's own `status` action and starting it if that reports it's
// not running -- Entware's rc.func doesn't respawn a crashed process on
// its own, unlike the control-server's systemd unit (Restart=on-failure,
// see packaging/server/keenetic-xray-control-server.service). `start`,
// not `restart`: status already established nothing is running, so
// there's nothing to stop first.
//
// Any other line already in cronFile (from an unrelated cron user) is
// preserved untouched; only the single line carrying WatchdogMarker is
// added, replaced, or removed. Safe to call on every postinst run.
func SetWatchdogCron(cronFile, initScript string, enabled bool) error {
	if err := os.MkdirAll(filepath.Dir(cronFile), 0o755); err != nil {
		return fmt.Errorf("creating cron directory: %w", err)
	}

	existing, err := os.ReadFile(cronFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", cronFile, err)
	}

	var kept []string
	for _, line := range strings.Split(string(existing), "\n") {
		if line == "" || strings.HasSuffix(line, "# "+WatchdogMarker) {
			continue
		}
		kept = append(kept, line)
	}
	if enabled {
		kept = append(kept, fmt.Sprintf("%s %s status >/dev/null 2>&1 || %s start >/dev/null 2>&1 # %s",
			WatchdogSchedule, initScript, initScript, WatchdogMarker))
	}

	data := ""
	if len(kept) > 0 {
		data = strings.Join(kept, "\n") + "\n"
	}
	if err := os.WriteFile(cronFile, []byte(data), 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", cronFile, err)
	}
	return nil
}

// WatchdogEnabled reports whether cronFile currently carries the
// watchdog entry.
func WatchdogEnabled(cronFile string) (bool, error) {
	data, err := os.ReadFile(cronFile)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("reading %s: %w", cronFile, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasSuffix(line, "# "+WatchdogMarker) {
			return true, nil
		}
	}
	return false, nil
}
