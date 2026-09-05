package install

import (
	"fmt"
	"os"
	"os/exec"
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
// The check-and-restart logic lives in a small script at scriptPath, not
// inline in the crontab line, for one reason: busybox crond echoes the
// *entire* command of every job it runs to syslog on each tick, so an
// inline `sh`-snippet here would spell the whole thing out in the router
// log every couple of minutes. A bare path keeps that echo down to one
// short `cmd <scriptPath>`. The script is (re)written on every enable and
// removed on disable, so it always matches the current initScript/logFile
// and never lingers after the entry is gone.
//
// The script appends one timestamped line to logFile *only* when it
// actually restarts the daemon (status failed) -- not on every routine
// tick, which would just be noise. A non-empty log is then direct
// evidence of how often the watchdog has actually had to intervene,
// distinguishing "working as intended, rarely needed" from "firing
// constantly" -- something a bare uptime/status snapshot can't show,
// since a restarted process's own in-memory state (including its
// failover.Daemon.Transitions history) starts fresh and carries no
// trace of why.
//
// Any other line already in cronFile (from an unrelated cron user) is
// preserved untouched; only the single line carrying WatchdogMarker is
// added, replaced, or removed. Safe to call on every postinst run.
func SetWatchdogCron(cronFile, scriptPath, initScript, logFile string, enabled bool) error {
	if err := os.MkdirAll(filepath.Dir(cronFile), 0o755); err != nil {
		return fmt.Errorf("creating cron directory: %w", err)
	}

	if enabled {
		if err := writeWatchdogScript(scriptPath, initScript, logFile); err != nil {
			return err
		}
	} else if err := os.Remove(scriptPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", scriptPath, err)
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
		kept = append(kept, fmt.Sprintf("%s %s # %s", WatchdogSchedule, scriptPath, WatchdogMarker))
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

// writeWatchdogScript (re)generates the tiny shell script the cron entry
// invokes. Kept deliberately dumb -- one status check, one conditional
// log line, one start -- so the interesting part (when it runs, what a
// non-empty log means) stays documented on SetWatchdogCron rather than
// spread across a shell file nobody reads.
func writeWatchdogScript(scriptPath, initScript, logFile string) error {
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
		return fmt.Errorf("creating script directory: %w", err)
	}
	body := fmt.Sprintf(`#!/bin/sh
# %s -- managed by keenetic-xray; regenerated on every install and on
# `+"`watchdog enable`"+`, so local edits here do not stick. Restarts the
# failover daemon if its init script reports it stopped; appends to the
# log only on an actual restart, never on a healthy tick.
%s status >/dev/null 2>&1 && exit 0
echo "$(date '+%%Y-%%m-%%d %%H:%%M:%%S') restarting -- status check failed" >> %s
%s start >/dev/null 2>&1
`, WatchdogMarker, initScript, logFile, initScript)
	if err := os.WriteFile(scriptPath, []byte(body), 0o755); err != nil {
		return fmt.Errorf("writing %s: %w", scriptPath, err)
	}
	// WriteFile does not chmod an existing file; make sure a regenerated
	// script stays executable.
	if err := os.Chmod(scriptPath, 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", scriptPath, err)
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

// CronInitScript is Entware's cron init script -- rc.func provides
// `status`/`enable`/`start` for free, the same mechanism the watchdog
// cron entry above relies on to check the keenetic-xray daemon itself.
const CronInitScript = "/opt/etc/init.d/S10cron"

// The four points below are the only places CronRunning/EnsureCron
// actually touch the system -- injectable vars (same convention as
// internal/keenetic's lookNdmc/ndmcRun) so the *decision logic* here
// (which order things are tried in, what happens on each failure) is
// testable without a real Entware router: a minimal busybox image,
// opkg, and rc.func aren't available in CI or on the Windows box this
// is developed on.
var (
	cronInitStatus   = func() error { return exec.Command(CronInitScript, "status").Run() }
	cronInitEnable   = func() error { return exec.Command(CronInitScript, "enable").Run() }
	cronInitStart    = func() error { return exec.Command(CronInitScript, "start").Run() }
	cronRunningViaPS = func() bool {
		// ps+grep, not pgrep: a minimal busybox image isn't guaranteed
		// to include the pgrep applet. Covers a bare `crond` invocation
		// with no init script involved (e.g. hand-started, or a
		// non-Entware cron package).
		return exec.Command("sh", "-c", "ps | grep -v grep | grep -q crond").Run() == nil
	}
	cronOpkgInstall = func() error { return exec.Command("opkg", "install", "cron").Run() }
)

// CronRunning reports whether a cron daemon is currently active, so
// SetWatchdogCron's entry actually has something reading it -- an
// enabled entry with no cron daemon behind it is silently inert.
func CronRunning() bool {
	if cronInitStatus() == nil {
		return true
	}
	return cronRunningViaPS()
}

// EnsureCron makes sure a cron daemon is installed and running,
// installing the Entware `cron` package via opkg first if needed, then
// enabling and starting it. A no-op if one's already running. This is
// what the bot's watchdog-enable button and `keenetic-xray watchdog
// enable` call before SetWatchdogCron, so "enable the watchdog" is a
// single action rather than requiring cron to already be present.
func EnsureCron() error {
	if CronRunning() {
		return nil
	}
	if err := cronOpkgInstall(); err != nil {
		return fmt.Errorf("installing the cron package: %w", err)
	}
	if err := cronInitEnable(); err != nil {
		return fmt.Errorf("enabling cron at boot: %w", err)
	}
	if err := cronInitStart(); err != nil {
		return fmt.Errorf("starting cron: %w", err)
	}
	if !CronRunning() {
		return fmt.Errorf("cron still isn't running after installing and starting it")
	}
	return nil
}
