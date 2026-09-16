package install

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
		if err := writeWatchdogScript(scriptPath, initScript, logFile, selfBinaryPath()); err != nil {
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

// selfBinaryPath resolves the currently-running keenetic-xray binary's
// own path via os.Executable, falling back to the install layout's
// fixed path (the same literal packaging/ipk/postinst already uses) if
// that somehow fails. SetWatchdogCron always runs *as* the keenetic-xray
// binary itself (postinst, `watchdog enable`, or the bot's own process),
// so this reliably finds the right thing for the watchdog script to
// invoke -- no need to thread a binary path through every caller.
func selfBinaryPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/opt/sbin/keenetic-xray"
}

// writeWatchdogScript (re)generates the tiny shell script the cron entry
// invokes. Kept deliberately dumb -- one status check, one conditional
// log line, one hook call -- so the interesting part (when it runs, what
// a non-empty log means) stays documented on SetWatchdogCron rather than
// spread across a shell file nobody reads.
//
// Calls `<binaryPath> internal watchdog-restart-hook` rather than a bare
// `<initScript> start`: that hook is what actually decides between an
// ordinary restart and rolling back a self-update that never managed to
// come up (see cmd/keenetic-xray's cmdWatchdogRestartHook) -- keeping
// that decision in Go, not shell, is what keeps it unit-testable, the
// same reasoning SetWatchdogCron's own doc comment already gives for
// EnsureCron/SetWatchdogCron themselves.
func writeWatchdogScript(scriptPath, initScript, logFile, binaryPath string) error {
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
		return fmt.Errorf("creating script directory: %w", err)
	}
	body := fmt.Sprintf(`#!/bin/sh
# %s -- managed by keenetic-xray; regenerated on every install and on
# `+"`watchdog enable`"+`, so local edits here do not stick. Restarts the
# failover daemon if its init script reports it stopped (or rolls back a
# bad self-update instead -- see internal watchdog-restart-hook); appends
# to the log only on an actual restart, never on a healthy tick.
%s status >/dev/null 2>&1 && exit 0
echo "$(date '+%%Y-%%m-%%d %%H:%%M:%%S') restarting -- status check failed" >> %s
%s internal watchdog-restart-hook >/dev/null 2>&1
`, WatchdogMarker, initScript, logFile, binaryPath)
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

// cronOpkgTimeout bounds cronOpkgInstall's own opkg calls -- see that
// var's doc comment for why this needs one at all.
const cronOpkgTimeout = 2 * time.Minute

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
	cronOpkgInstall = func() error {
		// Bounded: this is the one network-touching step in EnsureCron's
		// whole chain (the other three vars above are local status/init-
		// script checks) -- reached from postinst-setup on every self-
		// update whenever cron isn't already detected running, so an
		// unbounded stall here can hang the *entire* self-update chain
		// just as badly as the since-fixed lack of a timeout on this
		// project's own curl calls once did (#159). See
		// RouterHandler.selfUpdateOverallTimeout's own doc comment
		// (internal/botcontrol/commands.go) for the fuller incident.
		ctx, cancel := context.WithTimeout(context.Background(), cronOpkgTimeout)
		defer cancel()
		// `opkg update` first, best-effort -- same reasoning as
		// internal/addons' own opkgInstall helper.
		_ = exec.CommandContext(ctx, "opkg", "update").Run()
		return exec.CommandContext(ctx, "opkg", "install", "cron").Run()
	}
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
// starting it. A no-op if one's already running. This is what the bot's
// watchdog-enable button and `keenetic-xray watchdog enable` call before
// SetWatchdogCron, so "enable the watchdog" is a single action rather
// than requiring cron to already be present.
func EnsureCron() error {
	if CronRunning() {
		return nil
	}
	if err := cronOpkgInstall(); err != nil {
		return fmt.Errorf("installing the cron package: %w", err)
	}
	// No explicit "enable at boot" step: Entware's S10cron ships
	// ENABLED=yes and Entware runs every S* init script at boot, so it's
	// persistent already. This rc.func build has no `enable` action at
	// all -- it errors "Usage: ..." -- so call it only for the builds
	// that do have it and ignore the failure otherwise.
	_ = cronInitEnable()
	if err := cronInitStart(); err != nil {
		return fmt.Errorf("starting cron: %w", err)
	}
	if !CronRunning() {
		return fmt.Errorf("cron still isn't running after installing and starting it")
	}
	return nil
}
