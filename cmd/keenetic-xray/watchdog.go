package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

// cmdWatchdog controls the cron entry that restarts the daemon if it's
// not running -- Entware's rc.func doesn't respawn a crashed process on
// its own (unlike the control-server's systemd unit, which has
// Restart=on-failure for free). Installed enabled by default via
// postinst; this is the manual override, and the bot's own watchdog
// button (RouterHandler in internal/botcontrol) calls the same
// underlying install functions.
func cmdWatchdog(args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		fmt.Println(watchdogStatusText())
		return nil
	case "enable":
		out, err := watchdogEnable()
		fmt.Println(out)
		return err
	case "disable":
		if err := install.SetWatchdogCron(cronFilePath(), watchdogScriptPath(), initScript, watchdogLogPath(), false); err != nil {
			return err
		}
		fmt.Println("watchdog disabled")
		return nil
	case "log":
		fmt.Println(watchdogLogText())
		return nil
	default:
		return fmt.Errorf("usage: keenetic-xray watchdog {show|enable|disable|log}")
	}
}

// watchdogStatusText reports both halves of "is this actually working":
// the cron entry (WatchdogEnabled) and a cron daemon actually being
// there to run it (CronRunning) -- an enabled entry with no cron daemon
// behind it is silently inert, which is exactly the gap this closes.
func watchdogStatusText() string {
	enabled, err := install.WatchdogEnabled(cronFilePath())
	if err != nil {
		return fmt.Sprintf("watchdog: error reading %s: %v", cronFilePath(), err)
	}
	cron := "running"
	if !install.CronRunning() {
		cron = "NOT running -- the entry below won't fire until it is"
	}
	return fmt.Sprintf("watchdog entry: %v (checks every %s via %s)\ncron daemon: %s",
		enabled, install.WatchdogSchedule, initScript, cron)
}

// watchdogEnable is cmdWatchdog's "enable" action factored out so the
// bot side (internal/botcontrol) can call the exact same sequence:
// make sure a cron daemon exists first (installing the Entware package
// if needed), then write the entry. Returns the message to show either
// way, so a caller doesn't need its own success/failure text.
func watchdogEnable() (string, error) {
	if err := install.EnsureCron(); err != nil {
		return "", fmt.Errorf("cron isn't available and couldn't be installed: %w", err)
	}
	if err := install.SetWatchdogCron(cronFilePath(), watchdogScriptPath(), initScript, watchdogLogPath(), true); err != nil {
		return "", err
	}
	return "watchdog enabled (cron confirmed running)", nil
}

// watchdogLogText returns the last lines of watchdogLogPath -- restart
// events only, not routine ticks (see install.SetWatchdogCron), so an
// empty result means the watchdog has never had to intervene.
func watchdogLogText() string {
	const maxLines = 40
	data, err := os.ReadFile(watchdogLogPath())
	if err != nil {
		if os.IsNotExist(err) {
			return "no restarts logged yet"
		}
		return fmt.Sprintf("could not read %s: %v", watchdogLogPath(), err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return "no restarts logged yet"
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}
