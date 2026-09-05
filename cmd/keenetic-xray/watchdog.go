package main

import (
	"fmt"

	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

// cmdWatchdog controls the cron entry that restarts the daemon if it's
// not running -- Entware's rc.func doesn't respawn a crashed process on
// its own (unlike the control-server's systemd unit, which has
// Restart=on-failure for free). Installed enabled by default via
// postinst; this is the manual override.
func cmdWatchdog(args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		enabled, err := install.WatchdogEnabled(cronFilePath())
		if err != nil {
			return err
		}
		fmt.Printf("watchdog: %v (checks every %s via %s)\n", enabled, install.WatchdogSchedule, initScript)
		return nil
	case "enable":
		if err := install.SetWatchdogCron(cronFilePath(), initScript, true); err != nil {
			return err
		}
		fmt.Println("watchdog enabled")
		return nil
	case "disable":
		if err := install.SetWatchdogCron(cronFilePath(), initScript, false); err != nil {
			return err
		}
		fmt.Println("watchdog disabled")
		return nil
	default:
		return fmt.Errorf("usage: keenetic-xray watchdog {show|enable|disable}")
	}
}
