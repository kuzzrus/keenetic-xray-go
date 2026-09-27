//go:build unix

package main

import (
	"os"
	"syscall"
)

// execInitStart starts the daemon through its init script by *replacing*
// this process with the script rather than running it as a child, and
// only returns if that exec itself fails.
//
// While any process named keenetic-xray is alive, an rc.func-based init
// script -- the kind shipped until 2026-09-27, and the kind a rollback
// to an older version reinstalls -- takes that process for the daemon:
// `pidof keenetic-xray` finds it, "already running", nothing started.
// Run as a child of the watchdog hook, that was every single restart
// attempt (BOOT-01). Once exec'd, nothing named keenetic-xray is left
// for either kind of init script to trip over. caller only goes into
// the init script's boot.log -- never "cron", which an rc.func start
// refuses outright for a non-critical service.
func execInitStart(caller string) error {
	return syscall.Exec(initScript, []string{initScript, "start", caller}, os.Environ())
}
