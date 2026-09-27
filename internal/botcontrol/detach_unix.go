//go:build unix

package botcontrol

import (
	"os/exec"
	"syscall"
)

// detach puts cmd in its own session (setsid), the same precedent as
// cmd/keenetic-xray's own daemonctl_restart_unix.go: a detached updater
// or restart-scheduler must survive the process that spawned it being
// stopped mid-run -- which an rc.func-era init script's name-matching
// `stop` (PROCS=keenetic-xray) did, and a rollback can reinstall one.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
