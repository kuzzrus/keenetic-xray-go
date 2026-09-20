//go:build unix

package botcontrol

import (
	"os/exec"
	"syscall"
)

// detach puts cmd in its own session (setsid), the same precedent as
// cmd/keenetic-xray's own daemonctl_restart_unix.go: a detached updater
// or restart-scheduler must survive rc.func's name-matching `stop`
// (PROCS=keenetic-xray) killing the process that spawned it, mid-run.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
