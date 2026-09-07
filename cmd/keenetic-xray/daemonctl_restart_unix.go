//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// restartDetached puts the deferred `init.d restart` in its own session
// so rc.func's name-matching stop (PROCS=keenetic-xray) can't reach back
// and kill the CLI process that scheduled it.
func restartDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
