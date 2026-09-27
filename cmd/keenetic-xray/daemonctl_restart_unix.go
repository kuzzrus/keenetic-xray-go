//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// restartDetached puts the deferred `init.d restart` in its own session,
// so the CLI process that scheduled it isn't tied to the restart's fate
// -- see offerDaemonRestart for why that matters with an rc.func-era init
// script.
func restartDetached(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
