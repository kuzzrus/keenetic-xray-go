//go:build unix

package selfupdate

import (
	"os/exec"
	"syscall"
)

// ownSession starts cmd in a session of its own, out of reach of
// signals aimed at this process's group.
func ownSession(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
