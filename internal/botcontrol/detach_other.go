//go:build !unix

package botcontrol

import "os/exec"

// detach is a no-op off unix -- the control server only ever runs the
// router-side commands that need this on Entware/Linux; this path only
// compiles for the dev machine.
func detach(*exec.Cmd) {}
