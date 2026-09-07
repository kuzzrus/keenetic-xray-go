//go:build !unix

package main

import "os/exec"

// restartDetached is a no-op off unix (the init script is Entware-only
// anyway; this path only compiles for the dev machine).
func restartDetached(*exec.Cmd) {}
