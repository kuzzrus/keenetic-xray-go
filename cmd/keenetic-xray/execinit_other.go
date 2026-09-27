//go:build !unix

package main

import (
	"fmt"
	"os/exec"
)

// execInitStart is the non-Unix stand-in for the exec in
// execinit_unix.go: there is no init script off the router, so this only
// keeps the dev build compiling and reports what it could not do.
func execInitStart(caller string) error {
	out, err := exec.Command(initScript, "start", caller).CombinedOutput()
	fmt.Print(string(out))
	if err != nil {
		return fmt.Errorf("%s start: %w", initScript, err)
	}
	return nil
}
