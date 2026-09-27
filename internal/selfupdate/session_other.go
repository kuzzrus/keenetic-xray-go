//go:build !unix

package selfupdate

import "os/exec"

// ownSession is a no-op off Unix -- opkg and the router only exist there.
func ownSession(*exec.Cmd) {}
