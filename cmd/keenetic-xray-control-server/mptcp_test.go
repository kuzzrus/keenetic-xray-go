package main

import (
	"net"
	"testing"
)

// TestListenersDoNotUseMPTCP guards the "godebug multipathtcp=0" line in
// go.mod.
//
// Since Go 1.24 a plain net.Listen / http.Server.ListenAndServeTLS opens a
// multipath-TCP listener on Linux when the kernel supports it (GODEBUG
// multipathtcp=2, "listeners only"). The proof-of-concept root exploit for
// the Linux kernel's IPv4 TCP use-after-free (CVE-2026-98432, October 2026;
// golang/go#82717) was demonstrated against exactly such a listener, and
// this server listens on a public address of a VPS. Plain TCP is hit by the
// same kernel bug, so the real fix is a patched kernel -- but there is no
// reason to hand an attacker the easier path as well. Nothing here needs
// MPTCP: it is a single-path control channel.
//
// The directive lives in go.mod (not in one main package) so every binary
// of the module -- the router agent included -- gets it, and so a new
// listener added anywhere cannot silently bring MPTCP back.
func TestListenersDoNotUseMPTCP(t *testing.T) {
	var lc net.ListenConfig
	if lc.MultipathTCP() {
		t.Fatal("net.ListenConfig would open an MPTCP listener; go.mod must keep `godebug multipathtcp=0`")
	}
}
