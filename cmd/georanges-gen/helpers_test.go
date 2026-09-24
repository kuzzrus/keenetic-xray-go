package main

import (
	"encoding/binary"
	"net"
)

// Small shared helpers for this command's tests -- kept out of main.go
// so the production binary carries nothing that only tests need.

func ipv4(s string) uint32 {
	return binary.BigEndian.Uint32(net.ParseIP(s).To4())
}

func renderNets(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}

// addresses totals how many addresses a set of CIDR strings covers, so a
// test can assert a decomposition covers exactly the requested range --
// no more (which would exclude somebody else's addresses from the
// tunnel) and no less.
func addresses(cidrs []string) int {
	total := 0
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		total += 1 << (bits - ones)
	}
	return total
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// covers reports whether any of nets contains ip -- the assertion that
// actually matters for the veto, as opposed to matching a CIDR string
// that merely looks right.
func covers(nets []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(ip)
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}
