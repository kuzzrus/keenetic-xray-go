// Package knownranges maintains a small local lookup table of publicly
// known infrastructure IPv4 ranges (major clouds/CDNs -- AWS, Cloudflare,
// Google, Meta/Facebook, ...), sourced from lord-alfred/ipranges (github
// .com/lord-alfred/ipranges, CC0-1.0, daily-updated). internal/classifier's
// ClrBlockPromote consults it (via an injected Lookup, keeping that
// package free of any I/O of its own -- see its package doc comment) so a
// confirmed destination that falls inside a known range gets promoted to
// that range's real boundary instead of a blind fixed-width guess: a
// large provider's actual allocation is often much wider than one /24,
// and a guess that's too narrow just means the next sibling address in
// the same real range has to earn its own promotion from scratch.
//
// This package itself never fetches anything on its own -- FetchRaw/
// LoadCacheRaw/SaveCacheRaw are plain functions the caller (cmd/keenetic-
// xray's refresh loop) drives explicitly, same division of responsibility
// as internal/presets' own Refresh vs. its caller's presetRefreshLoop.
//
// The one bit of state this package *does* keep for itself, same
// precedent as internal/presets' own overlayDir/reload: SetCurrent/
// Lookup/CurrentLen, a process-wide "whatever table was loaded most
// recently" -- so every caller across process boundaries within the
// same binary (cmd/keenetic-xray's classify loop, and potentially
// internal/botcontrol's status screens) sees the same data without each
// having to keep its own copy or thread one through by hand.
package knownranges

import (
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

// Table is a loaded, ready-to-query set of known CIDR ranges. The zero
// value (and a nil *Table) is empty and safe to call Lookup/Len on --
// callers don't need a nil check before the first successful load.
type Table struct {
	nets []*net.IPNet
}

// Lookup returns the known range containing ip, if any. The source file
// is already deduplicated per-provider and providers don't overlap in
// practice, so the first match is treated as authoritative -- no attempt
// to find a "widest" or "narrowest" match among several.
func (t *Table) Lookup(ip string) (cidr string, ok bool) {
	if t == nil {
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	for _, n := range t.nets {
		if n.Contains(parsed) {
			return n.String(), true
		}
	}
	return "", false
}

// Len reports how many ranges are loaded, for status/diag reporting.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.nets)
}

// Parse builds a Table from raw text, one CIDR per line -- the exact
// shape of lord-alfred/ipranges' all/ipv4_merged.txt. Blank lines and
// lines starting with "#" are skipped, tolerant of minor format changes
// upstream since this project doesn't control that source. IPv6 entries
// are silently dropped: internal/classifier and internal/adaptiveroute
// are IPv4-only throughout, so keeping them would only waste scan time.
// Unparseable input yields an empty, non-nil Table rather than an error
// -- treated the same as "no data yet" by every caller.
func Parse(raw string) *Table {
	var nets []*net.IPNet
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil || n.IP.To4() == nil {
			continue
		}
		nets = append(nets, n)
	}
	// Sort purely for deterministic test output and diag dumps -- Lookup
	// itself doesn't rely on any ordering.
	sort.Slice(nets, func(i, j int) bool { return nets[i].String() < nets[j].String() })
	return &Table{nets: nets}
}

// current is the process-wide "latest successfully loaded table",
// swapped wholesale by SetCurrent. atomic.Pointer rather than a mutex:
// Lookup can be called many times per classify tick (internal/
// classifier.ClrBlockPromote, once per threshold-crossing block) from
// the daemon's own goroutine, with nothing to coordinate beyond "hand
// back whatever table is current right now."
var current atomic.Pointer[Table]

// SetCurrent stores t as what Lookup/CurrentLen report from now on.
// Called by whatever drives FetchRaw/LoadCacheRaw (cmd/keenetic-xray's
// refresh loop) after a successful load -- this package never calls it
// on its own.
func SetCurrent(t *Table) { current.Store(t) }

// Lookup consults the current table -- the exact shape internal/
// classifier.Config.KnownRangeLookup wants, so a caller can wire
// knownranges.Lookup in directly instead of writing an adapter closure.
// Safe to call before any successful load: current.Load() then returns
// a nil *Table, and Table.Lookup on a nil receiver just reports no
// match.
func Lookup(ip string) (cidr string, ok bool) { return current.Load().Lookup(ip) }

// CurrentLen reports how many ranges the current table holds, for
// status/diag reporting (0 before the first successful load).
func CurrentLen() int { return current.Load().Len() }
