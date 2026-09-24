// Package georanges maintains a small local lookup table of IPv4 ranges
// registered to Russia (sourced from HackingGate/Country-IP-Blocks,
// github.com/HackingGate/Country-IP-Blocks, Unlicense, itself derived
// from the delegated-stats files all 5 RIRs publish -- including RIPE
// NCC's own delegated-ripencc-latest -- refreshed on weekdays).
// internal/classifier consults it (via an injected ExcludedRangeLookup,
// same shape internal/knownranges' own KnownRangeLookup already
// established) to veto a destination from ever becoming an adaptive-
// routing candidate at all: the feature exists to route around foreign
// DPI blocks, and a Russian-hosted false positive (a LAN health-check
// probing an unrelated protocol, a transient stall, ...) should never
// have been eligible in the first place. See the russia-ip-exclusion-plan
// memory for the incident this closes (the user's own Russian-hosted
// backup VPN server kept getting swept into the tunnel) and the
// data-source evaluation.
//
// Deliberately its own package rather than a second table inside
// internal/knownranges: same fetch+cache+parse+singleton shape (and
// FetchRaw/LoadCacheRaw/SaveCacheRaw are reused directly from there --
// see cmd/keenetic-xray/georanges.go -- already fully generic over
// source URL and cache path, no reason to duplicate them), but this
// dataset is roughly an order of magnitude larger than knownranges' own
// (~11k entries vs. a few hundred) and, unlike KnownRangeLookup
// (consulted once per threshold-crossing block inside ClrBlockPromote, a
// rare event), ExcludedRangeLookup is consulted once per LAN flow on
// every classifyInterval tick (500ms, cmd/keenetic-xray/adaptiveroute.go)
// -- a plain linear scan at that call frequency and dataset size risks
// the same kind of real CPU cost this project already hit once on this
// exact router class (l7sni's NFLOG capture, see l7sni-build-plan
// memory). Table buckets its entries by first IPv4 octet instead of
// scanning the whole set on every Lookup.
package georanges

import (
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync/atomic"
)

// Table is a loaded, ready-to-query set of Russian CIDR ranges, bucketed
// by first IPv4 octet. The zero value (and a nil *Table) is empty and
// safe to call Lookup/Len on -- callers don't need a nil check before
// the first successful load, same as internal/knownranges.Table.
type Table struct {
	buckets [256][]*net.IPNet
	count   int // distinct CIDR entries -- NOT sum(len(buckets)), a wide entry occupies more than one bucket
}

// Lookup returns the Russian range containing ip, if any. Only scans
// buckets[ip's first octet] rather than the full set -- see the package
// doc comment for why that matters here. The source file is one flat,
// RIR-delegation-derived list with no expectation of overlaps, so the
// first match within the bucket is treated as authoritative, same
// convention as internal/knownranges.Table.Lookup.
func (t *Table) Lookup(ip string) (cidr string, ok bool) {
	if t == nil {
		return "", false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	v4 := parsed.To4()
	if v4 == nil {
		return "", false
	}
	for _, n := range t.buckets[v4[0]] {
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
	return t.count
}

// Parse builds a Table from raw text, one CIDR per line -- the exact
// shape of HackingGate/Country-IP-Blocks' own RU_IPv4.txt. Blank lines
// and lines starting with "#" are skipped, tolerant of minor format
// changes upstream since this project doesn't control that source. IPv6
// entries are silently dropped: internal/classifier and internal/
// adaptiveroute are IPv4-only throughout (RU_IPv6.txt exists upstream
// but nothing downstream could use it), same reasoning as internal/
// knownranges.Parse. Unparseable input yields an empty, non-nil Table
// rather than an error -- treated the same as "no data yet" by every
// caller.
func Parse(raw string) *Table {
	t := &Table{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil || n.IP.To4() == nil {
			continue
		}
		t.count++
		for _, octet := range spanningFirstOctets(n) {
			t.buckets[octet] = append(t.buckets[octet], n)
		}
	}
	// Sort purely for deterministic test output and diag dumps -- Lookup
	// itself doesn't rely on any ordering, same reasoning as internal/
	// knownranges.Parse.
	for i := range t.buckets {
		b := t.buckets[i]
		sort.Slice(b, func(i, j int) bool { return b[i].String() < b[j].String() })
	}
	return t
}

// spanningFirstOctets returns every first-IPv4-octet value n's network
// touches. Almost always exactly one -- every entry in this project's
// actual RU_IPv4.txt source is /22 or narrower -- but computed correctly
// for a hypothetically wider entry too (a /7 spans two, a /6 spans four,
// and so on) rather than assuming and silently mis-bucketing it.
func spanningFirstOctets(n *net.IPNet) []int {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	v4 := n.IP.To4()
	if ones >= 8 {
		return []int{int(v4[0])}
	}
	base := binary.BigEndian.Uint32(v4)
	last := base + (uint32(1) << uint(32-ones)) - 1
	first, end := int(base>>24), int(last>>24)
	octets := make([]int, 0, end-first+1)
	for o := first; o <= end; o++ {
		octets = append(octets, o)
	}
	return octets
}

// current is the process-wide "latest successfully loaded table", same
// atomic-swap precedent as internal/knownranges' own current.
var current atomic.Pointer[Table]

// SetCurrent stores t as what Lookup/CurrentLen report from now on.
// Called by cmd/keenetic-xray's georangesRefreshLoop after a successful
// load -- this package never calls it on its own.
func SetCurrent(t *Table) { current.Store(t) }

// Lookup consults the current table -- the exact shape internal/
// classifier.Config.ExcludedRangeLookup wants, so a caller can wire
// georanges.Lookup in directly instead of writing an adapter closure.
// Safe to call before any successful load: current.Load() then returns
// a nil *Table, and Table.Lookup on a nil receiver just reports no
// match.
func Lookup(ip string) (cidr string, ok bool) { return current.Load().Lookup(ip) }

// CurrentLen reports how many ranges the current table holds, for
// status/diag reporting (0 before the first successful load).
func CurrentLen() int { return current.Load().Len() }

// Overlaps reports whether cidr intersects any Russian range in t. The
// per-flow Lookup above answers "is this one address Russian"; this
// answers "does this whole network touch Russian space", which is a
// different question with a different caller: internal/classifier's
// ClrBlockPromote, which redirects an entire CIDR at once.
//
// That distinction is the whole reason this method exists. The veto
// Lookup backs is applied during classification, to individual flows --
// but ClrBlockPromote widens a threshold-crossing block into a single
// ipset entry covering every address inside it, and the kernel's
// REDIRECT rule then matches all of them. A Russian address sitting in
// a promoted neighbour's /24 (or, via a known-range match, its /18) was
// therefore still swept into the tunnel with the veto working exactly
// as designed and never consulted. Mixed legacy space makes that the
// normal case rather than a corner one: 138.124.0.0/17 alone is split
// between 36 ASNs, 7 of them Russian, across 82 separate /24s.
//
// Returns false for an unparseable or non-IPv4 cidr -- a caller that
// cannot describe the block it wants to promote gets no veto, same
// tolerant-of-bad-input convention as Lookup and Parse.
func (t *Table) Overlaps(cidr string) bool {
	if t == nil {
		return false
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || n.IP.To4() == nil {
		return false
	}
	for _, octet := range spanningFirstOctets(n) {
		for _, ru := range t.buckets[octet] {
			// Two CIDRs are aligned prefixes: they are either disjoint
			// or one contains the other's base address, so checking
			// containment both ways is a complete overlap test.
			if ru.Contains(n.IP) || n.Contains(ru.IP) {
				return true
			}
		}
	}
	return false
}

// Overlaps consults the current table, the package-level counterpart to
// Lookup -- the exact shape internal/classifier.Config.
// ExcludedRangeOverlap wants, wired in directly with no adapter. Safe
// before any successful load for the same reason Lookup is.
func Overlaps(cidr string) bool { return current.Load().Overlaps(cidr) }
