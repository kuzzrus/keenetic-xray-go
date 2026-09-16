package georanges

import "testing"

func TestParse_LookupFindsContainingRange(t *testing.T) {
	table := Parse(`
# comment line, ignored
2.56.24.0/23
5.61.16.0/20

8.8.8.0/24
`)
	if got := table.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	cidr, ok := table.Lookup("2.56.25.1")
	if !ok || cidr != "2.56.24.0/23" {
		t.Fatalf("Lookup(2.56.25.1) = %q, %v, want 2.56.24.0/23, true", cidr, ok)
	}

	cidr, ok = table.Lookup("5.61.20.9")
	if !ok || cidr != "5.61.16.0/20" {
		t.Fatalf("Lookup(5.61.20.9) = %q, %v, want 5.61.16.0/20, true", cidr, ok)
	}
}

func TestParse_LookupNoMatch(t *testing.T) {
	table := Parse("8.8.8.0/24\n")
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup(1.2.3.4) matched, want no match")
	}
}

func TestParse_LookupWrongBucketNeverMatches(t *testing.T) {
	// An address sharing every octet except the first must not fall
	// through to some other bucket's entries -- the whole point of
	// bucketing by first octet is that buckets stay disjoint.
	table := Parse("2.56.24.0/23\n")
	if _, ok := table.Lookup("9.56.24.5"); ok {
		t.Fatal("Lookup(9.56.24.5) matched a 2.x/23 entry, want no match")
	}
}

func TestParse_SkipsBlankCommentAndIPv6Lines(t *testing.T) {
	table := Parse("\n# header\n8.8.8.0/24\n2001:4860::/32\n\n")
	if got := table.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1 (IPv6 line should be skipped)", got)
	}
}

func TestParse_SkipsUnparseableLines(t *testing.T) {
	table := Parse("not-a-cidr\n8.8.8.0\n8.8.8.0/24\n")
	if got := table.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	table := Parse("")
	if got := table.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup on empty table matched, want no match")
	}
}

// TestParse_WideEntrySpansMultipleBuckets covers spanningFirstOctets'
// general case: a real RU_IPv4.txt entry is always /22 or narrower (one
// bucket), but Parse must still bucket a hypothetically wider entry
// correctly rather than silently only matching part of its range.
func TestParse_WideEntrySpansMultipleBuckets(t *testing.T) {
	table := Parse("6.0.0.0/7\n") // covers 6.0.0.0 - 7.255.255.255, two first octets
	if got := table.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1 (one CIDR entry, even though it spans two buckets)", got)
	}
	for _, ip := range []string{"6.1.2.3", "7.254.1.1"} {
		if _, ok := table.Lookup(ip); !ok {
			t.Errorf("Lookup(%s) = no match, want a match against 6.0.0.0/7", ip)
		}
	}
	if _, ok := table.Lookup("8.0.0.1"); ok {
		t.Error("Lookup(8.0.0.1) matched, want no match (just past the /7's range)")
	}
}

// TestParse_LookupMatchesTheIncidentAddress uses the real RIPE
// sub-allocation (138.124.255.0/24, "Cloudrix Infrastructure", RU --
// confirmed via RIPEstat/whois) covering 138.124.255.106, the user's own
// backup VPN server that kept getting swept into the adaptive-route
// tunnel and prompted this whole feature. Confirms the lookup mechanism
// itself is correct against a real, meaningful address, not just
// synthetic ones.
//
// NOTE: this /24 does NOT currently appear in this package's real
// upstream source (HackingGate/Country-IP-Blocks) -- it derives only
// from the coarse top-level RIPE delegated-stats file, which still
// attributes this address's containing legacy block (138.124.0.0/15) to
// a 1993 Swiss allocation, not the modern per-customer RU
// sub-assignment RDAP/whois shows today. See the russia-ip-exclusion-plan
// memory for what that gap means for this feature's real-world coverage
// of the address that originally motivated it.
func TestParse_LookupMatchesTheIncidentAddress(t *testing.T) {
	table := Parse("138.124.255.0/24\n")
	cidr, ok := table.Lookup("138.124.255.106")
	if !ok || cidr != "138.124.255.0/24" {
		t.Fatalf("Lookup(138.124.255.106) = %q, %v, want 138.124.255.0/24, true", cidr, ok)
	}
}

func TestTable_NilIsSafeAndEmpty(t *testing.T) {
	var table *Table
	if got := table.Len(); got != 0 {
		t.Fatalf("nil Table.Len() = %d, want 0", got)
	}
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("nil Table.Lookup matched, want no match")
	}
}

func TestTable_LookupUnparseableIP(t *testing.T) {
	table := Parse("8.8.8.0/24\n")
	if _, ok := table.Lookup("not-an-ip"); ok {
		t.Fatal("Lookup(not-an-ip) matched, want no match")
	}
}

// resetCurrent restores the process-wide table to empty after a test
// that calls SetCurrent -- current is package state, shared across every
// test in this package.
func resetCurrent(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetCurrent(nil) })
}

func TestCurrent_NothingLoadedYet(t *testing.T) {
	resetCurrent(t)
	SetCurrent(nil)

	if got := CurrentLen(); got != 0 {
		t.Fatalf("CurrentLen() = %d, want 0", got)
	}
	if _, ok := Lookup("8.8.8.8"); ok {
		t.Fatal("Lookup with nothing loaded: want no match, got one")
	}
}

func TestCurrent_SetCurrentThenLookup(t *testing.T) {
	resetCurrent(t)
	SetCurrent(Parse("8.8.8.0/24\n"))

	if got := CurrentLen(); got != 1 {
		t.Fatalf("CurrentLen() = %d, want 1", got)
	}
	cidr, ok := Lookup("8.8.8.8")
	if !ok || cidr != "8.8.8.0/24" {
		t.Fatalf("Lookup(8.8.8.8) = %q, %v, want 8.8.8.0/24, true", cidr, ok)
	}
	if _, ok := Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup(1.2.3.4): want no match against an unrelated table")
	}
}
