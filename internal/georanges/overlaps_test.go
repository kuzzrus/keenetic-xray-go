package georanges

import "testing"

const overlapTable = `
138.124.254.0/23
5.255.192.0/18
77.88.0.0/24
`

func TestOverlaps_ContainedBothWays(t *testing.T) {
	tbl := Parse(overlapTable)

	// The promoted block sits inside a Russian range.
	if !tbl.Overlaps("138.124.255.0/24") {
		t.Error("a /24 inside a listed /23 must count as overlapping")
	}
	// The promoted block swallows a Russian range -- the widening case
	// that motivated this method, where a KnownRangeLookup match drags
	// in far more than the service that tripped the promotion.
	if !tbl.Overlaps("138.124.0.0/16") {
		t.Error("a /16 containing a listed /23 must count as overlapping")
	}
	// Exact match.
	if !tbl.Overlaps("77.88.0.0/24") {
		t.Error("an exactly-listed range must count as overlapping")
	}
}

func TestOverlaps_DisjointIsClean(t *testing.T) {
	tbl := Parse(overlapTable)

	for _, cidr := range []string{
		"138.124.0.0/24",   // same first octet, different bucket neighbour
		"138.124.252.0/23", // directly adjacent, below
		"8.8.8.0/24",
		"77.88.1.0/24", // adjacent, above
	} {
		if tbl.Overlaps(cidr) {
			t.Errorf("Overlaps(%q) = true, want false -- nothing Russian is in it", cidr)
		}
	}
}

// TestOverlaps_SpansMultipleBuckets: the table buckets by first octet,
// so a block wide enough to cross octet boundaries has to be checked
// against every bucket it touches. Missing that would silently let a
// wide promotion through -- exactly the case with the most addresses at
// stake.
func TestOverlaps_SpansMultipleBuckets(t *testing.T) {
	tbl := Parse(overlapTable)
	if !tbl.Overlaps("76.0.0.0/6") { // 76.0.0.0 - 79.255.255.255, covers 77.88.0.0/24
		t.Error("a /6 spanning four first-octets must still find the listed range inside it")
	}
	if !tbl.Overlaps("4.0.0.0/6") { // 4.0.0.0 - 7.255.255.255, covers 5.255.192.0/18
		t.Error("a /6 spanning four first-octets must still find 5.255.192.0/18")
	}
}

func TestOverlaps_NilAndEmptyAreSafe(t *testing.T) {
	var nilTable *Table
	if nilTable.Overlaps("1.2.3.0/24") {
		t.Error("a nil Table must report no overlap, not panic")
	}
	if Parse("").Overlaps("1.2.3.0/24") {
		t.Error("an empty Table must report no overlap")
	}
}

// TestOverlaps_BadInputIsNoVeto: a caller that cannot describe the block
// it wants to promote gets no veto rather than a blanket one, matching
// Lookup's and Parse's own tolerance of malformed input.
func TestOverlaps_BadInputIsNoVeto(t *testing.T) {
	tbl := Parse(overlapTable)
	for _, bad := range []string{"", "not-a-cidr", "138.124.255.106", "2a00::/32"} {
		if tbl.Overlaps(bad) {
			t.Errorf("Overlaps(%q) = true, want false", bad)
		}
	}
}

// TestOverlaps_TheIncidentBlock ties the method back to the case it
// exists for: a /24 promotion next door to the user's own Russian-hosted
// server, and the /18 a known-range match would have widened it to, must
// both be refused.
func TestOverlaps_TheIncidentBlock(t *testing.T) {
	tbl := Parse(overlapTable)
	if !tbl.Overlaps("138.124.255.0/24") {
		t.Error("the /24 holding 138.124.255.106 must be flagged")
	}
	if !tbl.Overlaps("138.124.192.0/18") {
		t.Error("the /18 a known-range widening would reach must be flagged")
	}
}

func TestPackageOverlaps_UsesCurrentTable(t *testing.T) {
	prev := current.Load()
	t.Cleanup(func() { current.Store(prev) })

	SetCurrent(Parse(overlapTable))
	if !Overlaps("138.124.255.0/24") {
		t.Error("package-level Overlaps should consult the current table")
	}
	if Overlaps("8.8.8.0/24") {
		t.Error("package-level Overlaps should not match an unlisted block")
	}
}
