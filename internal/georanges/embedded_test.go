package georanges

import "testing"

// TestEmbedded_HasSubstantialData catches the file going missing or
// being accidentally truncated by a bad regeneration -- an empty or
// tiny embedded snapshot would defeat the entire point of having one
// (see embedded.go's own doc comment for why this exists at all).
func TestEmbedded_HasSubstantialData(t *testing.T) {
	table := Embedded()
	if got := table.Len(); got < 5000 {
		t.Fatalf("Embedded().Len() = %d, want at least 5000 -- looks truncated", got)
	}
}

// TestEmbedded_MatchesRealAddresses spot-checks a few addresses this
// project has directly confirmed are Russian-registered and covered by
// this data source this session (Yandex, Ozon, T-Bank ranges).
func TestEmbedded_MatchesRealAddresses(t *testing.T) {
	table := Embedded()
	for _, ip := range []string{
		"213.180.193.76", // Yandex, 213.180.192.0/19
		"158.160.138.33", // Yandex Cloud, 158.160.0.0/16
		"185.73.193.68",  // Ozon, 185.73.192.0/22
		"178.130.128.21", // T-Bank, 178.130.128.0/23
	} {
		if _, ok := table.Lookup(ip); !ok {
			t.Errorf("Lookup(%s): want a match, got none", ip)
		}
	}
}

// TestEmbedded_CoversTheIncidentAddress is the regression that made the
// ASN layer necessary, asserted against the shipped data file rather
// than a fixture -- a unit test on hand-written input cannot notice the
// real list losing this range again.
//
// 138.124.255.106 is the user's own Russian-hosted backup VPN server.
// The delegated-stats row covering it reads CH (a legacy 1993 block
// sub-assigned to a Russian customer and never restated at the registry
// layer), so for as long as this file came from delegated-stats alone it
// contained nothing at all in 138.124.0.0/16 and the veto never fired.
// Its origin AS214891 is plainly RU in those same files, which is what
// cmd/georanges-gen's second layer now picks up. See that command's doc
// comment and the russia-ip-exclusion-plan memory.
func TestEmbedded_CoversTheIncidentAddress(t *testing.T) {
	table := Embedded()
	const incident = "138.124.255.106"
	cidr, ok := table.Lookup(incident)
	if !ok {
		t.Fatalf("Lookup(%s): no match -- the ASN layer is missing from the shipped list", incident)
	}
	t.Logf("%s matched %s", incident, cidr)

	// And the block-level veto has to see it too: a neighbour's /24
	// promotion is what actually dragged this address into the tunnel.
	if !table.Overlaps("138.124.255.0/24") {
		t.Error("Overlaps(138.124.255.0/24) = false -- a neighbouring promotion would still sweep the address in")
	}
}

// TestEmbedded_CoversRegistryOnlyRanges guards the other direction: the
// ASN layer is additive, and a regeneration that somehow shipped only
// iptoasn's view would quietly drop allocated-but-unannounced space the
// registry layer legitimately claims.
func TestEmbedded_CoversRegistryOnlyRanges(t *testing.T) {
	table := Embedded()
	if got := table.Len(); got < 8000 {
		t.Errorf("Embedded().Len() = %d, want at least 8000 -- the union of both layers should be larger than either", got)
	}
}
