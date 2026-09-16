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
