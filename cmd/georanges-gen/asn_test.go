package main

import (
	"strings"
	"testing"
)

func TestParseDelegatedASNs_PicksOnlyTheRequestedCountry(t *testing.T) {
	in := strings.Join([]string{
		"2|ripencc|1700000000|12345|19830101|20260916|+0000", // header
		"ripencc|*|asn|*|9999|summary",                       // summary row
		"ripencc|RU|asn|214891|1|20240516|allocated",
		"ripencc|DE|asn|3320|1|19930901|allocated",         // wrong country
		"ripencc|RU|ipv4|2.56.24.0|512|20190821|allocated", // wrong type
		"# a comment",
	}, "\n")

	got, err := parseDelegatedASNs(strings.NewReader(in), "RU")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[214891] {
		t.Errorf("got %v, want exactly {214891}", got)
	}
}

// TestParseDelegatedASNs_ExpandsABlock: an asn row's value is a count of
// consecutive AS numbers, same as an ipv4 row's value is a count of
// addresses. Reading it as "just the one" would silently drop the rest
// of an allocated block, and every prefix those ASNs originate with it.
func TestParseDelegatedASNs_ExpandsABlock(t *testing.T) {
	in := "ripencc|RU|asn|64512|3|20240516|allocated"
	got, err := parseDelegatedASNs(strings.NewReader(in), "RU")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []uint64{64512, 64513, 64514} {
		if !got[want] {
			t.Errorf("AS%d missing from %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d ASNs, want exactly 3: %v", len(got), got)
	}
}

// TestParseIPToASN_TheIncidentAddress is the regression this whole
// second layer exists for. 138.124.255.106 is registered to Russia only
// at RIPE's per-inetnum layer; the delegated-stats row covering it says
// CH, so the registry layer alone never sees it and the veto never
// fired -- the user's own Russian-hosted backup VPN server kept being
// swept into the tunnel. Its origin AS214891 *is* plainly RU in the same
// delegated-stats files, which is what makes this recoverable at all.
func TestParseIPToASN_TheIncidentAddress(t *testing.T) {
	in := "138.124.254.0\t138.124.255.255\t214891\tRU\tDENALE-NET"
	nets, rejected, err := parseIPToASN(strings.NewReader(in), "RU", map[uint64]bool{214891: true})
	if err != nil {
		t.Fatal(err)
	}
	if rejected != 0 {
		t.Errorf("rejected %d rows, want 0", rejected)
	}
	got := renderNets(nets)
	if want := []string{"138.124.254.0/23"}; !equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if !covers(nets, "138.124.255.106") {
		t.Error("the produced range does not contain 138.124.255.106 -- the exact address this layer exists to cover")
	}
}

// TestParseIPToASN_CrossCheckRejects: a row iptoasn calls RU whose ASN
// the delegated-stats files do *not* register to RU is dropped and
// counted, not quietly trusted. Both sources derive that country the
// same way, so a disagreement means one of them is stale or broken.
func TestParseIPToASN_CrossCheckRejects(t *testing.T) {
	in := strings.Join([]string{
		"1.0.0.0\t1.0.0.255\t111\tRU\tAGREED",
		"2.0.0.0\t2.0.0.255\t222\tRU\tNOT-RU-IN-DELEGATED",
	}, "\n")

	nets, rejected, err := parseIPToASN(strings.NewReader(in), "RU", map[uint64]bool{111: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.0.0.0/24"}; !equal(renderNets(nets), want) {
		t.Errorf("got %v, want %v", renderNets(nets), want)
	}
	if rejected != 1 {
		t.Errorf("rejected %d rows, want 1", rejected)
	}
}

// TestParseIPToASN_SkipsNoiseWithoutCountingItRejected: a wrong-country
// row was never a candidate, and ASN 0 marks space with no origin at
// all -- neither is evidence of the two sources disagreeing, so neither
// may inflate the rejection count that exists to make real drift
// visible in the build log.
func TestParseIPToASN_SkipsNoiseWithoutCountingItRejected(t *testing.T) {
	in := strings.Join([]string{
		"3.0.0.0\t3.0.0.255\t333\tDE\tWRONG-COUNTRY",
		"4.0.0.0\t4.0.0.255\t0\tRU\tNO-ORIGIN",
		"5.0.0.0\t5.0.0.255\t555\tNone\tNOT-ROUTED",
		"6.0.0.255\t6.0.0.0\t111\tRU\tREVERSED-RANGE",
		"malformed",
	}, "\n")

	nets, rejected, err := parseIPToASN(strings.NewReader(in), "RU", map[uint64]bool{111: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 0 {
		t.Errorf("got %v, want nothing", renderNets(nets))
	}
	if rejected != 0 {
		t.Errorf("rejected %d rows, want 0 -- noise is not disagreement", rejected)
	}
}

// TestCoalesce_AbsorbsTheASNLayerIntoTheRegistryLayer is the normal
// shape of the union: the registry already claims a wide allocation and
// the ASN layer reports individual /24s inside it. Keeping both would
// bloat the committed file and lengthen every per-flow Lookup bucket
// scan for no added coverage.
func TestCoalesce_AbsorbsTheASNLayerIntoTheRegistryLayer(t *testing.T) {
	nets := cidrsForRange(ipv4("5.255.0.0"), 65536) // registry /16
	nets = append(nets, cidrsForRange(ipv4("5.255.192.0"), 256)...)
	nets = append(nets, cidrsForRange(ipv4("5.255.193.0"), 256)...)

	got := renderNets(coalesce(nets))
	if want := []string{"5.255.0.0/16"}; !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestCoalesce_MergesAdjacentAndKeepsDisjoint: touching ranges are one
// range (that is the whole point -- the two layers meet at boundaries
// constantly), but a real gap between them must survive, or the veto
// would start covering addresses neither source ever claimed.
func TestCoalesce_MergesAdjacentAndKeepsDisjoint(t *testing.T) {
	nets := cidrsForRange(ipv4("10.0.0.0"), 256)
	nets = append(nets, cidrsForRange(ipv4("10.0.1.0"), 256)...) // exactly adjacent
	nets = append(nets, cidrsForRange(ipv4("10.0.9.0"), 256)...) // gap before this

	got := renderNets(coalesce(nets))
	want := []string{"10.0.0.0/23", "10.0.9.0/24"}
	if !equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if total := addresses(got); total != 768 {
		t.Errorf("coalesced set covers %d addresses, want 768", total)
	}
}

// TestCoalesce_PartialOverlapKeepsTheUnion: neither input contains the
// other, so the result has to span both -- dropping either end would
// silently shrink the veto.
func TestCoalesce_PartialOverlapKeepsTheUnion(t *testing.T) {
	nets := cidrsForRange(ipv4("10.0.0.0"), 512)
	nets = append(nets, cidrsForRange(ipv4("10.0.1.0"), 512)...)

	got := renderNets(coalesce(nets))
	if total := addresses(got); total != 768 {
		t.Errorf("got %v covering %d addresses, want 768 (10.0.0.0-10.0.2.255)", got, total)
	}
	if !covers(coalesce(nets), "10.0.2.255") || !covers(coalesce(nets), "10.0.0.0") {
		t.Errorf("got %v, which does not span both inputs", got)
	}
}

func TestTotalAddresses(t *testing.T) {
	nets := cidrsForRange(ipv4("10.0.0.0"), 256)
	nets = append(nets, cidrsForRange(ipv4("11.0.0.0"), 1024)...)
	if got := totalAddresses(nets); got != 1280 {
		t.Errorf("got %d, want 1280", got)
	}
}
