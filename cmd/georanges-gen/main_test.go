package main

import (
	"strings"
	"testing"
)

// TestCidrsForRange_PowerOfTwoIsOneBlock: the ordinary case, where the
// count already is a power of two and the start is aligned.
func TestCidrsForRange_PowerOfTwoIsOneBlock(t *testing.T) {
	got := renderNets(cidrsForRange(ipv4("2.56.24.0"), 512))
	if want := []string{"2.56.24.0/23"}; !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestCidrsForRange_NonPowerOfTwoSplits is the defect this command
// exists to avoid: 1536 addresses is 1024 + 512, i.e. a /22 followed by
// a /23. Naive 32-log2(count) truncation yields a bare /21 -- 2048
// addresses -- over-claiming the 512 that follow the real range.
func TestCidrsForRange_NonPowerOfTwoSplits(t *testing.T) {
	got := renderNets(cidrsForRange(ipv4("10.0.0.0"), 1536))
	want := []string{"10.0.0.0/22", "10.0.4.0/23"}
	if !equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if total := addresses(got); total != 1536 {
		t.Errorf("blocks cover %d addresses, want exactly 1536", total)
	}
}

// TestCidrsForRange_UnalignedStart: a range whose start is not aligned
// to its size must be split at the alignment boundary, smallest block
// first, or the first block would reach back before `start`.
func TestCidrsForRange_UnalignedStart(t *testing.T) {
	got := renderNets(cidrsForRange(ipv4("10.0.1.0"), 512))
	want := []string{"10.0.1.0/24", "10.0.2.0/24"}
	if !equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if total := addresses(got); total != 512 {
		t.Errorf("blocks cover %d addresses, want exactly 512", total)
	}
}

func TestCidrsForRange_SingleAddress(t *testing.T) {
	got := renderNets(cidrsForRange(ipv4("192.0.2.7"), 1))
	if want := []string{"192.0.2.7/32"}; !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestCidrsForRange_NeverCoversMoreThanAsked is the invariant that
// actually matters for the veto: over-claiming would exclude somebody
// else's addresses from the tunnel.
func TestCidrsForRange_NeverCoversMoreThanAsked(t *testing.T) {
	for _, count := range []uint32{1, 3, 5, 100, 255, 256, 1000, 1536, 4097, 65535} {
		got := renderNets(cidrsForRange(ipv4("172.16.3.0"), count))
		if total := addresses(got); total != int(count) {
			t.Errorf("count %d: blocks cover %d addresses (%v)", count, total, got)
		}
	}
}

func TestParseDelegated_PicksOnlyTheRequestedCountryAndIPv4(t *testing.T) {
	in := strings.Join([]string{
		"2|ripencc|1700000000|12345|19830101|20260916|+0000", // header
		"ripencc|*|ipv4|*|9999|summary",                      // summary row
		"ripencc|RU|ipv4|2.56.24.0|512|20190821|allocated",
		"ripencc|DE|ipv4|1.2.3.0|256|20190821|allocated", // wrong country
		"ripencc|RU|ipv6|2a00::|32|20190821|allocated",   // wrong family
		"ripencc|RU|asn|12345|1|20190821|allocated",      // wrong type
		"# a comment",
		"ripencc|RU|ipv4|5.255.192.0|16384|20120101|allocated",
	}, "\n")

	nets, err := parseDelegated(strings.NewReader(in), "RU")
	if err != nil {
		t.Fatal(err)
	}
	got := renderNets(nets)
	want := []string{"2.56.24.0/23", "5.255.192.0/18"}
	if !equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestRender_SortsNumericallyAndDeduplicates: numeric order (not
// lexical) keeps the committed file readable and its day-to-day diffs
// small, and the same range arriving from two registries must appear
// once.
func TestRender_SortsNumericallyAndDeduplicates(t *testing.T) {
	nets := append(cidrsForRange(ipv4("77.88.0.0"), 256), cidrsForRange(ipv4("5.255.192.0"), 256)...)
	nets = append(nets, cidrsForRange(ipv4("213.180.193.0"), 256)...)
	nets = append(nets, cidrsForRange(ipv4("5.255.192.0"), 256)...) // duplicate
	nets = append(nets, cidrsForRange(ipv4("100.64.0.0"), 256)...)

	out := render(nets)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	want := []string{"5.255.192.0/24", "77.88.0.0/24", "100.64.0.0/24", "213.180.193.0/24"}
	if !equal(lines, want) {
		t.Errorf("got %v, want %v (numeric order, deduplicated)", lines, want)
	}
	if !strings.HasPrefix(out, "# RU IPv4 ranges") {
		t.Error("output should lead with the do-not-edit header")
	}
}
