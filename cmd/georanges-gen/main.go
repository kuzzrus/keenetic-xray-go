// Command georanges-gen regenerates internal/georanges/data/ru-ipv4.txt
// from the RIR delegated-statistics files -- the authoritative record of
// which address ranges are registered to which country -- plus an
// ASN-derived second layer covering what the registry layer
// structurally cannot (see "Why a second, ASN-derived layer" below).
//
// Why this lives in our own repo at all, rather than pointing
// internal/georanges at somebody else's generated list: the list has to
// be reachable *from a router in Russia*, and the third-party host this
// originally used (country-ip-blocks.hackinggate.com, GitHub Pages
// behind a custom domain) simply is not -- confirmed live 2026-09-16,
// every fetch died with "context deadline exceeded ... while awaiting
// headers", leaving the Russian-exclusion veto silently inert. This
// project already fetches its own installer and preset data from
// raw.githubusercontent.com and that path demonstrably works, so
// generating the list here and serving it from the repo removes an
// entire class of failure. See the russia-ip-exclusion-plan memory.
//
// It also fixes a real defect in the upstream generator we were relying
// on. Delegated-stats rows carry a *count of addresses*, not a prefix
// length, and that count is not always a power of two; computing
// `32 - log2(count)` and truncating (what HackingGate's own awk does)
// turns a 1536-address range into a /21, over-claiming 512 addresses
// that belong to somebody else. cidrsForRange below decomposes such a
// range into correctly aligned CIDRs instead.
//
// # Why a second, ASN-derived layer
//
// Delegated-stats records the country of the *top-level allocation* and
// never restates it when a block is sub-assigned to a customer in
// another country. Legacy space carved up in the 1990s is therefore
// systematically mis-attributed. The row covering 138.124.255.106 reads
//
//	ripencc|CH|ipv4|138.124.240.0|4096|19930901|assigned
//
// -- Switzerland -- while RIPE's own database puts "country: RU" on that
// /24, and the surrounding legacy /17 is in practice split between 36
// ASNs, 7 of them Russian, across 82 separate /24s. The registry layer
// sees none of that, so the veto never fired on the user's own
// Russian-hosted backup VPN server and it kept being swept into the
// tunnel -- the incident in the russia-ip-exclusion-plan memory.
//
// The fix reuses data this command already downloads. The same
// delegated-stats files also record which country every *AS number* is
// registered to -- AS214891, the origin of that /24, is plainly
// "ripencc|RU|asn|214891|1|20240516|allocated" -- so the only missing
// piece is a prefix-to-origin-ASN map. iptoasn.com publishes exactly
// that: rebuilt hourly, one 7 MB file, public domain (PDDL v1.0). That
// combination is why it wins over the alternatives evaluated alongside
// it -- Loyalsoldier/geoip's plain-text ru.txt is CC-BY-SA-4.0
// (share-alike on a data file this MIT repo redistributes) and rebuilt
// only daily; bgp.tools' full table is 76 MB and non-commercial-use
// only.
//
// A row is accepted only when iptoasn *and* the delegated-stats files
// agree the ASN is Russian. iptoasn derives its own country column the
// same way, from ASN registration, so the two should always agree --
// which is exactly the point: a disagreement means one side is stale or
// broken, and the conservative reading wins. No other candidate source
// offers that cross-check, because no other one is derived from
// something this command already holds.
//
// Both layers are unioned and then coalesced into a minimal set of
// CIDRs, so overlapping claims -- the registry's wide allocation and the
// ASN layer's individual /24s inside it -- collapse into one entry each
// instead of bloating both the file and internal/georanges' in-memory
// buckets.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sources are every RIR's delegated-statistics file. All five, not just
// RIPE NCC: although Russian resources live overwhelmingly in the RIPE
// region, historical transfers leave a handful of RU-attributed rows in
// the other registries' files, and skipping them would quietly drop
// those ranges from the veto.
var sources = []string{
	"https://ftp.ripe.net/ripe/stats/delegated-ripencc-latest",
	"https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
	"https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
	"https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
}

// iptoasnSource is the prefix-to-origin-ASN map backing the second
// layer -- gzipped TSV, "range_start<TAB>range_end<TAB>asn<TAB>country
// <TAB>description". See this command's doc comment for why this source
// specifically.
const iptoasnSource = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

// countryCode is the country whose ranges this generates. A constant
// rather than a flag on purpose: internal/georanges embeds exactly one
// list and its doc comments are written about Russia specifically, so a
// second country would be a deliberate feature, not a CLI invocation.
const countryCode = "RU"

const outPath = "internal/georanges/data/ru-ipv4.txt"

// minRanges guards against committing a truncated list: a partial
// download or an upstream format change that silently matches nothing
// would otherwise replace a good list with a near-empty one, disabling
// the veto exactly as effectively as an unreachable host did. Coalescing
// makes this a count of *merged* ranges, so it no longer tracks the
// registry's own row count.
const minRanges = 5000

// minAddresses is the same guard expressed in address space, and it is
// the one that actually matters. Range count alone can stay healthy
// while coverage collapses: now that entries are coalesced, a source
// degrading into a few huge bogus blocks -- or one whose narrow entries
// all vanish -- can hold its line count and still leave the veto
// useless. Real coverage is around 46-47M addresses across both layers.
const minAddresses = 40_000_000

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "georanges-gen:", err)
		os.Exit(1)
	}
}

func run() error {
	var all []*net.IPNet
	ruASNs := map[uint64]bool{}
	for _, url := range sources {
		raw, err := fetch(url)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		nets, err := parseDelegated(bytes.NewReader(raw), countryCode)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		asns, err := parseDelegatedASNs(bytes.NewReader(raw), countryCode)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		for asn := range asns {
			ruASNs[asn] = true
		}
		fmt.Fprintf(os.Stderr, "%s: %d ranges, %d ASNs\n", url, len(nets), len(asns))
		all = append(all, nets...)
	}
	registryOnly := coalesce(all)

	// The ASN layer is additive and strictly second, but its absence has
	// to be loud rather than silent: shipping only half the data is
	// exactly the failure mode the guards below exist to prevent.
	if len(ruASNs) == 0 {
		return fmt.Errorf("no %s ASNs across %d delegated-stats files -- refusing to skip the ASN layer silently",
			countryCode, len(sources))
	}
	raw, err := fetchGzip(iptoasnSource)
	if err != nil {
		return fmt.Errorf("%s: %w", iptoasnSource, err)
	}
	asnNets, rejected, err := parseIPToASN(bytes.NewReader(raw), countryCode, ruASNs)
	if err != nil {
		return fmt.Errorf("%s: %w", iptoasnSource, err)
	}
	fmt.Fprintf(os.Stderr, "%s: %d ranges from %d %s ASNs (%d rows rejected by the delegated-stats cross-check)\n",
		iptoasnSource, len(asnNets), len(ruASNs), countryCode, rejected)
	all = append(all, asnNets...)

	nets := coalesce(all)
	out := render(nets)
	count := len(nets)
	if count < minRanges {
		return fmt.Errorf("only %d ranges, want at least %d -- refusing to write a suspiciously short list",
			count, minRanges)
	}
	total := totalAddresses(nets)
	if total < minAddresses {
		return fmt.Errorf("only %d addresses covered, want at least %d -- refusing to write a suspiciously thin list",
			total, minAddresses)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d ranges / %d addresses (registry layer alone: %d / %d)\n",
		outPath, count, total, len(registryOnly), totalAddresses(registryOnly))
	return nil
}

func fetch(url string) ([]byte, error) {
	hc := &http.Client{Timeout: 5 * time.Minute} // these files run to tens of MB
	resp, err := hc.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// fetchGzip is fetch plus gunzip. Kept separate rather than sniffing
// inside fetch: the delegated-stats files are served plain, and a gzip
// magic-number sniff would quietly accept a truncated body that happens
// not to start with one.
func fetchGzip(url string) ([]byte, error) {
	raw, err := fetch(url)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// parseDelegated pulls every IPv4 range attributed to cc out of one
// delegated-statistics file. Row format is
// "registry|cc|type|start|value|date|status[|opaque-id]", where for
// ipv4 `value` is a *count of addresses*. Header lines (version/summary)
// and comments are skipped implicitly: they never carry "|ipv4|" with a
// parseable start address.
func parseDelegated(r io.Reader, cc string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	sc := newScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 || f[1] != cc || f[2] != "ipv4" {
			continue
		}
		ip := net.ParseIP(f[3]).To4()
		if ip == nil {
			continue
		}
		count, err := strconv.ParseUint(f[4], 10, 32)
		if err != nil || count == 0 {
			continue
		}
		nets = append(nets, cidrsForRange(binary.BigEndian.Uint32(ip), count)...)
	}
	return nets, sc.Err()
}

// parseDelegatedASNs pulls every AS number registered to cc out of the
// same file parseDelegated reads. An "asn" row's value is a count of
// consecutive AS numbers starting at `start`, exactly as it is a count
// of addresses for an "ipv4" row -- almost always 1, but blocks do get
// allocated and treating the count as 1 would drop the rest.
func parseDelegatedASNs(r io.Reader, cc string) (map[uint64]bool, error) {
	asns := map[uint64]bool{}
	sc := newScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "|")
		if len(f) < 7 || f[1] != cc || f[2] != "asn" {
			continue
		}
		start, err := strconv.ParseUint(f[3], 10, 32)
		if err != nil {
			continue
		}
		count, err := strconv.ParseUint(f[4], 10, 32)
		if err != nil || count == 0 {
			continue
		}
		for i := uint64(0); i < count; i++ {
			asns[start+i] = true
		}
	}
	return asns, sc.Err()
}

// parseIPToASN pulls every range iptoasn attributes to cc *and* whose
// origin ASN the delegated-stats files independently agree is registered
// to cc. It reports how many rows failed that second test, so a source
// drifting out of agreement shows up in the build log instead of
// silently changing the output. See this command's doc comment for why
// the cross-check is worth having.
//
// Rows are "range_start<TAB>range_end<TAB>asn<TAB>country<TAB>descr".
// ASN 0 marks space iptoasn knows of but sees no origin for; it can
// never pass the cross-check, and is skipped before it can be counted
// as a rejection.
func parseIPToASN(r io.Reader, cc string, ruASNs map[uint64]bool) (nets []*net.IPNet, rejected int, err error) {
	sc := newScanner(r)
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 4 {
			continue
		}
		asn, perr := strconv.ParseUint(f[2], 10, 32)
		if perr != nil || asn == 0 {
			continue
		}
		if f[3] != cc {
			continue
		}
		if !ruASNs[asn] {
			rejected++
			continue
		}
		start := net.ParseIP(f[0]).To4()
		end := net.ParseIP(f[1]).To4()
		if start == nil || end == nil {
			continue
		}
		s, e := binary.BigEndian.Uint32(start), binary.BigEndian.Uint32(end)
		if e < s {
			continue
		}
		nets = append(nets, cidrsForRange(s, uint64(e)-uint64(s)+1)...)
	}
	return nets, rejected, sc.Err()
}

// newScanner is the line scanner both parsers use. The buffer is raised
// past bufio's 64 KiB default because these files are machine-generated
// and one malformed long line would otherwise abort the scan with
// ErrTooLong -- which, unlike a skipped row, takes the whole list down.
func newScanner(r io.Reader) *bufio.Scanner {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	return sc
}

// cidrsForRange decomposes [start, start+count) into the minimal set of
// correctly aligned CIDR blocks. Necessary because a delegated-stats
// count need not be a power of two -- 1536 addresses, say, is 1024 + 512
// (a /22 then a /23), not the single /21 that naive log2-and-truncate
// arithmetic produces, which would cover 2048 and so over-claim the 512
// addresses following the real range. See this command's own package
// doc comment.
//
// count is a uint64 so a coalesced interval spanning the whole address
// space stays representable; the widest single block emitted is still a
// /1, so such an interval simply comes back as two of them.
func cidrsForRange(start uint32, count uint64) []*net.IPNet {
	var out []*net.IPNet
	for count > 0 {
		// Largest block that both starts at an address this aligned and
		// fits inside what is left.
		size := uint64(1) << 31
		if start != 0 {
			if align := uint64(start & (-start)); align < size {
				size = align
			}
		}
		if fit := uint64(1) << (bits.Len64(count) - 1); fit < size {
			size = fit
		}
		ones := 32 - bits.TrailingZeros64(size)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start)
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)})

		start += uint32(size)
		count -= size
		if start == 0 { // wrapped past 255.255.255.255
			break
		}
	}
	return out
}

// coalesce merges the union of both layers into the minimal equivalent
// set of CIDRs: overlapping and exactly adjacent ranges become one.
// Without it the layers stack -- the registry's wide allocation plus
// every individual /24 the ASN layer reports inside it -- inflating both
// the file and every per-flow Lookup that has to scan a bucket of them.
func coalesce(nets []*net.IPNet) []*net.IPNet {
	type span struct{ start, end uint64 }
	spans := make([]span, 0, len(nets))
	for _, n := range nets {
		v4 := n.IP.To4()
		ones, maskBits := n.Mask.Size()
		if v4 == nil || maskBits != 32 {
			continue
		}
		s := uint64(binary.BigEndian.Uint32(v4))
		spans = append(spans, span{s, s + (uint64(1) << uint(32-ones)) - 1})
	}
	if len(spans) == 0 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end < spans[j].end
	})

	var out []*net.IPNet
	cur := spans[0]
	flush := func(s span) {
		out = append(out, cidrsForRange(uint32(s.start), s.end-s.start+1)...)
	}
	for _, s := range spans[1:] {
		if s.start <= cur.end+1 { // overlapping, or exactly adjacent
			if s.end > cur.end {
				cur.end = s.end
			}
			continue
		}
		flush(cur)
		cur = s
	}
	flush(cur)
	return out
}

// totalAddresses sums the address space nets covers. Only meaningful on
// a coalesced set -- on a raw union, overlaps would be counted twice.
func totalAddresses(nets []*net.IPNet) uint64 {
	var total uint64
	for _, n := range nets {
		ones, maskBits := n.Mask.Size()
		if maskBits != 32 {
			continue
		}
		total += uint64(1) << uint(32-ones)
	}
	return total
}

func header() string {
	return "# " + countryCode + " IPv4 ranges, generated by cmd/georanges-gen from the RIR\n" +
		"# delegated-statistics files and iptoasn.com's prefix-to-ASN map\n" +
		"# (https://iptoasn.com/, PDDL v1.0). Do not edit by hand -- see that\n" +
		"# command's doc comment, and .github/workflows/georanges-update.yml.\n"
}

// render sorts numerically by network address (not lexically, so the
// file reads in real address order and its diffs stay small between
// runs), drops exact duplicates, and returns the finished file body.
func render(nets []*net.IPNet) string {
	sort.Slice(nets, func(i, j int) bool {
		a := binary.BigEndian.Uint32(nets[i].IP.To4())
		b := binary.BigEndian.Uint32(nets[j].IP.To4())
		if a != b {
			return a < b
		}
		ai, _ := nets[i].Mask.Size()
		bj, _ := nets[j].Mask.Size()
		return ai < bj
	})

	var b strings.Builder
	b.WriteString(header())
	var prev string
	for _, n := range nets {
		s := n.String()
		if s == prev {
			continue
		}
		prev = s
		b.WriteString(s)
		b.WriteByte('\n')
	}
	return b.String()
}
