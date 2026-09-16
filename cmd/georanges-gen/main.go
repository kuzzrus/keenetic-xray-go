// Command georanges-gen regenerates internal/georanges/data/ru-ipv4.txt
// from the RIR delegated-statistics files -- the authoritative record of
// which address ranges are registered to which country.
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
package main

import (
	"bufio"
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

// countryCode is the country whose ranges this generates. A constant
// rather than a flag on purpose: internal/georanges embeds exactly one
// list and its doc comments are written about Russia specifically, so a
// second country would be a deliberate feature, not a CLI invocation.
const countryCode = "RU"

const outPath = "internal/georanges/data/ru-ipv4.txt"

// minRanges guards against committing a truncated list: a partial
// download or an upstream format change that silently matches nothing
// would otherwise replace a good list with a near-empty one, disabling
// the veto exactly as effectively as an unreachable host did. The real
// count is around 11-12k; anything far below that is not a plausible
// day-to-day change.
const minRanges = 5000

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "georanges-gen:", err)
		os.Exit(1)
	}
}

func run() error {
	var all []*net.IPNet
	for _, url := range sources {
		raw, err := fetch(url)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		nets, err := parseDelegated(strings.NewReader(raw), countryCode)
		if err != nil {
			return fmt.Errorf("%s: %w", url, err)
		}
		fmt.Fprintf(os.Stderr, "%s: %d ranges\n", url, len(nets))
		all = append(all, nets...)
	}

	out := render(all)
	count := strings.Count(out, "\n")
	if count < minRanges {
		return fmt.Errorf("only %d ranges, want at least %d -- refusing to write a suspiciously short list",
			count, minRanges)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, []byte(out), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d ranges\n", outPath, count)
	return nil
}

func fetch(url string) (string, error) {
	hc := &http.Client{Timeout: 5 * time.Minute} // these files run to tens of MB
	resp, err := hc.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parseDelegated pulls every IPv4 range attributed to cc out of one
// delegated-statistics file. Row format is
// `registry|cc|type|start|value|date|status[|opaque-id]`, where for
// ipv4 `value` is a *count of addresses*. Header lines (version/summary)
// and comments are skipped implicitly: they never carry `|ipv4|` with a
// parseable start address.
func parseDelegated(r io.Reader, cc string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
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
		nets = append(nets, cidrsForRange(binary.BigEndian.Uint32(ip), uint32(count))...)
	}
	return nets, sc.Err()
}

// cidrsForRange decomposes [start, start+count) into the minimal set of
// correctly aligned CIDR blocks. Necessary because a delegated-stats
// count need not be a power of two -- 1536 addresses, say, is 1024 + 512
// (a /22 then a /23), not the single /21 that naive log2-and-truncate
// arithmetic produces, which would cover 2048 and so over-claim the 512
// addresses following the real range. See this command's own package
// doc comment.
func cidrsForRange(start, count uint32) []*net.IPNet {
	var out []*net.IPNet
	for count > 0 {
		// Largest block that both starts at an address this aligned and
		// fits inside what is left.
		size := uint32(1) << 31
		if start != 0 {
			if align := start & (-start); align < size {
				size = align
			}
		}
		if fit := uint32(1) << (bits.Len32(count) - 1); fit < size {
			size = fit
		}
		ones := 32 - bits.TrailingZeros32(size)
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, start)
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)})

		start += size
		count -= size
		if start == 0 { // wrapped past 255.255.255.255; malformed input
			break
		}
	}
	return out
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
	b.WriteString("# " + countryCode + " IPv4 ranges, generated by cmd/georanges-gen from the RIR\n")
	b.WriteString("# delegated-statistics files. Do not edit by hand -- see that command's\n")
	b.WriteString("# doc comment, and .github/workflows/georanges-update.yml.\n")
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
