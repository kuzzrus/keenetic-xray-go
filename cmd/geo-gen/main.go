// Command geo-gen regenerates presets/*.lst and presets/manifest.json from
// the upstreams named in presets/sources.json.
//
// It is a CI/maintenance tool -- .github/workflows/geo-update.yml runs it
// daily -- and is never compiled into the router binary or shipped.
//
// Upstreams:
//   - Geo-Aggregator (github.com/Ground-Zerro/Geo-Aggregator): curated
//     per-service domain lists, resolved through its db/catalog.json
//     (service id -> source path).
//   - lord-alfred/ipranges: per-provider ipv4.txt CIDR lists.
//   - optional cidr_extra URLs, e.g. core.telegram.org/resources/cidr.txt.
//
// Every line is validated through config.ClassifyRouteEntry -- the same
// gate the router applies to a hand-typed entry -- then deduped, sorted
// and capped. A per-file sanity gate keeps the previous list untouched
// when a fresh fetch shrinks or grows past the configured ratio, so one
// flaky upstream can't nuke a preset. The process exits non-zero only on
// a real error (unreadable sources.json, an unknown Geo-Aggregator tag,
// every upstream for a preset dead); a single transient failure is logged
// and the old file kept.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

type sourcesFile struct {
	Catalog       string       `json:"geo_aggregator_catalog"`
	IPRangesBase  string       `json:"ipranges_base"`
	MaxDomains    int          `json:"max_domains"`
	MaxCIDRs      int          `json:"max_cidrs"`
	MinKeep       int          `json:"min_keep"`
	DriftGateLow  float64      `json:"drift_gate_low"`
	DriftGateHigh float64      `json:"drift_gate_high"`
	Presets       []presetSpec `json:"presets"`
}

type presetSpec struct {
	Name          string   `json:"name"`
	Title         string   `json:"title"`
	Category      string   `json:"category"`
	GATags        []string `json:"ga_tags"`
	CIDRProviders []string `json:"cidr_providers"`
	CIDRExtra     []string `json:"cidr_extra"`
}

// manifestRow is one line of presets/manifest.json. internal/presets
// reads the same shape. Service groups a domain preset with its CIDR
// companion ("<name>" and "<name>-ip" share one Service) so the bot can
// show them together under one service entry.
type manifestRow struct {
	Name     string   `json:"name"`
	Service  string   `json:"service"`
	Title    string   `json:"title"`
	Category string   `json:"category"`
	Kind     string   `json:"kind"` // "domains" | "cidr"
	Count    int      `json:"count"`
	Rev      string   `json:"rev"`
	Sources  []string `json:"sources"`
}

type manifestFile struct {
	Version   int           `json:"version"`
	Generated string        `json:"generated"`
	Presets   []manifestRow `json:"presets"`
}

type catalog struct {
	Base     string `json:"base"`
	Services []struct {
		ID  string `json:"id"`
		Src string `json:"src"`
	} `json:"services"`
}

var httpClient = &http.Client{Timeout: 45 * time.Second}

func main() {
	dir := flag.String("dir", "presets", "directory holding sources.json and the generated *.lst / manifest.json")
	dryRun := flag.Bool("dry-run", false, "fetch and compute, but don't write files; report what would change")
	flag.Parse()

	if err := run(*dir, *dryRun); err != nil {
		fmt.Fprintln(os.Stderr, "geo-gen: "+err.Error())
		os.Exit(1)
	}
}

func run(dir string, dryRun bool) error {
	var src sourcesFile
	raw, err := os.ReadFile(filepath.Join(dir, "sources.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &src); err != nil {
		return fmt.Errorf("sources.json: %w", err)
	}
	src.applyDefaults()
	if src.Catalog == "" || src.IPRangesBase == "" {
		return fmt.Errorf("sources.json: geo_aggregator_catalog and ipranges_base are required")
	}

	cat, err := fetchCatalog(src.Catalog)
	if err != nil {
		return fmt.Errorf("Geo-Aggregator catalog: %w", err)
	}
	catByID := map[string]string{}
	for _, s := range cat.Services {
		catByID[s.ID] = strings.TrimRight(cat.Base, "/") + "/" + strings.TrimLeft(s.Src, "/")
	}

	var rows []manifestRow
	var problems []string
	summary := &strings.Builder{}
	fmt.Fprintf(summary, "| preset | вид | записей | итог |\n|---|---|--:|---|\n")

	for _, p := range src.Presets {
		// --- domains ---
		// ga_tags is a candidate list: the first id that exists in the
		// current Geo-Aggregator catalog wins. A rename upstream degrades
		// to "preset skipped, previous file kept", not a failed build.
		var domURL, domLabel string
		for _, tag := range p.GATags {
			if u, ok := catByID[tag]; ok {
				domURL, domLabel = u, "Geo-Aggregator: "+tag
				break
			}
		}
		if domURL == "" {
			problems = append(problems, fmt.Sprintf("%s: none of ga_tags %v in Geo-Aggregator catalog — preset skipped", p.Name, p.GATags))
			fmt.Fprintf(summary, "| %s | домены | — | ⚠️ тег не найден в каталоге |\n", p.Name)
			continue
		}
		if row, note := buildFile(dir, p.Name, p.Name, p.Title, p.Category, "domains",
			[]string{domURL}, []string{domLabel}, config.RouteDomain, src.MaxDomains, &src, dryRun); row != nil {
			rows = append(rows, *row)
			fmt.Fprintf(summary, "| %s | домены | %d | %s |\n", p.Name, row.Count, note)
		}

		// --- cidr (optional) ---
		if len(p.CIDRProviders) == 0 && len(p.CIDRExtra) == 0 {
			continue
		}
		var ipURLs, ipSrcLabels []string
		for _, prov := range p.CIDRProviders {
			ipURLs = append(ipURLs, strings.TrimRight(src.IPRangesBase, "/")+"/"+prov+"/ipv4.txt")
			ipSrcLabels = append(ipSrcLabels, "lord-alfred/ipranges: "+prov)
		}
		for _, u := range p.CIDRExtra {
			ipURLs = append(ipURLs, u)
			ipSrcLabels = append(ipSrcLabels, shortHost(u))
		}
		if row, note := buildFile(dir, p.Name+"-ip", p.Name, p.Title, p.Category, "cidr",
			ipURLs, ipSrcLabels, config.RouteSubnet, src.MaxCIDRs, &src, dryRun); row != nil {
			rows = append(rows, *row)
			fmt.Fprintf(summary, "| %s-ip | CIDR | %d | %s |\n", p.Name, row.Count, note)
		}
	}

	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "  ⚠️ "+p)
	}
	// A few renamed tags are survivable; a wholesale miss means the
	// catalog format changed and the run should fail loudly.
	if n := len(problems); n > 0 && n*10 > len(src.Presets)*3 {
		return fmt.Errorf("%d/%d presets could not resolve a Geo-Aggregator tag — catalog format likely changed", n, len(src.Presets))
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	mfPath := filepath.Join(dir, "manifest.json")
	generated := time.Now().UTC().Format("2006-01-02")
	if old := loadManifest(mfPath); old != nil && sameRows(old.Presets, rows) {
		generated = old.Generated // nothing changed -> keep the old stamp, no diff
	}
	mf := manifestFile{Version: 1, Generated: generated, Presets: rows}
	out, _ := json.MarshalIndent(mf, "", "  ")
	out = append(out, '\n')
	if dryRun {
		fmt.Println("[dry-run] manifest.json would be:")
		fmt.Println(string(out))
	} else if err := os.WriteFile(mfPath, out, 0o644); err != nil {
		return err
	}

	if len(problems) > 0 {
		fmt.Fprintf(summary, "\n**Проблемы (%d):**\n", len(problems))
		for _, p := range problems {
			fmt.Fprintf(summary, "- %s\n", p)
		}
	}

	fmt.Println(summary.String())
	if gs := os.Getenv("GITHUB_STEP_SUMMARY"); gs != "" {
		if f, err := os.OpenFile(gs, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
			fmt.Fprintf(f, "### presets refresh %s\n\n%s\n", mf.Generated, summary.String())
			f.Close()
		}
	}
	return nil
}

func (s *sourcesFile) applyDefaults() {
	if s.MaxDomains == 0 {
		s.MaxDomains = 200
	}
	if s.MaxCIDRs == 0 {
		s.MaxCIDRs = 48
	}
	if s.MinKeep == 0 {
		s.MinKeep = 8
	}
	if s.DriftGateLow == 0 {
		s.DriftGateLow = 0.5
	}
	if s.DriftGateHigh == 0 {
		s.DriftGateHigh = 2.0
	}
}

// buildFile fetches every URL, keeps the lines whose ClassifyRouteEntry
// kind matches want, dedupes/sorts/caps, applies the sanity gate against
// any existing file, writes the result (unless dryRun) and returns its
// manifest row plus a short human note for the summary table. A nil row
// means nothing usable was produced and no previous file exists.
func buildFile(dir, name, service, title, category, kind string,
	urls, srcLabels []string, want config.RouteEntryKind, cap int,
	s *sourcesFile, dryRun bool) (*manifestRow, string) {

	path := filepath.Join(dir, name+".lst")
	prev := readEntries(path)

	seen := map[string]struct{}{}
	var got []string
	var fetchErrs int
	for _, u := range urls {
		body, err := fetch(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %s: %v\n", name, u, err)
			fetchErrs++
			continue
		}
		for _, ln := range strings.Split(body, "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "//") {
				continue
			}
			k, norm, err := config.ClassifyRouteEntry(ln)
			if err != nil || k != want {
				continue
			}
			if _, dup := seen[norm]; dup {
				continue
			}
			seen[norm] = struct{}{}
			got = append(got, norm)
		}
	}

	capped := false
	if kind == "cidr" {
		// Provider CIDR dumps are huge and highly fragmented (github ~6k,
		// google ~1k). Collapse siblings / contained blocks first, then --
		// if still over budget -- keep the largest blocks, which covers
		// the most address space per object-group entry.
		got = aggregateCIDRs(got)
		if len(got) > cap {
			sort.Slice(got, func(i, j int) bool {
				pi, pj := prefixLen(got[i]), prefixLen(got[j])
				if pi != pj {
					return pi < pj // shorter prefix = bigger block first
				}
				return cidrKey(got[i]) < cidrKey(got[j])
			})
			got = got[:cap]
			capped = true
		}
		sortEntries(got, kind)
	} else {
		// Domains: rank apex/short names above regional ccTLD spam so a
		// cap never drops "paypal.com" in favour of "paypal.com.hk".
		sort.Slice(got, func(i, j int) bool { return domainRank(got[i]) < domainRank(got[j]) })
		if len(got) > cap {
			got = got[:cap]
			capped = true
		}
		sortEntries(got, kind)
	}

	// Sanity gate: an established file that suddenly collapses or explodes
	// is almost always an upstream problem -- keep what we had.
	keepPrev := false
	reason := ""
	switch {
	case len(got) == 0 && len(prev) > 0:
		keepPrev, reason = true, fmt.Sprintf("держим прежние %d (все источники недоступны)", len(prev))
	case len(got) == 0 && len(prev) == 0:
		if fetchErrs > 0 {
			return nil, "пусто, источники недоступны — пропуск"
		}
		return nil, "пусто — пропуск"
	case len(prev) >= s.MinKeep && float64(len(got)) < float64(len(prev))*s.DriftGateLow:
		keepPrev, reason = true, fmt.Sprintf("держим прежние %d (свежих только %d, < %.0f%%)", len(prev), len(got), s.DriftGateLow*100)
	case len(prev) >= s.MinKeep && float64(len(got)) > float64(len(prev))*s.DriftGateHigh:
		keepPrev, reason = true, fmt.Sprintf("держим прежние %d (свежих %d, > %.0fx)", len(prev), len(got), s.DriftGateHigh)
	}

	final := got
	if keepPrev {
		final = prev
	}

	row := &manifestRow{
		Name: name, Service: service, Title: title, Category: category,
		Kind: kind, Count: len(final), Rev: revOf(final), Sources: srcLabels,
	}

	if keepPrev {
		return row, reason
	}

	// Entry set unchanged -> leave the file byte-for-byte as it is (its
	// header date then reads as "last changed", and the daily CI run
	// produces no diff for this preset).
	if _, statErr := os.Stat(path); statErr == nil && revOf(prev) == row.Rev {
		note := "без изменений"
		if capped {
			note += fmt.Sprintf(", срезано до %d", cap)
		}
		return row, note
	}

	note := "обновлено"
	if len(prev) == 0 {
		note = "создано"
	}
	if capped {
		note += fmt.Sprintf(", срезано до %d", cap)
	}

	if dryRun {
		added, removed := diffCount(prev, final)
		fmt.Printf("[dry-run] %s.lst: +%d -%d (итого %d)\n", name, added, removed, len(final))
		return row, note
	}

	if err := os.WriteFile(path, renderList(title, kind, srcLabels, final), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "  %s: write: %v\n", name, err)
		return row, "ОШИБКА записи"
	}
	return row, note
}

func renderList(title, kind string, srcLabels, entries []string) []byte {
	b := &strings.Builder{}
	vid := "домены"
	if kind == "cidr" {
		vid = "IPv4-подсети (CIDR)"
	}
	fmt.Fprintf(b, "# %s — %s\n", title, vid)
	fmt.Fprintf(b, "# generated by cmd/geo-gen on %s — %d entries — do not edit by hand\n", time.Now().UTC().Format("2006-01-02"), len(entries))
	for _, s := range srcLabels {
		fmt.Fprintf(b, "# source: %s\n", s)
	}
	b.WriteString("\n")
	for _, e := range entries {
		b.WriteString(e)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// readEntries returns the data lines (comments and blanks stripped) of a
// generated .lst file, or nil if it doesn't exist.
func readEntries(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(raw), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func sortEntries(xs []string, kind string) {
	if kind == "cidr" {
		sort.Slice(xs, func(i, j int) bool {
			ai, aj := cidrKey(xs[i]), cidrKey(xs[j])
			if ai != aj {
				return ai < aj
			}
			return xs[i] < xs[j]
		})
		return
	}
	sort.Strings(xs)
}

// domainRank orders domains so a byte-budget cap keeps the important
// ones: fewest labels first (apex before deep subdomain), then shortest,
// then lexical. "paypal.com" (2 labels, 10 chars) outranks "paypal.com.hk".
func domainRank(d string) string {
	labels := strings.Count(d, ".") + 1
	return fmt.Sprintf("%02d%03d%s", labels, len(d), d)
}

// minAggBits stops CIDR aggregation from ever producing an absurdly
// broad route even if a provider dump is pathological.
const minAggBits = 8

// aggregateCIDRs collapses an IPv4 CIDR set: any block wholly contained
// in another is dropped, and two aligned siblings that together fill
// their parent are merged into it, repeated to a fixpoint. The result is
// equivalent coverage with far fewer entries (github ~6k -> a few
// hundred). Input strings are "a.b.c.d/p" as normalized by
// config.ClassifyRouteEntry; output is the same form, address-sorted.
func aggregateCIDRs(in []string) []string {
	type blk struct {
		base uint32
		bits int
	}
	var bs []blk
	for _, s := range in {
		i := strings.IndexByte(s, '/')
		if i < 0 {
			continue
		}
		ip := net.ParseIP(s[:i]).To4()
		if ip == nil {
			continue
		}
		bits := prefixLen(s)
		if bits < 1 || bits > 32 {
			continue
		}
		v := uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
		mask := uint32(0xFFFFFFFF)
		if bits < 32 {
			mask <<= uint(32 - bits)
		}
		bs = append(bs, blk{base: v & mask, bits: bits})
	}

	less := func(a, b blk) bool {
		if a.base != b.base {
			return a.base < b.base
		}
		return a.bits < b.bits
	}
	contains := func(outer, inner blk) bool {
		if outer.bits > inner.bits {
			return false
		}
		mask := uint32(0xFFFFFFFF)
		if outer.bits < 32 {
			mask <<= uint(32 - outer.bits)
		}
		return inner.base&mask == outer.base
	}

	for {
		sort.Slice(bs, func(i, j int) bool { return less(bs[i], bs[j]) })

		// drop blocks contained in an earlier (broader) one
		pruned := bs[:0]
		for i := 0; i < len(bs); i++ {
			if n := len(pruned); n > 0 && contains(pruned[n-1], bs[i]) {
				continue
			}
			pruned = append(pruned, bs[i])
		}
		bs = pruned

		// merge aligned sibling pairs into their parent
		merged := make([]blk, 0, len(bs))
		changed := false
		for i := 0; i < len(bs); i++ {
			if i+1 < len(bs) && bs[i].bits == bs[i+1].bits && bs[i].bits > minAggBits {
				pbits := bs[i].bits - 1
				pmask := uint32(0xFFFFFFFF) << uint(32-pbits)
				if bs[i].base&pmask == bs[i+1].base&pmask && bs[i].base != bs[i+1].base {
					merged = append(merged, blk{base: bs[i].base & pmask, bits: pbits})
					i++
					changed = true
					continue
				}
			}
			merged = append(merged, bs[i])
		}
		bs = merged
		if !changed {
			break
		}
	}

	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(b.base>>24), byte(b.base>>16), byte(b.base>>8), byte(b.base), b.bits)
	}
	return out
}

// cidrKey turns an IPv4 CIDR (or bare IP) into a sortable uint64:
// address in the high 32 bits, prefix length in the low bits.
func cidrKey(s string) uint64 {
	ip := s
	if i := strings.IndexByte(s, '/'); i >= 0 {
		ip = s[:i]
	}
	p := net.ParseIP(ip).To4()
	if p == nil {
		return 0
	}
	v := uint64(p[0])<<24 | uint64(p[1])<<16 | uint64(p[2])<<8 | uint64(p[3])
	return v<<8 | uint64(prefixLen(s))
}

func prefixLen(s string) int {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n := 0
		for _, c := range s[i+1:] {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		return n
	}
	return 32
}

func revOf(entries []string) string {
	h := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(h[:])[:12]
}

func diffCount(oldE, newE []string) (added, removed int) {
	o := map[string]struct{}{}
	for _, e := range oldE {
		o[e] = struct{}{}
	}
	n := map[string]struct{}{}
	for _, e := range newE {
		n[e] = struct{}{}
		if _, ok := o[e]; !ok {
			added++
		}
	}
	for _, e := range oldE {
		if _, ok := n[e]; !ok {
			removed++
		}
	}
	return added, removed
}

func loadManifest(path string) *manifestFile {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m manifestFile
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return &m
}

// sameRows reports whether two manifest row sets are identical ignoring
// the top-level date stamp -- i.e. no preset content or metadata moved.
func sameRows(a, b []manifestRow) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x.Name != y.Name || x.Service != y.Service || x.Title != y.Title ||
			x.Category != y.Category || x.Kind != y.Kind || x.Count != y.Count ||
			x.Rev != y.Rev || strings.Join(x.Sources, "|") != strings.Join(y.Sources, "|") {
			return false
		}
	}
	return true
}

func fetchCatalog(url string) (*catalog, error) {
	body, err := fetch(url)
	if err != nil {
		return nil, err
	}
	var c catalog
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return nil, err
	}
	if c.Base == "" {
		if i := strings.LastIndex(url, "/db/"); i >= 0 {
			c.Base = url[:i+1]
		}
	}
	if len(c.Services) == 0 {
		return nil, fmt.Errorf("no services in catalog")
	}
	return &c, nil
}

// fetch GETs url with one retry on any failure.
func fetch(url string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(3 * time.Second)
		}
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("User-Agent", "keenetic-xray-go geo-gen (+https://github.com/kuzzrus/keenetic-xray-go)")
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return string(b), nil
	}
	return "", lastErr
}

func shortHost(u string) string {
	s := u
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}
