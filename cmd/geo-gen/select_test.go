package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func setOf(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

func TestRootOf(t *testing.T) {
	set := setOf("example.com", "a.example.com", "notexample.com", "c.b.other.org", "b.other.org", "other.org")
	for name, want := range map[string]string{
		"c.b.other.org":       "other.org",   // a chain of three: the farthest, not the nearest
		"example.com":         "example.com", // itself
		"a.example.com":       "example.com", // the farthest listed parent, not the nearest
		"x.y.example.com":     "example.com", // the names in between need not be listed
		"notexample.com":      "notexample.com",
		"sub.notexample.com":  "notexample.com", // a suffix of the text is not a parent domain
		"unlisted.net":        "",
		"com":                 "",
		"deep.a.example.com.": "", // a trailing dot is a different spelling, never a parent
	} {
		if got := rootOf(set, name); got != want {
			t.Errorf("rootOf(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestCollapseDomains(t *testing.T) {
	set := setOf(
		"google.com", "mail.google.com", "a.mail.google.com", "docs.google.com",
		"deep.x.example.org", "example.org", // "x.example.org" is not listed: still covered
		"youtube.com", "notgoogle.com",
	)
	roots, covers := collapseDomains(set)
	wantRoots := []string{"example.org", "google.com", "notgoogle.com", "youtube.com"}
	if !reflect.DeepEqual(roots, wantRoots) {
		t.Errorf("roots = %v, want %v", roots, wantRoots)
	}
	wantCovers := map[string]int{"google.com": 4, "example.org": 2, "notgoogle.com": 1, "youtube.com": 1}
	if !reflect.DeepEqual(covers, wantCovers) {
		t.Errorf("covers = %v, want %v", covers, wantCovers)
	}
}

func TestCollapsedLen(t *testing.T) {
	if got := collapsedLen([]string{"a.example.com", "b.example.com", "example.com", "other.org"}); got != 2 {
		t.Errorf("collapsedLen = %d, want 2", got)
	}
	if got := collapsedLen(nil); got != 0 {
		t.Errorf("collapsedLen(nil) = %d, want 0", got)
	}
}

func TestCountryVariants(t *testing.T) {
	roots := []string{
		// a family: google.com covers the most names, so it heads it
		"google.com", "google.ae", "google.bf", "google.ca", "google.cd", "google.co.uk",
		// four members: a coincidence, not a family
		"amazon.com", "amazon.de", "amazon.fr", "amazon.it",
		// plenty of them, but not country-style suffixes
		"zed.dev", "zed.app", "zed.page", "zed.cloud", "zed.link",
		// one brand label, equal coverage everywhere: the plain .com heads it
		"brand.de", "brand.fr", "brand.it", "brand.es", "brand.com",
		// a different brand label with the same suffixes is another family
		"other.com",
		// what a family covers decides its head, not the suffix: wide.de covers four names
		"wide.com", "wide.de", "wide.fr", "wide.it", "wide.es",
	}
	covers := map[string]int{"google.com": 9, "wide.de": 4}
	for _, r := range roots {
		if _, ok := covers[r]; !ok {
			covers[r] = 1
		}
	}
	got := countryVariants(roots, covers)

	want := map[string]bool{
		"google.ae": true, "google.bf": true, "google.ca": true, "google.cd": true, "google.co.uk": true,
		"brand.de": true, "brand.fr": true, "brand.it": true, "brand.es": true,
		"wide.com": true, "wide.fr": true, "wide.it": true, "wide.es": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("variants = %v, want %v", got, want)
	}
}

// With nothing to tell the members of a family apart but their names, the
// shortest one heads it -- deterministically, whatever order they arrive in.
func TestCountryVariants_TieBreakIsStable(t *testing.T) {
	a := []string{"brand.fr", "brand.de", "brand.it", "brand.es", "brand.nl"}
	b := []string{"brand.nl", "brand.es", "brand.it", "brand.de", "brand.fr"}
	covers := map[string]int{}
	for _, r := range a {
		covers[r] = 1
	}
	ga, gb := countryVariants(a, covers), countryVariants(b, covers)
	if !reflect.DeepEqual(ga, gb) || ga["brand.de"] || len(ga) != 4 {
		t.Errorf("variants %v / %v: want brand.de as the head, whatever the order", ga, gb)
	}
}

// googleLike is a service the cap has to cut: its main names, a few subdomains of
// them, a family of country domains and a long tail.
func googleLike(tail int) []string {
	out := []string{
		"google.com", "mail.google.com", "docs.google.com", // collapsed into google.com
		"googlevideo.com", "gstatic.com",
		"googleapis.com", "a.googleapis.com", "b.googleapis.com", "c.googleapis.com", // covers 4
	}
	for _, cc := range []string{"ae", "bf", "ca", "cd", "cf", "cg", "ch", "ci", "cl", "cm"} {
		out = append(out, "google."+cc)
	}
	for i := 0; i < tail; i++ {
		out = append(out, fmt.Sprintf("svc%02d.example.net", i))
	}
	return out
}

func TestSelectDomains_PinsThenBreadthThenTheRest(t *testing.T) {
	entries := googleLike(3)
	kept, roots, missing := selectDomains(entries, []string{"googlevideo.com", "google.com"}, 6)

	// google.com, googlevideo.com, gstatic.com, googleapis.com + 10 country + 3 tail
	if roots != 17 {
		t.Errorf("roots = %d, want 17", roots)
	}
	if len(missing) != 0 {
		t.Errorf("missing = %v, want none", missing)
	}
	// Pins in the order they are listed; then the broadest (googleapis.com covers 4, google.com
	// is a pin already); then the tail before any country variant.
	want := []string{"googlevideo.com", "google.com", "googleapis.com", "gstatic.com", "svc00.example.net", "svc01.example.net"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %v\n want  %v", kept, want)
	}
}

// Country variants are not dropped, only ranked last: with room for them they are there.
func TestSelectDomains_VariantsFillWhatIsLeft(t *testing.T) {
	kept, roots, _ := selectDomains(googleLike(1), []string{"google.com"}, 8)
	if roots != 15 {
		t.Fatalf("roots = %d, want 15", roots)
	}
	// The pin, then everything that is not a variant (broadest first, then the
	// shorter and the shallower), then the variants that still fit, in name order.
	want := []string{"google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "svc00.example.net", "google.ae", "google.bf", "google.ca"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %v\n want  %v", kept, want)
	}
}

// No pins at all: google.com is the head of the google family, so it is ranked
// by what it covers like any other name -- ahead of the tail -- while the ten
// country domains wait behind everything.
func TestSelectDomains_HeadOfAFamilyIsNotDemoted(t *testing.T) {
	kept, _, _ := selectDomains(googleLike(40), nil, 3)
	want := []string{"googleapis.com", "google.com", "gstatic.com"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %v, want %v", kept, want)
	}
}

func TestSelectDomains_PinCoveredByAParentIsSatisfiedByIt(t *testing.T) {
	entries := []string{
		"google.com", "mail.google.com", // covers 2
		"big.example.org", "a.big.example.org", "b.big.example.org", "c.big.example.org", // covers 4
	}
	// Without a pin the broader one takes the only place ...
	if kept, _, _ := selectDomains(entries, nil, 1); !reflect.DeepEqual(kept, []string{"big.example.org"}) {
		t.Fatalf("unpinned: kept = %v, want [big.example.org]", kept)
	}
	// ... a pin on a name google.com covers makes google.com hold it, and a pin
	// nothing covers is reported.
	kept, _, missing := selectDomains(entries, []string{"mail.google.com", "absent.example"}, 1)
	if !reflect.DeepEqual(kept, []string{"google.com"}) {
		t.Errorf("kept = %v, want [google.com]: the pin on its subdomain holds its place", kept)
	}
	if !reflect.DeepEqual(missing, []string{"absent.example"}) {
		t.Errorf("missing = %v, want [absent.example]", missing)
	}
}

func TestSelectDomains_EverythingFits(t *testing.T) {
	entries := []string{"a.example.com", "example.com", "other.org"}
	kept, roots, missing := selectDomains(entries, nil, 10)
	if roots != 2 || len(missing) != 0 || !reflect.DeepEqual(kept, []string{"example.com", "other.org"}) {
		t.Errorf("kept %v roots %d missing %v", kept, roots, missing)
	}
	if kept, roots, _ := selectDomains(nil, nil, 10); len(kept) != 0 || roots != 0 {
		t.Errorf("empty source: kept %v roots %d", kept, roots)
	}
}

func TestSelectDomains_DuplicatePinsKeepTheFirstPlace(t *testing.T) {
	kept, _, _ := selectDomains([]string{"a.com", "b.com", "c.com"}, []string{"c.com", "b.com", "c.com"}, 3)
	if !reflect.DeepEqual(kept, []string{"c.com", "b.com", "a.com"}) {
		t.Errorf("kept = %v, want [c.com b.com a.com]", kept)
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func buildDomainsKeep(t *testing.T, dir string, entries, keep []string, cap int) (*manifestRow, string) {
	t.Helper()
	s := &sourcesFile{}
	s.applyDefaults()
	row, note := buildFile(dir, "svc", "svc", "Svc", "Cat", "domains", []string{listServer(t, entries)}, []string{"src"}, config.RouteDomain, cap, keep, s, false)
	if row == nil {
		t.Fatal("buildFile produced no row")
	}
	return row, note
}

// End to end: what lands in the file is the selection, and the row says how many
// names (after the collapse) the source really had.
func TestBuildFile_DomainSelection(t *testing.T) {
	dir := t.TempDir()
	row, _ := buildDomainsKeep(t, dir, googleLike(40), []string{"google.com", "googlevideo.com", "gstatic.com"}, 20)

	// roots: google.com, googlevideo.com, gstatic.com, googleapis.com, 10 country, 40 tail = 54
	if row.Count != 20 || row.SourceCount != 54 {
		t.Fatalf("row = %+v, want count 20 and source_count 54", row)
	}
	got := readEntries(filepath.Join(dir, "svc.lst"))
	set := setOf(got...)
	for _, must := range []string{"google.com", "googlevideo.com", "gstatic.com", "googleapis.com", "svc00.example.net"} {
		if _, ok := set[must]; !ok {
			t.Errorf("%s missing from %v", must, got)
		}
	}
	for _, mustNot := range []string{"mail.google.com", "docs.google.com", "a.googleapis.com", "google.ae", "google.cm"} {
		if _, ok := set[mustNot]; ok {
			t.Errorf("%s should not be in the list: %v", mustNot, got)
		}
	}
}

// A list that fits once its subdomains are folded away is not "cut": nothing a
// router would have routed is lost, so the row says nothing about the source.
func TestBuildFile_CollapseAloneIsNotACut(t *testing.T) {
	dir := t.TempDir()
	row, note := buildDomainsKeep(t, dir, googleLike(5), nil, 100)
	if row.Count != 19 || row.SourceCount != 0 {
		t.Errorf("row = %+v, want count 19 (the roots) and no source_count", row)
	}
	if strings.Contains(note, "срезано") {
		t.Errorf("note %q must not call a collapse a cut", note)
	}
	if got := readEntries(filepath.Join(dir, "svc.lst")); containsStr(got, "mail.google.com") {
		t.Errorf("a subdomain of a listed name survived: %v", got)
	}
}

func TestBuildFile_PinTheSourceLacksIsReportedNotInvented(t *testing.T) {
	dir := t.TempDir()
	row, note := buildDomainsKeep(t, dir, googleLike(5), []string{"google.com", "gone.example"}, 100)
	if !strings.Contains(note, "gone.example") {
		t.Errorf("note %q does not name the missing pin", note)
	}
	if got := readEntries(filepath.Join(dir, "svc.lst")); containsStr(got, "gone.example") || row.Count != 19 {
		t.Errorf("a pin the source does not have was written: %v (count %d)", got, row.Count)
	}
}

// writePrev writes a list the way an earlier run (one that did not collapse
// subdomains) would have: every name of the source, parents and children alike.
func writePrev(t *testing.T, dir string, entries []string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "svc.lst"), renderList("Svc", "domains", []string{"src"}, entries), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 30 roots with 70 subdomains between them: 100 names, worth 30.
func uncollapsed100() (all, roots []string) {
	for i := 0; i < 30; i++ {
		r := fmt.Sprintf("root%02d.example.com", i)
		roots = append(roots, r)
		all = append(all, r)
	}
	for i := 0; i < 70; i++ {
		all = append(all, fmt.Sprintf("s%d.root%02d.example.com", i, i%30))
	}
	return all, roots
}

// The first refresh after the collapse arrives sees a list of 100 become 30. That
// is the collapse, not an upstream problem; holding the old list would keep it for
// good (the next day would compare against it again).
func TestBuildFile_GateMeasuresAnUncollapsedPrevByWhatItIsWorth(t *testing.T) {
	dir := t.TempDir()
	all, roots := uncollapsed100()
	writePrev(t, dir, all)

	row, note := buildDomainsKeep(t, dir, all, nil, 250) // the same source as before, now collapsed
	if row.keptPrev || row.Count != len(roots) {
		t.Fatalf("row = %+v note %q: the collapsed list (30) must replace the old one (100)", row, note)
	}
	// ... and a real collapse on top of it is still caught.
	dir2 := t.TempDir()
	writePrev(t, dir2, all)
	row, _ = buildDomainsKeep(t, dir2, roots[:10], nil, 250) // 10 < half of the 30 it was worth
	if !row.keptPrev || row.Count != 100 {
		t.Errorf("row = %+v: a drop to a third of what the list was worth must still be held", row)
	}
}

// The upper gate keeps the list as it was: a fresh 150 against a 100-name list
// (worth 25) is no explosion; measured by worth it would read as 6x and be held.
func TestBuildFile_GateHighLimitUsesTheListAsItWas(t *testing.T) {
	dir := t.TempDir()
	all, _ := uncollapsed100()
	writePrev(t, dir, all)
	fresh := make([]string, 150)
	for i := range fresh {
		fresh[i] = fmt.Sprintf("n%03d.example.org", i)
	}
	row, note := buildDomainsKeep(t, dir, fresh, nil, 250)
	if row.keptPrev || row.Count != 150 {
		t.Errorf("row = %+v note %q: 150 against a list of 100 is below the 2x gate", row, note)
	}
	// An explosion past 2x of the list as it was is still held.
	big := make([]string, 250)
	for i := range big {
		big[i] = fmt.Sprintf("m%03d.example.org", i)
	}
	dir2 := t.TempDir()
	writePrev(t, dir2, all)
	if row, _ = buildDomainsKeep(t, dir2, big, nil, 250); !row.keptPrev || row.Count != 100 {
		t.Errorf("row = %+v: 250 against a list of 100 is past the 2x gate and must be held", row)
	}
}

// What sources.json asks of the selection must be well-formed: a pin that is not
// a valid, normalized domain could never match anything, and a name pinned twice
// or for an unknown preset would be a copy-paste slip nobody sees in the diff.
func TestSourcesJSON_KeepListsAreWellFormed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "presets", "data", "sources.json"))
	if err != nil {
		t.Fatal(err)
	}
	var src sourcesFile
	if err := json.Unmarshal(raw, &src); err != nil {
		t.Fatal(err)
	}
	src.applyDefaults()

	names := map[string]bool{}
	pinned := 0
	for _, p := range src.Presets {
		if names[p.Name] {
			t.Errorf("preset %q listed twice", p.Name)
		}
		names[p.Name] = true
		seen := map[string]bool{}
		for _, k := range p.Keep {
			kind, norm, err := config.ClassifyRouteEntry(k)
			if err != nil || kind != config.RouteDomain || norm != k {
				t.Errorf("%s: keep %q is not a normalized domain (%v %q %v)", p.Name, k, kind, norm, err)
			}
			if seen[k] {
				t.Errorf("%s: keep %q listed twice", p.Name, k)
			}
			seen[k] = true
		}
		pinned += len(p.Keep)
		if len(p.Keep) > src.MaxDomains/2 {
			t.Errorf("%s: %d pins leave less than half of the %d-name list to the selection", p.Name, len(p.Keep), src.MaxDomains)
		}
		if len(p.Keep) > 0 && len(p.GATags) == 0 {
			t.Errorf("%s: keep without a domain source (ga_tags) pins nothing", p.Name)
		}
	}
	if pinned == 0 {
		t.Error("no preset pins anything: the cut lists would be ranked by coverage alone")
	}
}

// The size of a domain list that docs/routing.md and the data README quote.
func TestApplyDefaults_DomainCap(t *testing.T) {
	var s sourcesFile
	s.applyDefaults()
	if s.MaxDomains != 250 {
		t.Errorf("default max_domains = %d, want 250", s.MaxDomains)
	}
}
