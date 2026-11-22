package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// listServer serves one plain-text list, one entry per line.
func listServer(t *testing.T, entries []string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Join(entries, "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func nDomains(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("d%04d.example.com", i)
	}
	return out
}

func buildDomains(t *testing.T, dir string, entries []string, cap int) *manifestRow {
	t.Helper()
	s := &sourcesFile{}
	s.applyDefaults()
	row, _ := buildFile(dir, "svc", "svc", "Svc", "Cat", "domains", []string{listServer(t, entries)}, []string{"src"}, config.RouteDomain, cap, s, false)
	if row == nil {
		t.Fatal("buildFile produced no row")
	}
	return row
}

// A list the cap cut says how many the upstream really had; one that fit says
// nothing (its row must not move with the source).
func TestBuildFile_SourceCountOnlyWhenTheCapCut(t *testing.T) {
	row := buildDomains(t, t.TempDir(), nDomains(300), 200)
	if row.Count != 200 || row.SourceCount != 300 {
		t.Errorf("capped list: count %d source_count %d, want 200 and 300", row.Count, row.SourceCount)
	}

	row = buildDomains(t, t.TempDir(), nDomains(150), 200)
	if row.Count != 150 || row.SourceCount != 0 {
		t.Errorf("list that fit: count %d source_count %d, want 150 and 0", row.Count, row.SourceCount)
	}
	// Exactly at the cap is not a cut either.
	if row = buildDomains(t, t.TempDir(), nDomains(200), 200); row.SourceCount != 0 {
		t.Errorf("list of exactly the cap: source_count %d, want 0", row.SourceCount)
	}
}

// CIDR lists are counted after sibling blocks were merged: that is what the cap
// is applied to.
func TestBuildFile_SourceCountOfACIDRListIsAfterMerging(t *testing.T) {
	var entries []string
	for i := 0; i < 100; i++ {
		entries = append(entries, fmt.Sprintf("203.0.%d.0/24", i*2)) // even third octets: no two are siblings
	}
	entries = append(entries, "198.51.100.0/25", "198.51.100.128/25") // these two merge into one /24
	s := &sourcesFile{}
	s.applyDefaults()
	row, _ := buildFile(t.TempDir(), "svc-ip", "svc", "Svc", "Cat", "cidr", []string{listServer(t, entries)}, []string{"src"}, config.RouteSubnet, 48, s, false)
	if row == nil || row.Count != 48 || row.SourceCount != 101 {
		t.Errorf("row = %+v, want count 48 and source_count 101 (100 + the merged pair)", row)
	}
}

// The sanity gate keeps the previous file when the fresh data collapses: the row
// then has no count of its own and must say so.
func TestBuildFile_SanityHoldHasNoCountOfItsOwn(t *testing.T) {
	dir := t.TempDir()
	buildDomains(t, dir, nDomains(100), 200) // establishes svc.lst
	row := buildDomains(t, dir, nDomains(10), 200)
	if !row.keptPrev || row.Count != 100 || row.SourceCount != 0 {
		t.Errorf("row = %+v, want the previous 100 kept, keptPrev set, no source_count", row)
	}
}

func TestCarrySourceCounts(t *testing.T) {
	old := &manifestFile{Presets: []manifestRow{
		{Name: "same", Rev: "r1", SourceCount: 540},
		{Name: "grew", Rev: "r1", SourceCount: 540},
		{Name: "changed", Rev: "r1", SourceCount: 540},
		{Name: "held", Rev: "r1", SourceCount: 540},
		{Name: "nowfits", Rev: "r1", SourceCount: 540},
		{Name: "firsttime", Rev: "r1"},
	}}
	rows := []manifestRow{
		{Name: "same", Rev: "r1", SourceCount: 561},      // drifted <25%, list unchanged: keep the old figure
		{Name: "grew", Rev: "r1", SourceCount: 900},      // the source grew well past a quarter: the new figure
		{Name: "changed", Rev: "r2", SourceCount: 561},   // the list changed: the new figure
		{Name: "held", Rev: "r1", keptPrev: true},        // a sanity hold has no figure: bring the old one back
		{Name: "nowfits", Rev: "r1"},                     // no longer cut: nothing to say
		{Name: "firsttime", Rev: "r1", SourceCount: 300}, // the old row had none: record what was measured
		{Name: "brandnew", Rev: "r9", SourceCount: 250},
	}
	carrySourceCounts(rows, old)
	want := map[string]int{"same": 540, "grew": 900, "changed": 561, "held": 540, "nowfits": 0, "firsttime": 300, "brandnew": 250}
	for _, r := range rows {
		if r.SourceCount != want[r.Name] {
			t.Errorf("%s: source_count %d, want %d", r.Name, r.SourceCount, want[r.Name])
		}
	}
	carrySourceCounts(rows, nil) // no old manifest: nothing to do, nothing to panic about
}

// The daily refresh commits only when the manifest moved: a figure that is kept
// must compare equal, one that changed must not.
func TestSameRows_SourceCount(t *testing.T) {
	a := []manifestRow{{Name: "x", Rev: "aaa", Count: 200, SourceCount: 540, Sources: []string{"s"}}}
	b := []manifestRow{{Name: "x", Rev: "aaa", Count: 200, SourceCount: 540, Sources: []string{"s"}}}
	if !sameRows(a, b) {
		t.Fatal("identical rows reported different")
	}
	b[0].SourceCount = 541
	if sameRows(a, b) {
		t.Fatal("a changed source_count was not noticed: the manifest would not be rewritten")
	}
}

func TestAggregateCIDRs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"sibling /24s merge", []string{"10.0.0.0/24", "10.0.1.0/24"}, []string{"10.0.0.0/23"}},
		{"contained dropped", []string{"10.0.0.0/16", "10.0.5.0/24", "10.0.9.128/25"}, []string{"10.0.0.0/16"}},
		{"non-siblings kept", []string{"10.0.0.0/24", "10.0.2.0/24"}, []string{"10.0.0.0/24", "10.0.2.0/24"}},
		{"four /24s collapse to /22", []string{"10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24", "10.0.1.0/24"}, []string{"10.0.0.0/22"}},
		{"unaligned pair not merged", []string{"10.0.1.0/24", "10.0.2.0/24"}, []string{"10.0.1.0/24", "10.0.2.0/24"}},
		{"floor: /8 siblings stay split", []string{"0.0.0.0/8", "1.0.0.0/8"}, []string{"0.0.0.0/8", "1.0.0.0/8"}},
		{"above floor: /9 siblings merge", []string{"0.0.0.0/9", "0.128.0.0/9"}, []string{"0.0.0.0/8"}},
		{"dedup identical", []string{"1.2.3.0/24", "1.2.3.0/24"}, []string{"1.2.3.0/24"}},
		{"single unchanged", []string{"203.0.113.0/24"}, []string{"203.0.113.0/24"}},
		{"host route normalized form", []string{"8.8.8.8/32", "8.8.8.9/32"}, []string{"8.8.8.8/31"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := aggregateCIDRs(c.in)
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("aggregateCIDRs(%v)\n  got  %v\n  want %v", c.in, got, want)
			}
		})
	}
}

func TestAggregateCIDRsOrderIndependent(t *testing.T) {
	fwd := aggregateCIDRs([]string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "172.16.0.0/16"})
	rev := aggregateCIDRs([]string{"172.16.0.0/16", "10.0.3.0/24", "10.0.2.0/24", "10.0.1.0/24", "10.0.0.0/24"})
	sort.Strings(fwd)
	sort.Strings(rev)
	if !reflect.DeepEqual(fwd, rev) {
		t.Errorf("order-dependent: %v vs %v", fwd, rev)
	}
	if len(fwd) != 2 { // 10.0.0.0/22 + 172.16.0.0/16
		t.Errorf("want 2 blocks, got %v", fwd)
	}
}

func TestDomainRank(t *testing.T) {
	// Lower rank string sorts first == kept first when capping.
	lessRanked := [][2]string{
		{"paypal.com", "paypal.com.hk"},
		{"paypal.com", "api.paypal.com"},
		{"a.io", "bbbb.io"},
		{"youtube.com", "www.youtube-nocookie.com"},
	}
	for _, p := range lessRanked {
		if !(domainRank(p[0]) < domainRank(p[1])) {
			t.Errorf("domainRank(%q)=%q should sort before domainRank(%q)=%q", p[0], domainRank(p[0]), p[1], domainRank(p[1]))
		}
	}
}

func TestPrefixLen(t *testing.T) {
	for in, want := range map[string]int{
		"1.2.3.0/24": 24, "10.0.0.0/8": 8, "8.8.8.8": 32, "1.2.3.4/32": 32,
	} {
		if got := prefixLen(in); got != want {
			t.Errorf("prefixLen(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestCIDRKeyOrders(t *testing.T) {
	xs := []string{"10.0.0.0/8", "1.2.3.0/24", "1.2.3.0/25", "203.0.113.0/24"}
	sort.Slice(xs, func(i, j int) bool { return cidrKey(xs[i]) < cidrKey(xs[j]) })
	want := []string{"1.2.3.0/24", "1.2.3.0/25", "10.0.0.0/8", "203.0.113.0/24"}
	if !reflect.DeepEqual(xs, want) {
		t.Errorf("cidrKey sort = %v, want %v", xs, want)
	}
}

func TestSameRows(t *testing.T) {
	a := []manifestRow{{Name: "x", Rev: "aaa", Count: 3, Sources: []string{"s"}}}
	b := []manifestRow{{Name: "x", Rev: "aaa", Count: 3, Sources: []string{"s"}}}
	if !sameRows(a, b) {
		t.Fatal("identical rows reported different")
	}
	b[0].Rev = "bbb"
	if sameRows(a, b) {
		t.Fatal("rev change not detected")
	}
	if sameRows(a, nil) {
		t.Fatal("length mismatch not detected")
	}
}

func TestReadEntries(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/x.lst"
	body := "# header\n# source: foo\n\nyoutube.com\nytimg.com\n\n# trailing comment\ngooglevideo.com\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got := readEntries(p)
	want := []string{"youtube.com", "ytimg.com", "googlevideo.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readEntries = %v, want %v", got, want)
	}
	if readEntries(dir+"/missing.lst") != nil {
		t.Error("missing file should return nil")
	}
}

func TestRenderListRoundTrips(t *testing.T) {
	entries := []string{"a.com", "b.com"}
	out := string(renderList("Example", "domains", []string{"src: x"}, entries))
	if !strings.Contains(out, "\na.com\nb.com\n") {
		t.Errorf("rendered list missing entries block:\n%s", out)
	}
	if !strings.HasPrefix(out, "# Example — домены\n") {
		t.Errorf("rendered list missing header:\n%s", out)
	}
}

// TestFetch_MalformedURLFailsFastNotPanics is PRE-03's regression test for
// the real risk the audit called out: http.NewRequest's error used to be
// dropped (req, _ := ...), so a malformed URL panicked on the very next
// line (req.Header.Set on a nil *http.Request) instead of returning an
// error. It must also fail on the first attempt, not retry -- a malformed
// URL/method is never transient, so looping (with fetch's own 3s
// inter-attempt sleep) would just waste time for no benefit.
func TestFetch_MalformedURLFailsFastNotPanics(t *testing.T) {
	start := time.Now()
	_, err := fetch("://bad")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("fetch(malformed URL): got nil error, want one")
	}
	if elapsed > time.Second {
		t.Errorf("fetch(malformed URL) took %s -- looks like it retried instead of failing fast", elapsed)
	}
}

// TestFetch_TruncatedBodyIsRetriedNotSilentlyAccepted is PRE-03's second
// regression test: io.ReadAll's error used to be dropped (b, _ := ...),
// so a connection that died mid-response silently produced a short,
// truncated "successful" result instead of retrying or erroring. The
// server advertises a Content-Length larger than what it actually sends,
// then closes the connection -- io.ReadAll must see that as an error on
// both of fetch's attempts (there's no working retry target here), and
// fetch must propagate it rather than returning the truncated body as if
// it were complete.
func TestFetch_TruncatedBodyIsRetriedNotSilentlyAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("ResponseWriter does not support hijacking")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close()
		fmt.Fprint(buf, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nshort")
		buf.Flush()
	}))
	defer srv.Close()

	orig := httpClient.Timeout
	httpClient.Timeout = 2 * time.Second
	defer func() { httpClient.Timeout = orig }()

	start := time.Now()
	_, err := fetch(srv.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("fetch(truncated body): got nil error, want one")
	}
	// Confirms it actually went through the 3s inter-attempt sleep (i.e.
	// treated the truncated read as retryable, same as any other
	// mid-transfer failure), not a fast-fail path.
	if elapsed < 3*time.Second {
		t.Errorf("fetch(truncated body) took %s -- want it to have retried once (~3s sleep)", elapsed)
	}
}
