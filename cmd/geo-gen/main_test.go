package main

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

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
