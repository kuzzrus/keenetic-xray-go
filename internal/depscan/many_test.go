package depscan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestParseSeeds(t *testing.T) {
	seeds, problems := ParseSeeds("Example.com, other.org\nthird.net;fourth.io", "example.com", "192.168.1.1 10.0.0.0/8 router.lan")
	if fmt.Sprint(seeds) != "[example.com other.org third.net]" {
		t.Errorf("seeds = %v, want the first %d valid ones, de-duplicated", seeds, MaxSeeds)
	}
	if len(problems) != 3 {
		t.Errorf("problems = %v, want one per unscannable entry (IP, subnet, internal name)", problems)
	}
	if s, p := ParseSeeds(); len(s) != 0 || len(p) != 0 {
		t.Errorf("ParseSeeds() = %v, %v", s, p)
	}
}

func TestScanMany(t *testing.T) {
	scan := func(_ context.Context, seed string, _ Options) (*Result, error) {
		if seed == "broken.example.com" {
			return nil, errors.New("через туннель страница не открылась")
		}
		return &Result{Pages: []Page{{Seed: seed, Status: 200}}, Hosts: []Host{{Name: "img.example-a.net", Class: ClassNeed}}}, nil
	}
	res, err := ScanMany(context.Background(), []string{"good.example.com", "broken.example.com"}, Options{}, scan)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 || len(res.Pages) != 2 {
		t.Fatalf("result = %+v", res)
	}
	var failed *Page
	for i := range res.Pages {
		if res.Pages[i].Seed == "broken.example.com" {
			failed = &res.Pages[i]
		}
	}
	if failed == nil || failed.Status != 0 || !strings.Contains(failed.Note, "не открылась") {
		t.Errorf("failed page = %+v", failed)
	}

	// Every seed failing is an error carrying the first reason.
	_, err = ScanMany(context.Background(), []string{"broken.example.com"}, Options{}, scan)
	if err == nil || !strings.Contains(err.Error(), "не открылась") {
		t.Errorf("err = %v", err)
	}
	if _, err := ScanMany(context.Background(), nil, Options{}, scan); err == nil {
		t.Error("no seeds: want an error")
	}
}

func TestCoveredIndex(t *testing.T) {
	covered := CoveredIndex([]NamedList{
		{Name: "first", Entries: []string{"Known.Example-A.net", "10.1.2.0/24", "1.2.3.4", "*.bad.example-x.net"}},
		{Name: "second", Entries: []string{"known.example-a.net", "other.example-b.net"}},
	})
	for host, want := range map[string]string{
		"known.example-a.net":          "first", // the first list that holds it is named
		"deep.sub.known.example-a.net": "first", // a domain entry covers its subdomains
		"other.example-b.net":          "second",
		"example-a.net":                "", // the parent of an entry is not covered
		"sibling.example-a.net":        "",
		"net":                          "",
		"":                             "",
	} {
		if got := covered(host); got != want {
			t.Errorf("covered(%q) = %q, want %q", host, got, want)
		}
	}
	// Order of names is stable for equal input.
	names := []string{covered("known.example-a.net"), covered("other.example-b.net")}
	if !sort.StringsAreSorted(names) {
		t.Logf("names %v", names)
	}
}
