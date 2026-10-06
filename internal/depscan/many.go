package depscan

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// MaxSeeds is how many domains one scan command looks at: they run in
// parallel on a small router, each with its own page fetch and probes.
const MaxSeeds = 3

// ParseSeeds reads domains out of free text (the entries an operator
// pasted, or command arguments: separated by spaces, commas, semicolons or
// newlines). It returns the valid, de-duplicated ones -- at most MaxSeeds --
// and one message per entry that cannot be scanned (an IP, a subnet, an
// internal name). Entries beyond the cap are dropped silently: the caller
// has what it can scan.
func ParseSeeds(args ...string) (seeds, problems []string) {
	return parseSeeds(MaxSeeds, args)
}

// CountSeeds is how many distinct scannable domains args hold, with no cap:
// the caller says "the first MaxSeeds of N" when N is larger.
func CountSeeds(args ...string) int {
	seeds, _ := parseSeeds(0, args)
	return len(seeds)
}

// parseSeeds is ParseSeeds with the cap as a parameter; limit <= 0 means none.
func parseSeeds(limit int, args []string) (seeds, problems []string) {
	seen := map[string]struct{}{}
	for _, a := range args {
		for _, raw := range strings.FieldsFunc(a, func(r rune) bool {
			return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '\r'
		}) {
			name, err := ValidSeed(raw)
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			if limit <= 0 || len(seeds) < limit {
				seeds = append(seeds, name)
			}
		}
	}
	return seeds, problems
}

// ScanFunc is Scan's shape, so a caller can inject a stand-in.
type ScanFunc func(ctx context.Context, seed string, o Options) (*Result, error)

// ScanMany scans every seed at once and merges the answers (Merge). A seed
// whose page could not be read still appears in the result -- as a Page
// with Status 0 and the reason in Note -- so the operator sees which of
// their domains was skipped and why; only when every seed fails is that an
// error.
func ScanMany(ctx context.Context, seeds []string, o Options, scan ScanFunc) (*Result, error) {
	if scan == nil {
		scan = Scan
	}
	results := make([]*Result, len(seeds))
	errs := make([]error, len(seeds))
	var wg sync.WaitGroup
	for i, s := range seeds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = scan(ctx, s, o)
		}()
	}
	wg.Wait()

	var good []*Result
	var failed []Page
	var firstErr error
	for i, r := range results {
		if errs[i] != nil {
			if firstErr == nil {
				firstErr = errs[i]
			}
			failed = append(failed, Page{Seed: seeds[i], Note: errs[i].Error()})
			continue
		}
		good = append(good, r)
	}
	if len(good) == 0 {
		if firstErr == nil {
			firstErr = errors.New("нечего сканировать")
		}
		return nil, firstErr
	}
	merged := Merge(good...)
	merged.Pages = append(merged.Pages, failed...)
	return merged, nil
}

// NamedList is a route list as the scan needs to see it.
type NamedList struct {
	Name    string
	Entries []string
}

// CoveredIndex builds Options.Covered from the lists that currently route
// traffic. A domain entry covers itself and every subdomain, as on the
// router; subnets and addresses cover no hostname. When two lists hold the
// same domain, the first one given is named.
func CoveredIndex(lists []NamedList) func(host string) string {
	idx := map[string]string{}
	for _, l := range lists {
		for _, e := range l.Entries {
			kind, norm, err := config.ClassifyRouteEntry(e)
			if err != nil || kind != config.RouteDomain {
				continue
			}
			if _, dup := idx[norm]; !dup {
				idx[norm] = l.Name
			}
		}
	}
	return func(host string) string {
		for h := host; h != ""; {
			if name, ok := idx[h]; ok {
				return name
			}
			i := strings.IndexByte(h, '.')
			if i < 0 {
				break
			}
			h = h[i+1:]
		}
		return ""
	}
}
