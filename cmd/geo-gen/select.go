package main

import (
	"regexp"
	"sort"
	"strings"
)

// Which names of a service's list a domain preset keeps.
//
// A router's object-group holds a few hundred entries, so a big service (google,
// apple, microsoft, ...) does not fit. The first cut -- fewest labels first, then
// shortest name -- was a poor proxy for importance: ~190 country domains of
// Google ("google.ae", "google.bf", ... 9 characters each) ranked ahead of
// "google.com", and the list lost google.com, googleapis.com, gstatic.com,
// googleusercontent.com and googlevideo.com altogether. What the selection does
// now:
//
//  1. Collapse. A name whose parent domain is also in the list adds nothing: the
//     router's DNS routing includes subdomains ("*" is rejected as unnecessary,
//     see config.ClassifyRouteEntry). Only the roots are candidates, and each
//     root remembers how many names of the source it covers.
//  2. Pins. The service's own "keep" list (sources.json) comes first, in its
//     order -- the few names whose absence breaks the service, which no count
//     can tell from a defensive registration with the same coverage of one.
//  3. Country variants of one brand ("google.xx", "amazon.co.xx") go last, except
//     the head of the family -- the one that covers the most names.
//  4. The rest by coverage, then the old order (fewer labels, shorter).

// rootOf returns the farthest name of set that covers d -- d itself or a parent
// domain of it -- or "" when nothing in set does.
func rootOf(set map[string]struct{}, d string) string {
	top := ""
	if _, ok := set[d]; ok {
		top = d
	}
	for rest := d; ; {
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			return top
		}
		rest = rest[i+1:]
		if _, ok := set[rest]; ok {
			top = rest
		}
	}
}

// collapseDomains returns the roots of set -- the names with no parent domain in
// it -- and, for each root, how many names of the set it covers (itself and
// everything below it).
func collapseDomains(set map[string]struct{}) (roots []string, covers map[string]int) {
	covers = map[string]int{}
	for d := range set {
		top := rootOf(set, d) // never "": d is in the set
		if top == d {
			roots = append(roots, d)
		}
		covers[top]++
	}
	sort.Strings(roots)
	return roots, covers
}

// collapsedLen is how many entries of a written list would remain after the same
// collapse: what a list from before the collapse is worth today.
func collapsedLen(entries []string) int {
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		set[e] = struct{}{}
	}
	roots, _ := collapseDomains(set)
	return len(roots)
}

// countrySuffix matches what follows the brand label in a country variant:
// "com", a two-letter country code, or a second-level label plus a country code.
var countrySuffix = regexp.MustCompile(`^(com|[a-z]{2}|(com|net|org|co|ac|gov|edu)\.[a-z]{2})$`)

// minCountryFamily is how many roots must share a brand label (with country
// suffixes) before they count as a family of variants rather than a coincidence.
const minCountryFamily = 5

// countryVariants returns the roots to rank last: in every family of at least
// minCountryFamily roots sharing a brand label and a country-style suffix, all
// but the head -- the member covering the most names; on a tie the plain
// "<brand>.com", then the shortest.
func countryVariants(roots []string, covers map[string]int) map[string]bool {
	families := map[string][]string{}
	for _, r := range roots {
		i := strings.IndexByte(r, '.')
		if i <= 0 || !countrySuffix.MatchString(r[i+1:]) {
			continue
		}
		families[r[:i]] = append(families[r[:i]], r)
	}
	plainCom := func(r string) bool { return strings.HasSuffix(r, ".com") && strings.Count(r, ".") == 1 }
	headOver := func(a, b string) bool {
		if covers[a] != covers[b] {
			return covers[a] > covers[b]
		}
		if plainCom(a) != plainCom(b) {
			return plainCom(a)
		}
		return domainRank(a) < domainRank(b)
	}

	out := map[string]bool{}
	for _, fam := range families {
		if len(fam) < minCountryFamily {
			continue
		}
		head := fam[0]
		for _, r := range fam[1:] {
			if headOver(r, head) {
				head = r
			}
		}
		for _, r := range fam {
			if r != head {
				out[r] = true
			}
		}
	}
	return out
}

// selectDomains picks up to limit names from entries (the source list, already
// deduplicated and valid) by the rules above. roots is how many candidates there
// were after the collapse -- what the list would hold if it fitted -- and
// missingKeep the pins the source does not cover at all (a typo, or the upstream
// renamed them). A pin that a listed parent already covers is satisfied by the
// parent, which then holds the pin's place.
func selectDomains(entries, keep []string, limit int) (kept []string, roots int, missingKeep []string) {
	set := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		set[e] = struct{}{}
	}
	rs, covers := collapseDomains(set)

	pinRank := map[string]int{} // root -> the place of the first pin it holds
	for i, k := range keep {
		r := rootOf(set, k)
		if r == "" {
			missingKeep = append(missingKeep, k)
			continue
		}
		if _, held := pinRank[r]; !held {
			pinRank[r] = i
		}
	}
	variants := countryVariants(rs, covers)

	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		pa, aPinned := pinRank[a]
		pb, bPinned := pinRank[b]
		if aPinned != bPinned {
			return aPinned
		}
		if aPinned {
			return pa < pb
		}
		if variants[a] != variants[b] {
			return !variants[a]
		}
		if covers[a] != covers[b] {
			return covers[a] > covers[b]
		}
		return domainRank(a) < domainRank(b)
	})
	if len(rs) > limit {
		rs = rs[:limit]
	}
	return rs, len(covers), missingKeep
}
