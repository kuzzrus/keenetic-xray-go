package presets

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strings"
	"testing"
)

func revOf(entries []string) string {
	h := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(h[:])[:12]
}

func TestManifestLoads(t *testing.T) {
	all := All()
	if len(all) < 50 {
		t.Fatalf("expected many presets, got %d", len(all))
	}
	if Generated() == "" {
		t.Error("Generated() empty")
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Name >= all[i].Name {
			t.Fatalf("All() not sorted by name: %q then %q", all[i-1].Name, all[i].Name)
		}
	}
	for _, p := range all {
		if p.Name == "" || p.Title == "" || p.Category == "" || p.Rev == "" {
			t.Errorf("preset %+v missing a required field", p)
		}
		if p.Kind != "domains" && p.Kind != "cidr" {
			t.Errorf("preset %q: bad kind %q", p.Name, p.Kind)
		}
		if p.Count <= 0 {
			t.Errorf("preset %q: count %d", p.Name, p.Count)
		}
	}
}

// TestManifestMatchesFiles is the guard against a hand-edited or
// half-regenerated data/ dir: every manifest row must have a matching
// .lst whose entry count and content hash are exactly what the row
// claims.
func TestManifestMatchesFiles(t *testing.T) {
	for _, p := range All() {
		ent, ok := Entries(p.Name)
		if !ok {
			t.Errorf("%s: no data/%s.lst for manifest row", p.Name, p.Name)
			continue
		}
		if len(ent) != p.Count {
			t.Errorf("%s: manifest count %d, file has %d", p.Name, p.Count, len(ent))
		}
		if got := revOf(ent); got != p.Rev {
			t.Errorf("%s: manifest rev %s, file hashes to %s", p.Name, p.Rev, got)
		}
		if !sort.StringsAreSorted(ent) && p.Kind == "domains" {
			t.Errorf("%s: domain entries not sorted", p.Name)
		}
	}
}

func TestEntriesKindMatchesContent(t *testing.T) {
	for _, p := range All() {
		ent, _ := Entries(p.Name)
		for _, e := range ent {
			isCIDR := strings.Contains(e, "/") || net.ParseIP(e) != nil
			if p.Kind == "cidr" && !strings.Contains(e, "/") {
				t.Errorf("%s (cidr): %q is not a CIDR", p.Name, e)
			}
			if p.Kind == "domains" && isCIDR {
				t.Errorf("%s (domains): %q looks like an IP/CIDR", p.Name, e)
			}
		}
	}
}

func TestFind(t *testing.T) {
	if _, ok := Find("youtube"); !ok {
		t.Error("Find(youtube) missing")
	}
	if _, ok := Find("  YouTube "); !ok {
		t.Error("Find should trim and lowercase")
	}
	if _, ok := Find("definitely-not-a-preset"); ok {
		t.Error("Find returned a bogus preset")
	}
}

func TestEntries(t *testing.T) {
	yt, ok := Entries("youtube")
	if !ok || len(yt) < 20 {
		t.Fatalf("youtube entries: ok=%v n=%d", ok, len(yt))
	}
	for _, d := range yt {
		if strings.HasPrefix(d, "#") || d == "" || strings.ContainsAny(d, " \t") {
			t.Errorf("dirty entry %q", d)
		}
	}
	if _, ok := Entries("nope-nope"); ok {
		t.Error("Entries returned data for unknown preset")
	}
}

func TestByCategory(t *testing.T) {
	cats := ByCategory()
	if len(cats) < 5 {
		t.Fatalf("expected several categories, got %d", len(cats))
	}
	seenYouTube := false
	for _, c := range cats {
		if c.Name == "" || len(c.Presets) == 0 {
			t.Errorf("empty category %+v", c)
		}
		for _, p := range c.Presets {
			if p.Kind != "domains" {
				t.Errorf("ByCategory leaked a non-domain preset %q", p.Name)
			}
			if strings.HasSuffix(p.Name, "-ip") {
				t.Errorf("ByCategory leaked a CIDR companion %q", p.Name)
			}
			if p.Name == "youtube" {
				seenYouTube = true
			}
		}
		if !sort.SliceIsSorted(c.Presets, func(i, j int) bool { return c.Presets[i].Title < c.Presets[j].Title }) {
			t.Errorf("category %q not sorted by title", c.Name)
		}
	}
	if !seenYouTube {
		t.Error("youtube preset not found in any category")
	}
}

func TestHasCIDR(t *testing.T) {
	if !HasCIDR("youtube") {
		t.Error("youtube should have a -ip companion")
	}
	if HasCIDR("netflix") {
		t.Error("netflix has no -ip companion")
	}
}
