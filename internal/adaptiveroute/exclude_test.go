package adaptiveroute

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeExclusion(t *testing.T) {
	good := map[string]string{
		"1.2.3.4":        "1.2.3.4",
		" 1.2.3.4 ":      "1.2.3.4",
		"1.2.3.4/32":     "1.2.3.4",
		"10.1.2.3/24":    "10.1.2.0/24",
		"142.251.0.0/16": "142.251.0.0/16",
		"8.0.0.0/8":      "8.0.0.0/8",
	}
	for in, want := range good {
		got, err := NormalizeExclusion(in)
		if err != nil || got != want {
			t.Errorf("NormalizeExclusion(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "  ", "garbage", "::1", "2001:db8::/32", "1.2.3.4/33", "1.2.3.4/x",
		"0.0.0.0/0", "10.0.0.0/7", "1.2.3"}
	for _, in := range bad {
		if got, err := NormalizeExclusion(in); err == nil {
			t.Errorf("NormalizeExclusion(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseExclusions(t *testing.T) {
	text := "# my list\n\n" +
		"142.251.153.4   # a google front end\n" +
		"  8.8.8.0/24\n" +
		"142.251.153.4\n" + // duplicate
		"not-an-address\n" +
		"10.0.0.0/4\n" + // too wide
		"1.1.1.1/32\n"
	e := parseExclusions(text)
	want := []string{"1.1.1.1", "142.251.153.4", "8.8.8.0/24"}
	if got := e.Entries(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Entries = %v, want %v", got, want)
	}
	if e.Skipped != 2 {
		t.Errorf("Skipped = %d, want 2 (the garbage line and the /4)", e.Skipped)
	}
	if e.Len() != 3 {
		t.Errorf("Len = %d, want 3", e.Len())
	}
}

func TestExclusions_ContainsAndOverlaps(t *testing.T) {
	e := parseExclusions("142.251.153.4\n8.8.8.0/24\n31.13.0.0/16\n")
	contains := map[string]bool{
		"142.251.153.4": true, "142.251.153.5": false,
		"8.8.8.200": true, "8.8.9.1": false,
		"31.13.72.9": true, "31.14.0.1": false,
		"not-an-ip": false, "8.8.8.0/24": false, "::1": false,
	}
	for ip, want := range contains {
		if got := e.Contains(ip); got != want {
			t.Errorf("Contains(%q) = %v, want %v", ip, got, want)
		}
	}
	overlaps := map[string]bool{
		"142.251.153.0/24": true,  // contains the excluded /32
		"142.251.154.0/24": false, // next /24
		"8.8.8.0/25":       true,  // inside the excluded /24
		"8.8.9.0/24":       false,
		"31.13.72.0/24":    true, // inside the excluded /16
		"31.0.0.0/8":       true, // contains the excluded /16
		"142.251.153.4":    true, // a bare address behaves like a /32
		"9.9.9.9":          false,
		"garbage":          false,
	}
	for c, want := range overlaps {
		if got := e.Overlaps(c); got != want {
			t.Errorf("Overlaps(%q) = %v, want %v", c, got, want)
		}
	}
	var none *Exclusions
	if none.Contains("1.2.3.4") || none.Overlaps("1.2.3.0/24") || none.Len() != 0 {
		t.Error("a nil list must exclude nothing")
	}
}

func TestAddRemoveExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "adaptive-exclude.txt") // the directory does not exist yet

	c, added, err := AddExclusion(path, " 142.251.153.4/32 ")
	if err != nil || !added || c != "142.251.153.4" {
		t.Fatalf("first add = %q, %v, %v", c, added, err)
	}
	if _, added, err := AddExclusion(path, "142.251.153.4"); err != nil || added {
		t.Errorf("second add of the same entry = added %v, err %v; want a no-op", added, err)
	}
	if _, _, err := AddExclusion(path, "8.8.8.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddExclusion(path, "bogus"); err == nil {
		t.Error("adding a bogus entry should fail")
	}

	// A hand-edited file: comments and an unknown line must survive our edits.
	data, _ := os.ReadFile(path)
	hand := "# keep me\n" + string(data) + "garbage line\n"
	if err := os.WriteFile(path, []byte(hand), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, removed, err := RemoveExclusion(path, "142.251.153.4"); err != nil || !removed {
		t.Fatalf("remove = removed %v, err %v", removed, err)
	}
	after, _ := os.ReadFile(path)
	if !strings.Contains(string(after), "# keep me") || !strings.Contains(string(after), "garbage line") ||
		!strings.Contains(string(after), "8.8.8.0/24") || strings.Contains(string(after), "142.251.153.4") {
		t.Errorf("file after remove = %q", after)
	}
	if _, removed, err := RemoveExclusion(path, "142.251.153.4"); err != nil || removed {
		t.Errorf("removing an absent entry = removed %v, err %v; want a quiet no-op", removed, err)
	}
	if _, removed, err := RemoveExclusion(filepath.Join(t.TempDir(), "missing.txt"), "1.2.3.4"); err != nil || removed {
		t.Errorf("removing from a missing file = removed %v, err %v; want a quiet no-op", removed, err)
	}

	ex, err := LoadExclusions(path)
	if err != nil || ex.Len() != 1 || !ex.Contains("8.8.8.77") {
		t.Errorf("LoadExclusions after the edits = %v, %v", ex.Entries(), err)
	}
}

func TestAddExclusion_Limit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.txt")
	var b strings.Builder
	for i := 0; i < maxExclusions; i++ {
		fmt.Fprintf(&b, "1.%d.%d.%d\n", i/65536, (i/256)%256, i%256)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AddExclusion(path, "9.9.9.9"); err == nil || !strings.Contains(err.Error(), "предел") {
		t.Errorf("adding past the limit = %v, want the limit error", err)
	}
	if _, added, err := AddExclusion(path, "1.0.0.5"); err != nil || added {
		t.Errorf("re-adding an existing entry at the limit = added %v, err %v; want a no-op", added, err)
	}
}

func TestLoadExclusions_MissingFileIsEmpty(t *testing.T) {
	ex, err := LoadExclusions(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil || ex.Len() != 0 {
		t.Errorf("LoadExclusions(missing) = %v, %v; want an empty list", ex.Entries(), err)
	}
}

func TestExclusionsPath(t *testing.T) {
	got := ExclusionsPath(filepath.Join("opt", "etc", "keenetic-xray", "config.json"))
	want := filepath.Join("opt", "etc", "keenetic-xray", "adaptive-exclude.txt")
	if got != want {
		t.Errorf("ExclusionsPath = %q, want %q", got, want)
	}
}

func TestExclusionsWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adaptive-exclude.txt")
	w := &ExclusionsWatcher{Path: path}

	ex, changed := w.Get()
	if !changed || ex.Len() != 0 {
		t.Fatalf("first Get on a missing file = %v entries, changed %v; want empty and changed", ex.Len(), changed)
	}
	if _, changed := w.Get(); changed {
		t.Error("second Get with nothing new reported a change")
	}

	if err := os.WriteFile(path, []byte("1.2.3.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t1 := time.Now().Add(-time.Hour)
	_ = os.Chtimes(path, t1, t1)
	ex, changed = w.Get()
	if !changed || !ex.Contains("1.2.3.4") {
		t.Fatalf("Get after writing the file = contains %v, changed %v", ex.Contains("1.2.3.4"), changed)
	}
	if _, changed := w.Get(); changed {
		t.Error("Get with an untouched file reported a change")
	}

	if err := os.WriteFile(path, []byte("1.2.3.4\n5.6.7.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t2 := t1.Add(time.Minute)
	_ = os.Chtimes(path, t2, t2)
	ex, changed = w.Get()
	if !changed || !ex.Contains("5.6.7.8") {
		t.Errorf("Get after an edit = contains %v, changed %v", ex.Contains("5.6.7.8"), changed)
	}

	_ = os.Remove(path)
	ex, changed = w.Get()
	if !changed || ex.Len() != 0 {
		t.Errorf("Get after deleting the file = %d entries, changed %v; want empty and changed", ex.Len(), changed)
	}
	if _, changed := w.Get(); changed {
		t.Error("a second Get on a still-missing file reported a change")
	}
}
