package presets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withOverlay points the package at dir for one test and restores the
// embed-only state afterwards (SetOverlay is process-global).
func withOverlay(t *testing.T, dir string) {
	t.Helper()
	SetOverlay(dir)
	t.Cleanup(func() { SetOverlay(""); reload() })
}

func fakeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	mux := http.NewServeMux()
	for name, body := range files {
		b := body
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, b) })
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func manifestJSON(rows ...Preset) string {
	m := manifest{Version: 1, Generated: "2026-09-09", Categories: []string{"Тест"}, Presets: rows}
	b, _ := json.Marshal(m)
	return string(b)
}

// list builds a preset row whose Rev/Count match the given entries, plus
// the .lst body -- mirroring what cmd/geo-gen writes.
func list(name, kind, title string, entries ...string) (Preset, string) {
	return Preset{
		Name: name, Service: strings.TrimSuffix(name, "-ip"), Title: title,
		Category: "Тест", Kind: kind, Count: len(entries), Rev: revOf(entries),
	}, "# " + title + "\n\n" + strings.Join(entries, "\n") + "\n"
}

func TestRefresh_WritesOverlayAndServesIt(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)

	pDom, bDom := list("acme", "domains", "Acme", "alpha.example", "beta.example", "gamma.example")
	pIP, bIP := list("acme-ip", "cidr", "Acme", "203.0.113.0/24", "198.51.100.0/24")
	base := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(pDom, pIP),
		"acme.lst":      bDom,
		"acme-ip.lst":   bIP,
	})

	res, err := Refresh(context.Background(), base)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.Updated != 2 || res.Failed != 0 {
		t.Fatalf("Result = %+v, want Updated 2 Failed 0", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "acme.lst")); err != nil {
		t.Errorf("overlay acme.lst not written: %v", err)
	}
	if Generated() != "2026-09-09" {
		t.Errorf("Generated() = %q, want the fetched date", Generated())
	}
	got, ok := Entries("acme")
	if !ok || strings.Join(got, ",") != "alpha.example,beta.example,gamma.example" {
		t.Errorf("Entries(acme) = %v (%v)", got, ok)
	}
	if p, ok := Find("acme"); !ok || p.Title != "Acme" || p.Count != 3 {
		t.Errorf("Find(acme) = %+v (%v)", p, ok)
	}

	// Second run: nothing changed upstream -> all skipped, no error.
	res2, err := Refresh(context.Background(), base)
	if err != nil || res2.Updated != 0 || res2.Skipped != 2 {
		t.Fatalf("second Refresh = %+v, %v; want all skipped", res2, err)
	}
}

func TestRefresh_DropsInvalidLines(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)
	base := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(Preset{Name: "acme", Kind: "domains", Count: 3, Rev: "x", Title: "Acme", Category: "Тест"}),
		// one good, one wildcard (rejected), one blank, one IPv6 (rejected), one dupe
		"acme.lst": "good.example\n*.bad.example\n\ndead:beef::1\ngood.example\nfine.example\n",
	})
	res, err := Refresh(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Entries("acme")
	if strings.Join(got, ",") != "fine.example,good.example" && strings.Join(got, ",") != "good.example,fine.example" {
		t.Errorf("kept %v, want just the two valid uniques", got)
	}
	_ = res
}

func TestRefresh_KeepsPreviousOnCollapse(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)

	full := "a.example\nb.example\nc.example\nd.example\ne.example\nf.example\ng.example\nh.example\ni.example\nj.example\n"
	base1 := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(Preset{Name: "acme", Kind: "domains", Count: 10, Rev: "r1", Title: "Acme", Category: "Тест"}),
		"acme.lst":      full,
	})
	if _, err := Refresh(context.Background(), base1); err != nil {
		t.Fatal(err)
	}
	before, _ := Entries("acme")
	if len(before) != 10 {
		t.Fatalf("setup: got %d entries", len(before))
	}

	// Upstream now returns a near-empty list (looks like a broken fetch).
	base2 := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(Preset{Name: "acme", Kind: "domains", Count: 10, Rev: "r2", Title: "Acme", Category: "Тест"}),
		"acme.lst":      "a.example\n",
	})
	res, err := Refresh(context.Background(), base2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 {
		t.Errorf("Result = %+v, want Failed 1 (collapse guard)", res)
	}
	after, _ := Entries("acme")
	if len(after) != 10 {
		t.Errorf("list collapsed to %d entries; the guard should have kept the previous 10", len(after))
	}
}

func TestRefresh_FallsBackToEmbedOnFetchError(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)
	// Manifest names a real embedded preset but its .lst 404s.
	yt, _ := Entries("youtube") // from the embed, before overlay has anything
	base := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(Preset{Name: "youtube", Kind: "domains", Count: len(yt) + 5, Rev: "different", Title: "YouTube", Category: "Видео"}),
		// no youtube.lst handler -> 404
	})
	res, err := Refresh(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 {
		t.Errorf("Result = %+v, want Failed 1", res)
	}
	got, ok := Entries("youtube")
	if !ok || len(got) != len(yt) {
		t.Errorf("Entries(youtube) = %d, want embed fallback of %d", len(got), len(yt))
	}
}

func TestRefresh_NoOverlayConfigured(t *testing.T) {
	SetOverlay("")
	defer reload()
	if _, err := Refresh(context.Background(), "http://example.invalid"); err == nil {
		t.Fatal("expected an error when no overlay dir is set")
	}
}

// TestValidPresetName is PRE-02's core allowlist test.
func TestValidPresetName(t *testing.T) {
	ok := []string{"youtube", "youtube-ip", "x-twitter", "a", "google-ai"}
	bad := []string{"", "..", "../evil", "/etc/passwd", "a/b", "a.lst", "UPPER", "with space", "with_underscore"}
	for _, n := range ok {
		if !validPresetName(n) {
			t.Errorf("validPresetName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validPresetName(n) {
			t.Errorf("validPresetName(%q) = true, want false", n)
		}
	}
}

// TestRefresh_RejectsPathTraversalName is PRE-02's regression test for the
// write-side path traversal the audit flagged: row.Name becomes a bare
// filename joined onto the overlay dir with no validation. A manifest
// entry shaped like a path must be rejected outright, before it ever
// reaches filepath.Join, not just fail some later step.
func TestRefresh_RejectsPathTraversalName(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)

	evil := Preset{Name: "../evil", Kind: "domains", Count: 1, Rev: "x", Title: "Evil", Category: "Тест"}
	base := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(evil),
		"../evil.lst":   "owned.example\n",
	})

	res, err := Refresh(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 {
		t.Errorf("Result = %+v, want Failed 1 (bad name rejected)", res)
	}
	// Nothing must have been written outside the overlay dir.
	outside := filepath.Join(filepath.Dir(dir), "evil.lst")
	if _, err := os.Stat(outside); err == nil {
		t.Errorf("a file was written outside the overlay dir: %s", outside)
	}
	if _, ok := Find("../evil"); ok {
		t.Error("the path-traversal-named preset should not be servable")
	}
}

// TestRefresh_WriteFailureFallsBackToEmbed is PRE-02's regression test
// for the worse-than-assumed failure mode the audit's re-verification
// found: a write failure used to drop the preset from the index
// entirely, not "fall back to the embedded default" as it looked like
// at a glance. Pre-creates the target .lst path as a directory so
// writeFileAtomic's final rename onto it fails.
func TestRefresh_WriteFailureFallsBackToEmbed(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)
	if err := os.MkdirAll(filepath.Join(dir, "youtube.lst"), 0o755); err != nil {
		t.Fatal(err)
	}

	yt, _ := Entries("youtube") // the embedded copy, before overlay has anything real
	base := fakeRepo(t, map[string]string{
		"manifest.json": manifestJSON(Preset{Name: "youtube", Kind: "domains", Count: len(yt), Rev: "different", Title: "YouTube", Category: "Видео"}),
		"youtube.lst":   strings.Join(yt, "\n") + "\n",
	})

	res, err := Refresh(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed != 1 {
		t.Errorf("Result = %+v, want Failed 1 (write error)", res)
	}
	if _, ok := Find("youtube"); !ok {
		t.Fatal("youtube vanished from the index entirely instead of falling back to the embed")
	}
	got, ok := Entries("youtube")
	if !ok || len(got) != len(yt) {
		t.Errorf("Entries(youtube) = %d entries, want the embed fallback of %d", len(got), len(yt))
	}
}

// TestHttpGet_OversizedResponseErrorsInsteadOfTruncating is PRE-02's
// regression test for the third integrity gap: io.LimitReader(body,
// limit) alone silently truncates a larger response to exactly limit
// bytes with no error -- the .lst-fetch analog of SUB-01's bug, one HTTP
// response over.
func TestHttpGet_OversizedResponseErrorsInsteadOfTruncating(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "0123456789") // 10 bytes
	}))
	defer srv.Close()

	_, err := httpGet(context.Background(), srv.Client(), srv.URL, 5)
	if err == nil {
		t.Fatal("httpGet with a 10-byte response and a 5-byte limit: want an error, got nil")
	}
}

// TestSnapshot_FiltersPathTraversalNameFromOnDiskManifest is PRE-02's
// read-side regression test: an overlay manifest.json is untrusted
// whether it was just fetched or was already sitting on disk (corrupted,
// hand-edited, or written by an older unpatched build) -- snapshot()
// must filter row names the same way Refresh does, not just trust
// whatever's already on the filesystem.
func TestSnapshot_FiltersPathTraversalNameFromOnDiskManifest(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)

	raw := manifestJSON(
		Preset{Name: "../evil", Kind: "domains", Count: 1, Rev: "x", Title: "Evil", Category: "Тест"},
		Preset{Name: "acme", Kind: "domains", Count: 1, Rev: "y", Title: "Acme", Category: "Тест"},
	)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "acme.lst"), []byte("good.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reload()

	if _, ok := Find("../evil"); ok {
		t.Error("path-traversal-named entry loaded from an on-disk manifest should be filtered out")
	}
	if _, ok := Find("acme"); !ok {
		t.Error("the legitimate sibling entry should still load")
	}
	for _, p := range All() {
		if p.Name == "../evil" {
			t.Error("../evil leaked into All()")
		}
	}
}
