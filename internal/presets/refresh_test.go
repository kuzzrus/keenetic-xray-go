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
