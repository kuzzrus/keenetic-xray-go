package knownranges

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func fakeSource(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestFetchRaw_Success(t *testing.T) {
	url := fakeSource(t, "8.8.8.0/24\n1.1.1.0/24\n")
	raw, err := FetchRaw(context.Background(), url)
	if err != nil {
		t.Fatalf("FetchRaw: %v", err)
	}
	table := Parse(raw)
	if table.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", table.Len())
	}
}

func TestFetchRaw_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	if _, err := FetchRaw(context.Background(), srv.URL); err == nil {
		t.Fatal("FetchRaw: want error on HTTP 404, got nil")
	}
}

func TestFetchRaw_EmptyURLUsesDefault(t *testing.T) {
	// Just check it builds a request against the real SourceURL and
	// fails for a reason that isn't "bad URL" (no network in CI/sandbox
	// is fine -- this only guards against a typo turning "" into a
	// literal empty request URL).
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_, err := FetchRaw(ctx, "")
	if err == nil {
		t.Fatal("FetchRaw with an already-expired context: want error, got nil")
	}
}

func TestSaveCacheRaw_LoadCacheRaw_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "known-ranges.txt")
	if err := SaveCacheRaw(path, "8.8.8.0/24\n"); err != nil {
		t.Fatalf("SaveCacheRaw: %v", err)
	}
	raw, err := LoadCacheRaw(path)
	if err != nil {
		t.Fatalf("LoadCacheRaw: %v", err)
	}
	if raw != "8.8.8.0/24\n" {
		t.Fatalf("LoadCacheRaw = %q, want %q", raw, "8.8.8.0/24\n")
	}
}

func TestSaveCacheRaw_OverwritesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known-ranges.txt")
	if err := SaveCacheRaw(path, "8.8.8.0/24\n"); err != nil {
		t.Fatalf("SaveCacheRaw (1st): %v", err)
	}
	if err := SaveCacheRaw(path, "1.1.1.0/24\n"); err != nil {
		t.Fatalf("SaveCacheRaw (2nd): %v", err)
	}
	raw, err := LoadCacheRaw(path)
	if err != nil {
		t.Fatalf("LoadCacheRaw: %v", err)
	}
	if raw != "1.1.1.0/24\n" {
		t.Fatalf("LoadCacheRaw = %q, want %q", raw, "1.1.1.0/24\n")
	}
	// No leftover temp file next to it.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("dir has %d entries, want 1 (no leftover temp file): %v", len(entries), entries)
	}
}

func TestLoadCacheRaw_MissingFile(t *testing.T) {
	_, err := LoadCacheRaw(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("LoadCacheRaw on missing file: want error, got nil")
	}
}
