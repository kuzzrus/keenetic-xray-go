package susanincore

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildTarGz packs files (path -> content) into an in-memory gzip-compressed
// tar archive, flat like upstream's own release layout.
func buildTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %q: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeRelease serves a vendored-asset layout: susanin-<version>-linux-<goarch>.tar.gz
// and its .sha256 (sha256sum format), the same shape susanin-core.yml uploads.
func fakeRelease(t *testing.T, version string, files map[string]string) (baseURL, assetName string) {
	t.Helper()
	assetName = fmt.Sprintf("susanin-%s-linux-%s.tar.gz", version, runtime.GOARCH)
	payload := buildTarGz(t, files)
	sum := sha256.Sum256(payload)
	sha := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), assetName)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+version+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/"+version+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sha)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, assetName
}

func TestPinnedVersion_Sane(t *testing.T) {
	if PinnedVersion == "" {
		t.Fatal("PinnedVersion must not be empty")
	}
}

func TestPinnedVersion_MatchesPackagingPin(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "susanin-core", "version"))
	if err != nil {
		t.Fatalf("reading packaging/susanin-core/version: %v", err)
	}
	if pinned := strings.TrimSpace(string(data)); pinned != PinnedVersion {
		t.Errorf("PinnedVersion = %q but packaging/susanin-core/version = %q -- keep them in sync", PinnedVersion, pinned)
	}
}

func TestEnsure_ExtractsAndSmokeTests(t *testing.T) {
	base, _ := fakeRelease(t, PinnedVersion, map[string]string{
		"susanin-agent": "PACKED-SUSANIN-BINARY",
		"install.sh":    "#!/bin/sh\necho hi\n",
		"susanin.sh":    "#!/bin/sh\n",
	})

	var smokedBin string
	dir, err := Ensure(context.Background(), Options{
		BaseURL: base,
		smoke: func(bin string) error {
			smokedBin = bin
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	if smokedBin != filepath.Join(dir, "susanin-agent") {
		t.Errorf("smoke tested %q, want the extracted susanin-agent path", smokedBin)
	}
	got, err := os.ReadFile(filepath.Join(dir, "susanin-agent"))
	if err != nil || string(got) != "PACKED-SUSANIN-BINARY" {
		t.Fatalf("extracted susanin-agent = %q (%v)", got, err)
	}
	if _, err := os.ReadFile(filepath.Join(dir, "install.sh")); err != nil {
		t.Errorf("install.sh not extracted alongside the binary: %v", err)
	}
	if runtime.GOOS != "windows" { // Windows has no exec bit
		if fi, _ := os.Stat(filepath.Join(dir, "susanin-agent")); fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("extracted binary is not executable: %v", fi.Mode())
		}
	}
	// The archive itself is a scratch file, not part of what callers need.
	if _, err := os.Stat(filepath.Join(dir, "susanin-"+PinnedVersion+"-linux-"+runtime.GOARCH+".tar.gz")); !os.IsNotExist(err) {
		t.Error("the downloaded archive should have been removed after extraction")
	}
}

func TestEnsure_MissingBinaryInArchiveErrors(t *testing.T) {
	base, _ := fakeRelease(t, PinnedVersion, map[string]string{
		"install.sh": "#!/bin/sh\n", // no susanin-agent
	})
	dir, err := Ensure(context.Background(), Options{
		BaseURL: base,
		smoke:   func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected an error when the archive has no susanin-agent")
	}
	if dir != "" {
		t.Errorf("returned dir = %q, want empty on error", dir)
	}
}

func TestEnsure_SmokeFailureCleansUp(t *testing.T) {
	base, _ := fakeRelease(t, PinnedVersion, map[string]string{
		"susanin-agent": "BROKEN",
	})
	dir, err := Ensure(context.Background(), Options{
		BaseURL: base,
		smoke:   func(string) error { return fmt.Errorf("exec format error") },
	})
	if err == nil {
		t.Fatal("expected an error when the extracted binary doesn't run")
	}
	if dir != "" {
		t.Errorf("returned dir = %q, want empty on error", dir)
	}
}

func TestEnsure_ChecksumMismatchErrorsAndCleansUp(t *testing.T) {
	assetName := fmt.Sprintf("susanin-%s-linux-%s.tar.gz", PinnedVersion, runtime.GOARCH)
	payload := buildTarGz(t, map[string]string{"susanin-agent": "X"})
	mux := http.NewServeMux()
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("a", 64), assetName) // wrong hash
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir, err := Ensure(context.Background(), Options{
		BaseURL: srv.URL,
		smoke:   func(string) error { return fmt.Errorf("should never be called") },
	})
	if err == nil {
		t.Fatal("expected an error on checksum mismatch (susanincore has no opkg fallback)")
	}
	if dir != "" {
		t.Errorf("returned dir = %q, want empty on error", dir)
	}
}

func TestEnsure_UnreachableBaseURLErrors(t *testing.T) {
	dir, err := Ensure(context.Background(), Options{
		BaseURL: "http://127.0.0.1:0",
		smoke:   func(string) error { return nil },
	})
	if err == nil || dir != "" {
		t.Fatalf("Ensure = (%q, %v), want an error", dir, err)
	}
}

func TestExtractTarGz_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	evil := "../../../../tmp/evil"
	hdr := &tar.Header{Name: evil, Mode: 0o644, Size: 4}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("evil")); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	archivePath := filepath.Join(dir, "evil.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	extractDir := filepath.Join(dir, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGz(archivePath, extractDir); err == nil {
		t.Fatal("expected a path-traversal entry to be rejected")
	}
}
