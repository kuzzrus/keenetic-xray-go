package xraycore

import (
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

// fakeRelease serves a vendored-asset layout: xray-<tag>-linux-<goarch>
// and its .sha256 (sha256sum format, two entries like the real workflow).
func fakeRelease(t *testing.T, tag, payload string) (baseURL, assetName string) {
	t.Helper()
	assetName = fmt.Sprintf("xray-%s-linux-%s", tag, runtime.GOARCH)
	sum := sha256.Sum256([]byte(payload))
	sha := fmt.Sprintf("%s  %s\n%s  %s.xz\n",
		hex.EncodeToString(sum[:]), assetName,
		strings.Repeat("0", 64), assetName)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+tag+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
	})
	mux.HandleFunc("/"+tag+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sha)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, assetName
}

func TestTags_Sane(t *testing.T) {
	if DefaultTag == "" {
		t.Fatal("DefaultTag must not be empty")
	}
	if PrereleaseTag != "" && PrereleaseTag == DefaultTag {
		t.Error("PrereleaseTag should be a *different* tag from DefaultTag, or empty")
	}
}

func TestDefaultTag_MatchesPackagingPin(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "xray-core", "version"))
	if err != nil {
		t.Fatalf("reading packaging/xray-core/version: %v", err)
	}
	if pinned := strings.TrimSpace(string(data)); pinned != DefaultTag {
		t.Errorf("DefaultTag = %q but packaging/xray-core/version = %q -- keep them in sync", DefaultTag, pinned)
	}
}

func TestEnsure_ExistingBinaryShortCircuits(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := Ensure(context.Background(), Options{
		Dest:  dest,
		smoke: func(string) error { return nil }, // pretend it runs
		opkg:  func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "existing" {
		t.Fatalf("Ensure = (%q, %v), want (existing, nil)", src, err)
	}
}

func TestEnsure_ForceReinstallsOverRunningBinary(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	if err := os.WriteFile(dest, []byte("OLD-CORE"), 0o755); err != nil {
		t.Fatal(err)
	}
	base, _ := fakeRelease(t, "v9.9.9", "NEW-CORE")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Tag:     "v9.9.9",
		BaseURL: base,
		Force:   true,
		Prefer:  "vendored",
		smoke:   func(string) error { return nil }, // the old binary "runs" -- Force must ignore that
		opkg:    func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil) -- Force should skip the existing-binary short-circuit", src, err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "NEW-CORE" {
		t.Errorf("dest = %q, want the freshly downloaded NEW-CORE", got)
	}
}

func TestEnsure_ForceKeepsWorkingCoreWhenDownloadFails(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	if err := os.WriteFile(dest, []byte("STILL-GOOD"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Tag:     "v9.9.9",
		BaseURL: "http://127.0.0.1:0", // unreachable
		Force:   true,
		Prefer:  "vendored", // no opkg substitution for an explicit upgrade
		smoke:   func(string) error { return nil },
		opkg:    func(context.Context) error { t.Fatal("opkg must not be called with Prefer=vendored"); return nil },
	})
	if err == nil {
		t.Fatal("expected an error when the forced upgrade can't be downloaded")
	}
	if got, _ := os.ReadFile(dest); string(got) != "STILL-GOOD" {
		t.Errorf("dest = %q, want the original binary untouched after a failed forced upgrade", got)
	}
}

func TestEnsure_InstallsVendored(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	base, _ := fakeRelease(t, DefaultTag, "PACKED-XRAY-BINARY")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: base,
		smoke: func(bin string) error {
			// The first probe (bin == dest) happens before anything is
			// installed, so report "not runnable" until the file exists.
			if _, statErr := os.Stat(bin); statErr != nil {
				return statErr
			}
			return nil
		},
		opkg: func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil)", src, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "PACKED-XRAY-BINARY" {
		t.Fatalf("installed file = %q (%v)", got, err)
	}
	if runtime.GOOS != "windows" { // Windows has no exec bit
		if fi, _ := os.Stat(dest); fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("installed binary is not executable: %v", fi.Mode())
		}
	}
}

func TestEnsure_ChecksumMismatchFallsBackToOpkg(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")

	assetName := fmt.Sprintf("xray-%s-linux-%s", DefaultTag, runtime.GOARCH)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+DefaultTag+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "actual-bytes")
	})
	mux.HandleFunc("/"+DefaultTag+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("a", 64), assetName) // wrong hash
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	opkgCalled := false
	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: srv.URL,
		smoke: func(bin string) error {
			if bin == dest && !opkgCalled {
				return fmt.Errorf("not installed")
			}
			return nil // succeeds after opkg
		},
		opkg: func(context.Context) error {
			opkgCalled = true
			return os.WriteFile(dest, []byte("from-opkg"), 0o755)
		},
	})
	if err != nil || src != "entware" {
		t.Fatalf("Ensure = (%q, %v), want (entware, nil)", src, err)
	}
	if !opkgCalled {
		t.Error("expected the opkg fallback after a checksum mismatch")
	}
	if _, err := os.Stat(dest + ".keenetic-xray.tmp"); !os.IsNotExist(err) {
		t.Error("temp file left behind after a failed vendored install")
	}
}

func TestEnsure_PreferVendoredDoesNotFallBack(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "xray")
	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Prefer:  "vendored",
		BaseURL: "http://127.0.0.1:0", // unreachable
		smoke:   func(string) error { return fmt.Errorf("nope") },
		opkg:    func(context.Context) error { t.Fatal("opkg must not be called with Prefer=vendored"); return nil },
	})
	if err == nil || src != "" {
		t.Fatalf("Ensure = (%q, %v), want an error", src, err)
	}
}

func TestEnsure_PreferEntwareSkipsDownload(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "xray")
	opkgCalled := false
	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Prefer:  "entware",
		BaseURL: "http://127.0.0.1:0",
		smoke: func(bin string) error {
			if !opkgCalled {
				return fmt.Errorf("not installed")
			}
			return nil
		},
		opkg: func(context.Context) error { opkgCalled = true; return nil },
	})
	if err != nil || src != "entware" {
		t.Fatalf("Ensure = (%q, %v), want (entware, nil)", src, err)
	}
}
