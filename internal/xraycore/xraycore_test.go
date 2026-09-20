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
	"sync"
	"testing"
	"time"
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

func TestEnsure_KeepsExistingWhenVersionUnreadable(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		smoke:   func(string) error { return nil },
		version: func(string) (string, error) { return "", fmt.Errorf("garbled") },
		opkg:    func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "existing" {
		t.Fatalf("Ensure = (%q, %v), want (existing, nil)", src, err)
	}
}

func TestEnsure_UpgradesWhenInstalledVersionDiffers(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	if err := os.WriteFile(dest, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	base, _ := fakeRelease(t, DefaultTag, "NEW-PACKED-XRAY")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: base,
		smoke:   func(string) error { return nil },                                     // the old core "runs"...
		version: func(string) (string, error) { return "Xray 1.2.3 (Xray, ...)", nil }, // ...but it's the wrong version
		opkg:    func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil)", src, err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "NEW-PACKED-XRAY" {
		t.Fatalf("core not upgraded: %q", got)
	}
}

func TestEnsure_KeepsExistingWhenVersionMatches(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "xray")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := Ensure(context.Background(), Options{
		Dest:  dest,
		smoke: func(string) error { return nil },
		version: func(string) (string, error) {
			return "Xray " + strings.TrimPrefix(DefaultTag, "v") + " (Xray, ...)", nil
		},
		opkg: func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
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

// TestEnsure_InstallsVendored_CreatesDestDirIfMissing is the regression
// test for INST-02's ordering half: MkdirAll used to run *after* the
// download attempt, so installing to a not-yet-existing directory (a
// fresh /opt/sbin, say) failed the very first write before MkdirAll ever
// got a chance to create it.
func TestEnsure_InstallsVendored_CreatesDestDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "not-yet-created", "nested", "xray")
	base, _ := fakeRelease(t, DefaultTag, "PACKED-XRAY-BINARY")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: base,
		smoke: func(bin string) error {
			if _, statErr := os.Stat(bin); statErr != nil {
				return statErr
			}
			return nil
		},
		opkg: func(context.Context) error { t.Fatal("opkg must not be called"); return nil },
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil) even though the destination directory didn't exist yet", src, err)
	}
	if got, rerr := os.ReadFile(dest); rerr != nil || string(got) != "PACKED-XRAY-BINARY" {
		t.Fatalf("installed file = %q (%v)", got, rerr)
	}
}

// TestEnsure_ConcurrentForceInstalls_DoNotCorruptEachOther is the
// regression test for INST-02's collision half: the old fixed
// `dest + ".keenetic-xray.tmp"` name meant two concurrent installs for
// the same dest (a second install.sh run before the first finishes, a
// manual CLI invocation racing the daemon's own reconcile) wrote through
// the *same* temp file, risking a torn/corrupted result for whichever
// renamed last. Both calls use Force so neither short-circuits on the
// other's not-yet-written dest; the asset handler sleeps briefly so the
// two downloads genuinely overlap rather than happening to run back to
// back.
func TestEnsure_ConcurrentForceInstalls_DoNotCorruptEachOther(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	assetName := fmt.Sprintf("xray-%s-linux-%s", DefaultTag, runtime.GOARCH)
	payload := "PACKED-XRAY-BINARY-CONTENT-FOR-CONCURRENCY-TEST"
	sum := sha256.Sum256([]byte(payload))
	sha := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), assetName)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+DefaultTag+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // hold both downloads open long enough to genuinely overlap
		fmt.Fprint(w, payload)
	})
	mux.HandleFunc("/"+DefaultTag+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, sha)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	opts := Options{
		Dest: dest, BaseURL: srv.URL, Force: true,
		smoke: func(bin string) error {
			if _, statErr := os.Stat(bin); statErr != nil {
				return statErr
			}
			return nil
		},
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = Ensure(context.Background(), opts)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent Ensure call %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading final dest: %v", err)
	}
	if string(got) != payload {
		t.Errorf("final installed content = %q, want the complete payload %q -- concurrent installs must not share a temp file", got, payload)
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
	if leftover, _ := filepath.Glob(filepath.Join(dir, filepath.Base(dest)+".*.tmp")); len(leftover) != 0 {
		t.Errorf("temp file(s) left behind after a failed vendored install: %v", leftover)
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
