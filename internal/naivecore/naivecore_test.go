package naivecore

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

// fakeRelease serves a vendored-asset layout: naive-<version>-linux-<goarch>
// and its .sha256 (sha256sum format), the same shape naive-core.yml uploads.
func fakeRelease(t *testing.T, version, payload string) (baseURL, assetName string) {
	t.Helper()
	assetName = fmt.Sprintf("naive-%s-linux-%s", version, runtime.GOARCH)
	sum := sha256.Sum256([]byte(payload))
	sha := fmt.Sprintf("%s  %s\n%s  %s.xz\n",
		hex.EncodeToString(sum[:]), assetName,
		strings.Repeat("0", 64), assetName)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+version+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, payload)
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
	data, err := os.ReadFile(filepath.Join("..", "..", "packaging", "naive-core", "version"))
	if err != nil {
		t.Fatalf("reading packaging/naive-core/version: %v", err)
	}
	if pinned := strings.TrimSpace(string(data)); pinned != PinnedVersion {
		t.Errorf("PinnedVersion = %q but packaging/naive-core/version = %q -- keep them in sync", PinnedVersion, pinned)
	}
}

func TestEnsure_ExistingBinaryShortCircuits(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "naive")
	if err := os.WriteFile(dest, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := Ensure(context.Background(), Options{
		Dest:  dest,
		smoke: func(string) error { return nil }, // pretend it runs
	})
	if err != nil || src != "existing" {
		t.Fatalf("Ensure = (%q, %v), want (existing, nil)", src, err)
	}
}

func TestEnsure_InstallsVendored(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "naive")
	base, _ := fakeRelease(t, PinnedVersion, "PACKED-NAIVE-BINARY")

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
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil)", src, err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "PACKED-NAIVE-BINARY" {
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
	dest := filepath.Join(dir, "not-yet-created", "nested", "naive")
	base, _ := fakeRelease(t, PinnedVersion, "PACKED-NAIVE-BINARY")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: base,
		smoke: func(bin string) error {
			if _, statErr := os.Stat(bin); statErr != nil {
				return statErr
			}
			return nil
		},
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil) even though the destination directory didn't exist yet", src, err)
	}
	if got, rerr := os.ReadFile(dest); rerr != nil || string(got) != "PACKED-NAIVE-BINARY" {
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
	dest := filepath.Join(dir, "naive")
	assetName := fmt.Sprintf("naive-%s-linux-%s", PinnedVersion, runtime.GOARCH)
	payload := "PACKED-NAIVE-BINARY-CONTENT-FOR-CONCURRENCY-TEST"
	sum := sha256.Sum256([]byte(payload))
	sha := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), assetName)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond) // hold both downloads open long enough to genuinely overlap
		fmt.Fprint(w, payload)
	})
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
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

func TestEnsure_ForceReinstallsOverRunningBinary(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "naive")
	if err := os.WriteFile(dest, []byte("OLD-NAIVE"), 0o755); err != nil {
		t.Fatal(err)
	}
	base, _ := fakeRelease(t, "v151.0.0.0-1", "NEW-NAIVE")

	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Version: "v151.0.0.0-1",
		BaseURL: base,
		Force:   true,
		smoke:   func(string) error { return nil }, // the old binary "runs" -- Force must ignore that
	})
	if err != nil || src != "vendored" {
		t.Fatalf("Ensure = (%q, %v), want (vendored, nil) -- Force should skip the existing-binary short-circuit", src, err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "NEW-NAIVE" {
		t.Errorf("dest = %q, want the freshly downloaded NEW-NAIVE", got)
	}
}

func TestEnsure_ForceKeepsWorkingBinaryWhenDownloadFails(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "naive")
	if err := os.WriteFile(dest, []byte("STILL-GOOD"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Ensure(context.Background(), Options{
		Dest:    dest,
		Version: "v151.0.0.0-1",
		BaseURL: "http://127.0.0.1:0", // unreachable
		Force:   true,
		smoke:   func(string) error { return nil },
	})
	if err == nil {
		t.Fatal("expected an error when the forced upgrade can't be downloaded")
	}
	if got, _ := os.ReadFile(dest); string(got) != "STILL-GOOD" {
		t.Errorf("dest = %q, want the original binary untouched after a failed forced upgrade", got)
	}
}

func TestEnsure_ChecksumMismatchErrorsAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "naive")

	assetName := fmt.Sprintf("naive-%s-linux-%s", PinnedVersion, runtime.GOARCH)
	mux := http.NewServeMux()
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "actual-bytes")
	})
	mux.HandleFunc("/"+PinnedVersion+"/"+assetName+".sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s  %s\n", strings.Repeat("a", 64), assetName) // wrong hash
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: srv.URL,
		smoke:   func(string) error { return fmt.Errorf("not installed") },
	})
	if err == nil {
		t.Fatal("expected an error on checksum mismatch (naivecore has no opkg fallback)")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Error("dest should not exist after a failed install")
	}
	if leftover, _ := filepath.Glob(filepath.Join(dir, filepath.Base(dest)+".*.tmp")); len(leftover) != 0 {
		t.Errorf("temp file(s) left behind after a failed install: %v", leftover)
	}
}

func TestEnsure_UnreachableBaseURLErrors(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "naive")
	src, err := Ensure(context.Background(), Options{
		Dest:    dest,
		BaseURL: "http://127.0.0.1:0",
		smoke:   func(string) error { return fmt.Errorf("not installed") },
	})
	if err == nil || src != "" {
		t.Fatalf("Ensure = (%q, %v), want an error", src, err)
	}
}
