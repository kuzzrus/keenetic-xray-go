//go:build linux

package selfupdate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOpkg puts an `opkg` stand-in first on PATH for the test.
func fakeOpkg(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opkg"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func rollbackFixture(t *testing.T) (marker, logPath string, opts RollbackOptions) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "self-update.json")
	writeMarkerT(t, marker, Marker{PrevVersion: "0.32.81", IPKURL: "https://host/x.ipk", Arch: "aarch64-3.10", StartedAt: time.Now()})
	logPath = filepath.Join(dir, "log", "rollback.log")
	return marker, logPath, RollbackOptions{
		DownloadPath: filepath.Join(dir, "rb.ipk"),
		OpkgLog:      logPath,
		Fetch:        func(_ context.Context, _, dest string) error { return writeRaw(dest, "ipk") },
	}
}

// TestRollback_OpkgOutputGoesToAFile is N2 (2026-09-27 external review):
// opkg's output used to be a pipe into the process running the rollback.
// The package's prerm stopped the daemon with `killall keenetic-xray`,
// which killed that process too -- and opkg's next write died of SIGPIPE,
// leaving the package half-installed. With the output in a file there is
// no reader to lose.
func TestRollback_OpkgOutputGoesToAFile(t *testing.T) {
	fakeOpkg(t, `i=0; while [ $i -lt 50 ]; do echo "postinst step $i"; i=$((i+1)); done`+"\n")
	marker, logPath, opts := rollbackFixture(t)
	if err := Rollback(context.Background(), marker, opts); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	b, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(b), "postinst step 49") {
		t.Errorf("opkg's output did not all reach %s: %v\n%s", logPath, err, b)
	}
	if _, err := os.Stat(opts.DownloadPath); !os.IsNotExist(err) {
		t.Error("the downloaded .ipk was left behind")
	}
}

func TestRollback_OpkgFailureCarriesItsOwnWords(t *testing.T) {
	fakeOpkg(t, "echo 'Collected errors:'; echo ' * pkg_hash_check_unresolved: cannot find dependency'; exit 255\n")
	marker, _, opts := rollbackFixture(t)
	err := Rollback(context.Background(), marker, opts)
	if err == nil || !strings.Contains(err.Error(), "cannot find dependency") {
		t.Fatalf("err = %v, want opkg's own last lines in it", err)
	}
	if _, ok := ReadMarker(marker); !ok {
		t.Error("marker must survive a failed opkg install")
	}
}
