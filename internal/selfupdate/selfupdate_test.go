package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMarker_RoundTripAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "self-update.json")
	if _, ok := ReadMarker(path); ok {
		t.Fatal("ReadMarker on a missing file should be ok=false")
	}
	m := Marker{PrevVersion: "0.27.0", IPKURL: "https://x/y.ipk", Arch: "aarch64-3.10", StartedAt: time.Now().Truncate(time.Second)}
	if err := WriteMarker(path, m); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
	got, ok := ReadMarker(path)
	if !ok || got.PrevVersion != "0.27.0" || got.IPKURL != "https://x/y.ipk" || got.Arch != "aarch64-3.10" {
		t.Fatalf("round-trip = %+v ok=%v", got, ok)
	}
	if err := ClearMarker(path); err != nil {
		t.Fatalf("ClearMarker: %v", err)
	}
	if err := ClearMarker(path); err != nil {
		t.Errorf("ClearMarker on an already-gone file should be a no-op, got %v", err)
	}
}

func TestReadMarker_MalformedAndEmptyURL(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bad.json":   "{not json",
		"nourl.json": `{"prev_version":"0.1.0"}`,
	} {
		p := filepath.Join(dir, name)
		if err := writeRaw(p, body); err != nil {
			t.Fatal(err)
		}
		if _, ok := ReadMarker(p); ok {
			t.Errorf("%s: ReadMarker should be ok=false", name)
		}
	}
}

func TestDetectArch(t *testing.T) {
	cases := []struct {
		name, out, want string
		runErr          bool
		wantErr         bool
	}{
		{"aarch64", "arch all 1\narch aarch64-3.10 10\n", "aarch64-3.10", false, false},
		{"mipsel", "arch noarch 1\narch mipsel-3.4 10\n", "mipsel-3.4", false, false},
		{"priority aarch64 wins order", "arch mipsel-3.4 10\narch aarch64-3.10 10\n", "aarch64-3.10", false, false},
		{"unsupported", "arch all 1\narch x86_64 10\n", "", false, true},
		{"opkg failed", "", "", true, true},
	}
	for _, c := range cases {
		got, err := DetectArch(func(args ...string) (string, error) {
			if c.runErr {
				return "", errors.New("opkg exploded")
			}
			return c.out, nil
		})
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestIPKURL(t *testing.T) {
	want := "https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.27.0/keenetic-xray_0.27.0-1_aarch64-3.10.ipk"
	if got := IPKURL("0.27.0", "aarch64-3.10"); got != want {
		t.Errorf("IPKURL = %q, want %q", got, want)
	}
	if got := IPKURL("v0.27.0", "mipsel-3.4"); got != "https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.27.0/keenetic-xray_0.27.0-1_mipsel-3.4.ipk" {
		t.Errorf("leading v not trimmed: %q", got)
	}
}

func TestNewMarker(t *testing.T) {
	m, err := NewMarker("v1.2.3", func(...string) (string, error) { return "arch aarch64-3.10 10\n", nil })
	if err != nil {
		t.Fatalf("NewMarker: %v", err)
	}
	if m.PrevVersion != "1.2.3" || m.Arch != "aarch64-3.10" {
		t.Errorf("marker = %+v", m)
	}
	if m.IPKURL != IPKURL("1.2.3", "aarch64-3.10") {
		t.Errorf("IPKURL = %q", m.IPKURL)
	}
	if time.Since(m.StartedAt) > time.Minute {
		t.Errorf("StartedAt not recent: %v", m.StartedAt)
	}
}

func TestRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "self-update.json")

	// no marker -> error
	if err := Rollback(context.Background(), path, RollbackOptions{}); err == nil {
		t.Error("Rollback with no marker should error")
	}

	m := Marker{PrevVersion: "0.26.6", IPKURL: "https://host/keenetic-xray_0.26.6-1_aarch64-3.10.ipk", Arch: "aarch64-3.10", StartedAt: time.Now()}
	writeMarkerT(t, path, m)

	var fetchedURL, fetchedDest, installedPath string
	opts := RollbackOptions{
		DownloadPath: filepath.Join(t.TempDir(), "rb.ipk"),
		Fetch: func(_ context.Context, url, dest string) error {
			fetchedURL, fetchedDest = url, dest
			return writeRaw(dest, "ipk-bytes")
		},
		OpkgInstall: func(_ context.Context, p string) error { installedPath = p; return nil },
	}
	if err := Rollback(context.Background(), path, opts); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if fetchedURL != m.IPKURL || fetchedDest != opts.DownloadPath || installedPath != opts.DownloadPath {
		t.Errorf("fetch/install wiring wrong: url=%q dest=%q install=%q", fetchedURL, fetchedDest, installedPath)
	}
	if _, ok := ReadMarker(path); ok {
		t.Error("marker should be cleared after a successful rollback")
	}

	// fetch failure: marker must survive
	writeMarkerT(t, path, m)
	err := Rollback(context.Background(), path, RollbackOptions{
		Fetch: func(context.Context, string, string) error { return errors.New("network down") },
	})
	if err == nil {
		t.Error("Rollback should propagate a fetch error")
	}
	if _, ok := ReadMarker(path); !ok {
		t.Error("marker must survive a failed rollback so it can be retried")
	}

	// install failure: marker must survive
	writeMarkerT(t, path, m)
	err = Rollback(context.Background(), path, RollbackOptions{
		Fetch:       func(_ context.Context, _, dest string) error { return writeRaw(dest, "x") },
		OpkgInstall: func(context.Context, string) error { return errors.New("opkg refused") },
	})
	if err == nil {
		t.Error("Rollback should propagate an opkg error")
	}
	if _, ok := ReadMarker(path); !ok {
		t.Error("marker must survive a failed opkg install")
	}
}

func writeMarkerT(t *testing.T, path string, m Marker) {
	t.Helper()
	if err := WriteMarker(path, m); err != nil {
		t.Fatalf("WriteMarker: %v", err)
	}
}

func writeRaw(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o644)
}
