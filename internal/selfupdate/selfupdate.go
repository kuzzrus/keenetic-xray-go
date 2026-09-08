// Package selfupdate backs the router agent's "update myself" flow with
// a rollback path. Before it re-runs install.sh (which pulls the *latest*
// release .ipk), the agent drops a marker recording the version it's
// leaving and the exact .ipk URL to get back to it. After the swap the
// daemon watches itself come up; if it doesn't, the operator gets one
// loud message with a ready `keenetic-xray internal self-rollback`
// command, and that command reinstalls the marked .ipk.
package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Repo is the GitHub owner/repo the release .ipk assets live under.
const Repo = "kuzzrus/keenetic-xray-go"

// Marker is what the agent writes before triggering an update, so a
// post-update health check (or a manual rollback) can get back to the
// exact build it left.
type Marker struct {
	PrevVersion string    `json:"prev_version"` // e.g. "0.27.0" (no leading v)
	IPKURL      string    `json:"ipk_url"`
	Arch        string    `json:"arch"` // "aarch64-3.10" | "mipsel-3.4"
	StartedAt   time.Time `json:"started_at"`
}

// WriteMarker saves m atomically (0644 -- it holds no secrets, only a
// public release URL).
func WriteMarker(path string, m Marker) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadMarker loads the marker; ok is false when there is none or it's
// unreadable/malformed.
func ReadMarker(path string) (m Marker, ok bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Marker{}, false
	}
	if err := json.Unmarshal(b, &m); err != nil || m.IPKURL == "" {
		return Marker{}, false
	}
	return m, true
}

// ClearMarker removes the marker; a missing file is not an error.
func ClearMarker(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// supportedArches is the priority order install.sh itself uses.
var supportedArches = []string{"aarch64-3.10", "mipsel-3.4"}

// DetectArch asks opkg which architecture .ipk it accepts -- the same
// `opkg print-architecture` check install.sh does, so the two can't
// disagree. runOpkg is a seam; nil uses the real `opkg`.
func DetectArch(runOpkg func(args ...string) (string, error)) (string, error) {
	if runOpkg == nil {
		runOpkg = func(args ...string) (string, error) {
			out, err := exec.Command("opkg", args...).Output()
			return string(out), err
		}
	}
	out, err := runOpkg("print-architecture")
	if err != nil {
		return "", fmt.Errorf("opkg print-architecture: %w", err)
	}
	for _, want := range supportedArches {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line) // "arch <name> <priority>"
			if len(f) >= 2 && f[0] == "arch" && f[1] == want {
				return want, nil
			}
		}
	}
	return "", fmt.Errorf("no supported architecture in `opkg print-architecture` (want one of %s)", strings.Join(supportedArches, ", "))
}

// IPKURL is the deterministic release-asset URL for one version+arch,
// e.g. .../releases/download/v0.27.0/keenetic-xray_0.27.0-1_aarch64-3.10.ipk
func IPKURL(version, arch string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("https://github.com/%s/releases/download/v%s/keenetic-xray_%s-1_%s.ipk", Repo, v, v, arch)
}

// NewMarker builds a Marker for the currently-running version, detecting
// the arch. version is version.Version (may carry a leading "v").
func NewMarker(version string, runOpkg func(args ...string) (string, error)) (Marker, error) {
	arch, err := DetectArch(runOpkg)
	if err != nil {
		return Marker{}, err
	}
	v := strings.TrimPrefix(version, "v")
	return Marker{
		PrevVersion: v,
		IPKURL:      IPKURL(v, arch),
		Arch:        arch,
		StartedAt:   time.Now(),
	}, nil
}

// RollbackOptions carries the seams Rollback needs; all nil-able for the
// real thing.
type RollbackOptions struct {
	DownloadPath string // where the .ipk is fetched to; "" -> /opt/keenetic-xray-rollback.ipk
	Fetch        func(ctx context.Context, url, dest string) error
	OpkgInstall  func(ctx context.Context, ipkPath string) error
	Log          func(string, ...any)
}

// Rollback downloads the marked .ipk and reinstalls it (forcing the
// downgrade, since opkg won't step back a version on its own). The
// package's own postinst restarts the daemon. On success the marker is
// cleared.
func Rollback(ctx context.Context, markerPath string, o RollbackOptions) error {
	m, ok := ReadMarker(markerPath)
	if !ok {
		return fmt.Errorf("нет маркера обновления (%s) — откатывать не к чему", markerPath)
	}
	logf := o.Log
	if logf == nil {
		logf = func(string, ...any) {}
	}
	dest := o.DownloadPath
	if dest == "" {
		dest = "/opt/keenetic-xray-rollback.ipk"
	}
	fetch := o.Fetch
	if fetch == nil {
		fetch = curlOrWget
	}
	install := o.OpkgInstall
	if install == nil {
		install = func(ctx context.Context, ipkPath string) error {
			out, err := exec.CommandContext(ctx, "opkg", "install", "--force-downgrade", "--force-reinstall", ipkPath).CombinedOutput()
			if err != nil {
				return fmt.Errorf("opkg install %s: %w: %s", ipkPath, err, strings.TrimSpace(string(out)))
			}
			return nil
		}
	}

	logf("откат: качаю %s", m.IPKURL)
	if err := fetch(ctx, m.IPKURL, dest); err != nil {
		return fmt.Errorf("скачивание %s: %w", m.IPKURL, err)
	}
	defer os.Remove(dest)

	logf("откат: opkg install %s (форс-даунгрейд до %s)", filepath.Base(dest), m.PrevVersion)
	if err := install(ctx, dest); err != nil {
		return err
	}
	_ = ClearMarker(markerPath)
	logf("откат до %s выполнен — демон перезапустит postinst пакета", m.PrevVersion)
	return nil
}

// curlOrWget mirrors install.sh's fetch(): curl first (some routers'
// busybox wget can't do HTTPS), wget as the fallback.
func curlOrWget(ctx context.Context, url, dest string) error {
	if _, err := exec.LookPath("curl"); err == nil {
		return exec.CommandContext(ctx, "curl", "-fsSL", url, "-o", dest).Run()
	}
	return exec.CommandContext(ctx, "wget", "-q", url, "-O", dest).Run()
}
