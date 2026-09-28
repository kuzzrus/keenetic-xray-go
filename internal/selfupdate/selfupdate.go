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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
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
	OpkgLog      string // where opkg's own output goes; "" -> /opt/var/log/keenetic-xray/rollback.log
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
		logPath := o.OpkgLog
		if logPath == "" {
			logPath = "/opt/var/log/keenetic-xray/rollback.log"
		}
		install = func(ctx context.Context, ipkPath string) error {
			return opkgInstallToFile(ctx, ipkPath, logPath)
		}
	}

	// Before the fetch, not after it: a download that fails half-way
	// must not leave a partial .ipk behind on the router's flash.
	defer os.Remove(dest)
	logf("откат: качаю %s", m.IPKURL)
	if err := fetch(ctx, m.IPKURL, dest); err != nil {
		return fmt.Errorf("скачивание %s: %w", m.IPKURL, err)
	}
	if err := verifyIPK(ctx, fetch, m, dest, logf); err != nil {
		return err
	}

	logf("откат: opkg install %s (форс-даунгрейд до %s)", filepath.Base(dest), m.PrevVersion)
	if err := install(ctx, dest); err != nil {
		return err
	}
	_ = ClearMarker(markerPath)
	logf("откат до %s выполнен — демон перезапустит postinst пакета", m.PrevVersion)
	return nil
}

// ChecksumsURL is the release's checksums.txt, which release.yml extends
// with every .ipk's sha256 (REL-01).
func ChecksumsURL(version string) string {
	v := strings.TrimPrefix(version, "v")
	return fmt.Sprintf("https://github.com/%s/releases/download/v%s/checksums.txt", Repo, v)
}

// verifyIPK checks the downloaded .ipk against the checksums.txt of the
// release it came from, as install.sh does for an install (2026-09-27
// external review, R-4). A mismatch refuses the rollback. A checksums.txt
// that can't be fetched, or that has no line for this .ipk (releases
// older than REL-01), is only logged: a rollback is the way back from a
// broken update and must not need more than the .ipk itself.
func verifyIPK(ctx context.Context, fetch func(context.Context, string, string) error, m Marker, ipk string, logf func(string, ...any)) error {
	sumsPath := ipk + ".checksums"
	defer os.Remove(sumsPath)
	url := ChecksumsURL(m.PrevVersion)
	if err := fetch(ctx, url, sumsPath); err != nil {
		logf("откат: %s недоступен (%v) — ставлю без проверки sha256", url, err)
		return nil
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		logf("откат: не читается %s (%v) — ставлю без проверки sha256", sumsPath, err)
		return nil
	}
	name := path.Base(m.IPKURL)
	want := checksumFor(string(sums), name)
	if want == "" {
		logf("откат: в checksums.txt релиза v%s нет %s — ставлю без проверки sha256", m.PrevVersion, name)
		return nil
	}
	got, err := fileSHA256(ipk)
	if err != nil {
		return fmt.Errorf("sha256 %s: %w", ipk, err)
	}
	if got != want {
		return fmt.Errorf("sha256 скачанного %s не совпадает с checksums.txt релиза v%s (%s, ожидался %s) — откат отменён", name, m.PrevVersion, got, want)
	}
	logf("откат: sha256 %s совпадает с checksums.txt", name)
	return nil
}

// checksumFor finds name's hash in `sha256sum` output ("<hex>  <name>",
// or "<hex> *<name>" in binary mode); "" when it isn't there.
func checksumFor(sums, name string) string {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return strings.ToLower(f[0])
		}
	}
	return ""
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// opkgInstallToFile runs the forced reinstall with opkg's output going to
// logPath, in a session of its own.
//
// Not CombinedOutput -- not a pipe into this process at all (N2,
// 2026-09-27 external review). The package's prerm stops the daemon
// while opkg runs, and an rc.func-era init script did that with
// `killall keenetic-xray`, which also killed the process reading opkg's
// output; opkg's next write then died of SIGPIPE, leaving the package
// half-installed and the daemon stopped. Same fix UPD-01 already made
// for the update path: a real file, not an in-process buffer.
func opkgInstallToFile(ctx context.Context, ipkPath, logPath string) error {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return fmt.Errorf("opkg log directory: %w", err)
	}
	f, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", logPath, err)
	}
	cmd := exec.CommandContext(ctx, "opkg", "install", "--force-downgrade", "--force-reinstall", ipkPath)
	cmd.Stdout, cmd.Stderr = f, f
	ownSession(cmd)
	err = cmd.Run()
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("opkg install %s: %w -- last lines of %s:\n%s", ipkPath, err, logPath, tailLines(logPath, 15))
	}
	return nil
}

// tailLines returns the last n lines of path, or "" if it can't be read.
func tailLines(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// curlOrWget mirrors install.sh's fetch(): curl first (some routers'
// busybox wget can't do HTTPS), wget as the fallback. Bounded either way
// -- a stalled download must not hold a rollback, and the router
// waiting on it, open-ended.
func curlOrWget(ctx context.Context, url, dest string) error {
	if _, err := exec.LookPath("curl"); err == nil {
		return exec.CommandContext(ctx, "curl", "-fsSL", "--connect-timeout", "15", "--max-time", "180", url, "-o", dest).Run()
	}
	return exec.CommandContext(ctx, "wget", "-q", "-T", "180", url, "-O", dest).Run()
}
