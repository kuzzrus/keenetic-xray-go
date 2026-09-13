// Package susanincore fetches and verifies the vendored Susanin.Keenetic
// release tarball (github.com/R17a/Susanin.Keenetic) -- adaptive,
// conntrack-based blocked-destination routing that the "susanin" addon
// (internal/addons) wraps. See docs/HANDOFF-susanin.md.
//
// Unlike internal/naivecore (a single binary this project places directly
// at a fixed path), the susanin release is a tarball containing upstream's
// own installer/control scripts alongside the susanin-agent binary --
// upstream's own install.sh already knows how to lay that out under
// /opt/susanin (config preserved across reinstalls, an init.d entry, etc.),
// so reimplementing that here would just be a worse copy of it. This
// package's job stops at "safely get me a verified, extracted copy of the
// release in a scratch directory" -- the addon layer runs install.sh from
// there. Never compiles anything: R17a/Susanin.Keenetic is MIT and already
// publishes a ready per-arch tarball; .github/workflows/susanin-core.yml
// re-hosts a UPX-repacked copy of it under this repo's own releases with
// a provenance file, the same trust shape as naive-core.
package susanincore

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PinnedVersion is the R17a/Susanin.Keenetic release this project has
// mirrored and smoke-tested. Kept in sync with packaging/susanin-core/version
// (enforced by a test, same as naivecore.PinnedVersion <-> packaging/naive-core/version).
const PinnedVersion = "v0.3.6"

const defaultBaseURL = "https://github.com/kuzzrus/keenetic-xray-go/releases/download/susanin"

// maxAssetBytes caps the vendored tarball download. Upstream's own tarball
// is well under 1 MB; bound generously against a broken or hostile
// endpoint (same reasoning as naivecore.maxAssetBytes).
const maxAssetBytes = 10 << 20

// Options configures Ensure. The zero value is usable: it fetches
// PinnedVersion.
type Options struct {
	Version string // "" -> PinnedVersion
	BaseURL string // "" -> defaultBaseURL
	HTTP    *http.Client

	// Test hooks; nil selects the real implementation.
	smoke func(bin string) error // "<bin> version" must exit 0
}

// Ensure downloads and verifies the susanin release tarball, extracting it
// into a fresh temporary directory, and returns that directory's path
// (containing susanin-agent, install.sh, susanin.sh, datapath.sh,
// update.sh, uninstall.sh, config.example.conf, vpn_always.txt,
// vpn_never.txt -- upstream's own flat tarball layout). The extracted
// susanin-agent is smoke-tested before the directory is returned, so a
// caller never runs install.sh against a binary that doesn't even execute.
//
// The caller owns the returned directory's lifetime (defer
// os.RemoveAll(dir) once done with it, typically right after running
// install.sh from it).
func Ensure(ctx context.Context, opts Options) (dir string, err error) {
	version := opts.Version
	if version == "" {
		version = PinnedVersion
	}
	base := opts.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	hc := opts.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	smoke := opts.smoke
	if smoke == nil {
		smoke = func(bin string) error { return exec.Command(bin, "version").Run() }
	}

	goarch := runtime.GOARCH
	name := fmt.Sprintf("susanin-%s-linux-%s.tar.gz", version, goarch)
	assetURL := fmt.Sprintf("%s/%s/%s", strings.TrimRight(base, "/"), version, name)

	wantSum, err := fetchExpectedSum(ctx, hc, assetURL+".sha256", name)
	if err != nil {
		return "", fmt.Errorf("checksum for %s: %w", name, err)
	}

	dir, err = os.MkdirTemp("", "susanin-core-*")
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()

	archivePath := filepath.Join(dir, name)
	if err := downloadVerified(ctx, hc, assetURL, archivePath, wantSum); err != nil {
		return "", err
	}
	if err := extractTarGz(archivePath, dir); err != nil {
		return "", fmt.Errorf("extracting %s: %w", name, err)
	}
	_ = os.Remove(archivePath) // the archive itself isn't needed once extracted

	bin := filepath.Join(dir, "susanin-agent")
	if err := os.Chmod(bin, 0o755); err != nil {
		return "", fmt.Errorf("susanin-agent missing from %s: %w", name, err)
	}
	if err := smoke(bin); err != nil {
		return "", fmt.Errorf("%s downloaded, verified and extracted but susanin-agent does not run (packed binary may be incompatible with this router): %w", name, err)
	}

	ok = true
	return dir, nil
}

// Version runs `<binary> version` and returns its output, e.g. "0.3.6".
// Mirrors naivecore.Version/xraycore.Version so status/doctor code can
// report every vendored component the same way.
func Version(binary string) (string, error) {
	out, err := exec.Command(binary, "version").Output()
	if err != nil {
		return "", err
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if first == "" {
		return "", fmt.Errorf("%s version printed nothing", binary)
	}
	return first, nil
}

// fetchExpectedSum pulls the sha256sum-format checksum file and returns
// the hash whose filename column equals want. Copied from
// internal/naivecore rather than shared -- same reasoning as that
// package's own copy from internal/xraycore: a small, stable, one-off
// helper isn't worth a shared-package dependency across three vendoring
// packages that otherwise don't need to know about each other.
func fetchExpectedSum(ctx context.Context, hc *http.Client, url, want string) (string, error) {
	body, err := httpGet(ctx, hc, url, 64<<10)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == want {
			if len(fields[0]) != 64 {
				return "", fmt.Errorf("malformed checksum line %q", line)
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum for %q in %s", want, url)
}

func downloadVerified(ctx context.Context, hc *http.Client, url, dest, wantSum string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: status %s", url, resp.Status)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxAssetBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("writing %s: %w", dest, copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxAssetBytes {
		return fmt.Errorf("%s exceeds the %d byte limit", url, maxAssetBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSum {
		return fmt.Errorf("%s checksum mismatch: got %s, want %s", url, got, wantSum)
	}
	return nil
}

func httpGet(ctx context.Context, hc *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// extractTarGz extracts a gzip-compressed tar archive (flat -- no
// subdirectory, matching upstream's own layout) into dir. Rejects any
// entry whose path would escape dir (defensive; the archive is
// checksum-verified before this runs, but a path-traversal guard on
// archive extraction is cheap and standard practice regardless) and any
// non-regular-file entry other than a directory (upstream's tarball has
// none, but a mirrored asset should never be trusted to make this
// package extract a symlink/device node).
func extractTarGz(archivePath, dir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if name == "." {
			continue
		}
		target := filepath.Join(dir, name)
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("archive entry %q escapes the extraction directory", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, io.LimitReader(tr, maxAssetBytes))
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		default:
			return fmt.Errorf("archive entry %q: unsupported type %v", hdr.Name, hdr.Typeflag)
		}
	}
}
