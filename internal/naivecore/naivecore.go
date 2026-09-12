// Package naivecore ensures a runnable `naive` binary is present on the
// router -- the NaiveProxy client (github.com/klzgrad/naiveproxy) the
// failover package's sidecar manager supervises for Profile.Protocol ==
// "naive" (see docs/HANDOFF-naive.md). It mirrors internal/xraycore's
// download-verify-smoke shape, simplified: naive isn't in any Entware
// feed, so there's no opkg fallback and no "is the installed version
// wrong" auto-upgrade -- Force is the only way to replace a working
// binary, same as choosing to update xray-core's pin.
//
// Unlike xray-core, this package never compiles anything: naive is a
// prebuilt Chromium-net binary klzgrad already publishes for our
// architectures (the static openwrt build, to stay clear of Entware's
// libc). .github/workflows/naive-core.yml re-hosts it under this repo's
// own releases (naive-core/<version>) with a provenance file, the same
// trust shape as xray-core/<tag>.
package naivecore

import (
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

// PinnedVersion is the klzgrad/naiveproxy release this project has
// mirrored and smoke-tested. Kept in sync with packaging/naive-core/version
// (enforced by a test, same as xraycore.DefaultTag <-> packaging/xray-core/version).
const PinnedVersion = "v150.0.7871.63-1"

const defaultBaseURL = "https://github.com/kuzzrus/keenetic-xray-go/releases/download/naive-core"

// maxAssetBytes caps the vendored-binary download. Unpacked naive is
// ~12-14 MB; the packed asset is smaller, but bound generously against a
// broken or hostile endpoint (same reasoning as xraycore.maxAssetBytes).
const maxAssetBytes = 40 << 20

// Options configures Ensure. The zero value is usable: it installs
// PinnedVersion to /opt/sbin/naive.
type Options struct {
	Dest    string // naive binary destination; "" -> /opt/sbin/naive
	Version string // "" -> PinnedVersion
	BaseURL string // "" -> defaultBaseURL
	HTTP    *http.Client

	// Force re-installs even when a runnable binary is already at Dest.
	// Still safe: installVendored downloads to a temp file and
	// smoke-tests it there, only renaming over Dest once that passes, so
	// a broken download never replaces a working naive.
	Force bool

	// Test hooks; nil selects the real implementation.
	smoke func(bin string) error // "<bin> --version" must exit 0
}

// Ensure guarantees a runnable naive binary at opts.Dest and reports
// where it came from: "existing" or "vendored". It never removes a
// binary that already runs, and with opts.Force it still won't, since a
// replacement is only swapped in after it smoke-tests in a temp file.
func Ensure(ctx context.Context, opts Options) (string, error) {
	dest := opts.Dest
	if dest == "" {
		dest = "/opt/sbin/naive"
	}
	smoke := opts.smoke
	if smoke == nil {
		smoke = func(bin string) error { return exec.Command(bin, "--version").Run() }
	}

	if !opts.Force && smoke(dest) == nil {
		return "existing", nil
	}
	if err := installVendored(ctx, opts, dest, smoke); err != nil {
		return "", err
	}
	return "vendored", nil
}

// Version runs `<binary> --version` and returns its output, e.g.
// "naive 150.0.7871.63". Mirrors xraycore.Version so status/doctor code
// can report both cores the same way.
func Version(binary string) (string, error) {
	out, err := exec.Command(binary, "--version").Output()
	if err != nil {
		return "", err
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	if first == "" {
		return "", fmt.Errorf("%s --version printed nothing", binary)
	}
	return first, nil
}

func installVendored(ctx context.Context, opts Options, dest string, smoke func(string) error) error {
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
		hc = &http.Client{Timeout: 4 * time.Minute}
	}

	name := fmt.Sprintf("naive-%s-linux-%s", version, runtime.GOARCH)
	assetURL := fmt.Sprintf("%s/%s/%s", strings.TrimRight(base, "/"), version, name)

	wantSum, err := fetchExpectedSum(ctx, hc, assetURL+".sha256", name)
	if err != nil {
		return fmt.Errorf("checksum for %s: %w", name, err)
	}

	tmp := dest + ".keenetic-xray.tmp"
	_ = os.Remove(tmp)
	if err := downloadVerified(ctx, hc, assetURL, tmp, wantSum); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := smoke(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s downloaded and verified but does not run (packed binary may be incompatible with this router): %w", name, err)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// fetchExpectedSum pulls the sha256sum-format checksum file and returns
// the hash whose filename column equals want.
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
