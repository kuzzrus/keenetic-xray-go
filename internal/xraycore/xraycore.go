// Package xraycore makes sure a working xray-core binary is present on
// the router. The .ipk used to declare `Depends: xray-core` and let opkg
// pull it from the Entware feed, but that feed doesn't always carry a
// current xray-core for both router architectures, and its unpacked size
// (~30 MB) is a problem on a small internal-flash /opt. So the default is
// now a size-optimised (UPX-packed) build published from this project's
// own releases, with `opkg install xray-core` kept as the fallback.
package xraycore

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

// DefaultTag is the pinned XTLS/Xray-core release the vendored builds
// track. Keep it in sync with packaging/xray-core/version (enforced by a
// test).
const DefaultTag = "v26.3.27"

const defaultBaseURL = "https://github.com/kuzzrus/keenetic-xray-go/releases/download/xray-core"

// maxAssetBytes caps the vendored-binary download. The unpacked xray-core
// is ~35 MB; the packed asset is far smaller, but bound it generously
// against a broken or hostile endpoint.
const maxAssetBytes = 80 << 20

// Options configures Ensure. The zero value is usable: it installs the
// default vendored build to /opt/sbin/xray, falling back to opkg.
type Options struct {
	Dest    string // xray binary destination; "" -> /opt/sbin/xray
	Tag     string // "" -> DefaultTag
	Prefer  string // "", "auto": vendored then opkg | "vendored": vendored only | "entware": opkg only
	BaseURL string // "" -> defaultBaseURL
	HTTP    *http.Client

	// Test hooks; nil selects the real implementation.
	smoke func(bin string) error          // "<bin> version" must exit 0
	opkg  func(ctx context.Context) error // install xray-core through opkg
}

// Ensure guarantees a runnable xray binary at opts.Dest and reports where
// it came from: "existing", "vendored", or "entware". It never removes a
// binary that already runs.
func Ensure(ctx context.Context, opts Options) (string, error) {
	dest := opts.Dest
	if dest == "" {
		dest = "/opt/sbin/xray"
	}
	smoke := opts.smoke
	if smoke == nil {
		smoke = func(bin string) error { return exec.Command(bin, "version").Run() }
	}
	opkg := opts.opkg
	if opkg == nil {
		opkg = realOpkgInstall
	}

	if smoke(dest) == nil {
		return "existing", nil
	}

	if opts.Prefer != "entware" {
		err := installVendored(ctx, opts, dest, smoke)
		if err == nil {
			return "vendored", nil
		}
		if opts.Prefer == "vendored" {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "keenetic-xray: vendored xray-core unavailable (%v); trying opkg\n", err)
	}

	if err := opkg(ctx); err != nil {
		return "", fmt.Errorf("installing xray-core via opkg: %w", err)
	}
	if err := smoke(dest); err != nil {
		return "", fmt.Errorf("xray-core installed via opkg but %s still does not run: %w", dest, err)
	}
	return "entware", nil
}

// Version runs `<binary> version` and returns its first line, e.g.
// "Xray 26.3.27 (Xray, Penetrates Everything.) ...". Shared by
// `keenetic-xray status`/`doctor` and the bot's status command so they
// report the core version the same way.
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

func realOpkgInstall(ctx context.Context) error {
	if _, err := exec.LookPath("opkg"); err != nil {
		return fmt.Errorf("opkg not found: %w", err)
	}
	c := exec.CommandContext(ctx, "opkg", "install", "xray-core")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

func installVendored(ctx context.Context, opts Options, dest string, smoke func(string) error) error {
	tag := opts.Tag
	if tag == "" {
		tag = DefaultTag
	}
	base := opts.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	hc := opts.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 4 * time.Minute}
	}

	name := fmt.Sprintf("xray-%s-linux-%s", tag, runtime.GOARCH)
	assetURL := fmt.Sprintf("%s/%s/%s", strings.TrimRight(base, "/"), tag, name)

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
