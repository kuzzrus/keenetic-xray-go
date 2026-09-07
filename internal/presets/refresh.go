package presets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// DefaultSourceURL is where Refresh pulls the daily-updated lists from:
// the data/ dir on the repo's main branch. Same trust level as
// internal/xraycore fetching xray-core from this repo's releases.
const DefaultSourceURL = "https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/internal/presets/data"

const (
	maxManifestBytes = 512 << 10
	maxListBytes     = 256 << 10
)

// Result summarizes one Refresh run.
type Result struct {
	ManifestDate string
	Checked      int
	Updated      int // .lst files rewritten from upstream
	Skipped      int // up-to-date, left as-is
	Failed       int // fetch/validation failed -- previous copy kept
	Notes        []string
}

func (r Result) String() string {
	s := fmt.Sprintf("проверено %d, обновлено %d, без изменений %d", r.Checked, r.Updated, r.Skipped)
	if r.Failed > 0 {
		s += fmt.Sprintf(", не удалось %d", r.Failed)
	}
	if r.ManifestDate != "" {
		s += " (manifest " + r.ManifestDate + ")"
	}
	return s
}

// OverlayDir returns the live overlay directory, or "" if none is set.
func OverlayDir() string {
	mu.Lock()
	defer mu.Unlock()
	return overlayDir
}

// Refresh pulls the manifest and any changed *.lst from baseURL (""
// -> DefaultSourceURL) into the overlay directory, validating every line
// through config.ClassifyRouteEntry before it's written. A file that
// fails to fetch or validate is left as it was. Requires SetOverlay to
// have been called with a writable path.
func Refresh(ctx context.Context, baseURL string) (Result, error) {
	dir := OverlayDir()
	if dir == "" {
		return Result{}, fmt.Errorf("presets: overlay directory not configured")
	}
	if baseURL == "" {
		baseURL = DefaultSourceURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	hc := &http.Client{Timeout: 30 * time.Second}

	raw, err := httpGet(ctx, hc, baseURL+"/manifest.json", maxManifestBytes)
	if err != nil {
		return Result{}, fmt.Errorf("presets: manifest: %w", err)
	}
	var remote manifest
	if err := json.Unmarshal(raw, &remote); err != nil || len(remote.Presets) == 0 {
		return Result{}, fmt.Errorf("presets: manifest: unparseable or empty")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Result{}, fmt.Errorf("presets: %w", err)
	}

	_, embedIdx := snapshot() // embedded rows, for the local rev baseline & fallback
	res := Result{ManifestDate: remote.Generated, Checked: len(remote.Presets)}
	kept := make([]Preset, 0, len(remote.Presets))

	for _, row := range remote.Presets {
		localRev := localRevOf(dir, row.Name, embedIdx)
		if localRev == row.Rev {
			res.Skipped++
			kept = append(kept, row)
			continue
		}

		body, err := httpGet(ctx, hc, baseURL+"/"+row.Name+".lst", maxListBytes)
		if err != nil {
			res.Failed++
			res.Notes = append(res.Notes, row.Name+": "+err.Error())
			if p, ok := embedIdx[row.Name]; ok {
				kept = append(kept, p) // keep serving the embed
			}
			continue
		}
		lines, dropped := validateList(body, row.Kind)
		if len(lines) == 0 || (row.Count >= 8 && len(lines)*2 < row.Count) {
			res.Failed++
			res.Notes = append(res.Notes, fmt.Sprintf("%s: подозрительный ответ (%d строк, %d отброшено) — оставлен прежний", row.Name, len(lines), dropped))
			if p, ok := embedIdx[row.Name]; ok {
				kept = append(kept, p)
			}
			continue
		}

		if err := writeFileAtomic(filepath.Join(dir, row.Name+".lst"), renderOverlayList(row, lines)); err != nil {
			res.Failed++
			res.Notes = append(res.Notes, row.Name+": запись: "+err.Error())
			continue
		}
		// The rev the manifest advertises must match what we just wrote.
		row.Rev = revOf(lines)
		row.Count = len(lines)
		res.Updated++
		kept = append(kept, row)
	}

	// Overlay manifest reflects exactly what the overlay (or the embed
	// fallback) will serve, so drift checks stay honest.
	remote.Presets = kept
	mfBytes, _ := json.MarshalIndent(remote, "", "  ")
	mfBytes = append(mfBytes, '\n')
	if err := writeFileAtomic(filepath.Join(dir, "manifest.json"), mfBytes); err != nil {
		return res, fmt.Errorf("presets: manifest write: %w", err)
	}
	reload()
	return res, nil
}

// localRevOf is the content hash of the overlay's copy of <name>.lst, or
// the embedded row's rev when the overlay has no copy yet.
func localRevOf(dir, name string, embedIdx map[string]Preset) string {
	if b, err := os.ReadFile(filepath.Join(dir, name+".lst")); err == nil {
		return revOf(dataLines(b))
	}
	return embedIdx[name].Rev
}

func dataLines(b []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// validateList keeps only the lines that pass config.ClassifyRouteEntry
// with the kind the manifest promised, normalized and deduped, order
// preserved.
func validateList(b []byte, kind string) (lines []string, dropped int) {
	want := config.RouteDomain
	if kind == "cidr" {
		want = config.RouteSubnet
	}
	seen := map[string]struct{}{}
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, norm, err := config.ClassifyRouteEntry(ln)
		if err != nil || k != want {
			dropped++
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		lines = append(lines, norm)
	}
	return lines, dropped
}

func renderOverlayList(p Preset, lines []string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — %s\n# refreshed from repo on %s — %d entries\n\n",
		p.Title, p.Kind, time.Now().UTC().Format("2006-01-02"), len(lines))
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func revOf(entries []string) string {
	h := sha256.Sum256([]byte(strings.Join(entries, "\n")))
	return hex.EncodeToString(h[:])[:12]
}

func httpGet(ctx context.Context, hc *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "keenetic-xray presets")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".preset-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
