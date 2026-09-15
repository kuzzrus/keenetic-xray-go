package knownranges

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// SourceURL is the one combined, already-deduplicated file covering
// every provider lord-alfred/ipranges tracks -- same repo and license
// tier internal/presets' instagram-ip preset already sources its own
// (narrower, Facebook-only) list from.
const SourceURL = "https://raw.githubusercontent.com/lord-alfred/ipranges/main/all/ipv4_merged.txt"

// maxSourceBytes caps the download -- the real file is roughly 150KB as
// of 2026; a much larger response is a sign something's wrong upstream,
// not a reason to keep reading.
const maxSourceBytes = 4 << 20

// FetchRaw downloads the current combined range list as raw text from
// sourceURL ("" -> SourceURL). Doesn't parse or cache it -- the caller
// decides what to do with a successful fetch (SaveCache it, then Parse
// it). The parameter (rather than a bare constant) is what lets tests
// point this at an httptest server instead of the real GitHub mirror,
// same convention as internal/presets.Refresh's own baseURL.
func FetchRaw(ctx context.Context, sourceURL string) (string, error) {
	if sourceURL == "" {
		sourceURL = SourceURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "keenetic-xray knownranges")
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("knownranges: fetch: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSourceBytes))
	if err != nil {
		return "", fmt.Errorf("knownranges: fetch: %w", err)
	}
	return string(b), nil
}

// LoadCacheRaw reads back a previously SaveCache'd copy, e.g. right after
// startup, before the first refresh has had a chance to run.
func LoadCacheRaw(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SaveCacheRaw writes raw to path atomically (temp file + rename, same
// convention as internal/presets' writeFileAtomic), so a reader never
// observes a half-written file.
func SaveCacheRaw(path, raw string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("knownranges: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".known-ranges-*.tmp")
	if err != nil {
		return fmt.Errorf("knownranges: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("knownranges: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("knownranges: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("knownranges: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("knownranges: %w", err)
	}
	return nil
}
