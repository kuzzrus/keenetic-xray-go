// Package updatecheck discovers this project's own latest published
// releases on GitHub -- the keenetic-xray app itself, and the xray-core
// tags mirrored under internal/xraycore's trust model -- so a running
// control server can offer live data instead of whatever was compiled
// into it at its last build (internal/xraycore's DefaultTag/PrereleaseTag
// pins, or the control server's own version.Version). GitHub's
// unauthenticated REST API allows only 60 requests/hour per IP, and a
// control server may be asked many times an hour (every bot screen
// open, every periodic watch tick), so every result is cached.
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const repo = "kuzzrus/keenetic-xray-go"

const defaultBaseURL = "https://api.github.com/repos/" + repo

// DefaultCacheFor bounds how often Checker actually hits GitHub.
const DefaultCacheFor = time.Hour

const fetchTimeout = 10 * time.Second

// Checker discovers the latest keenetic-xray app release
// ("LatestAppVersion") and the newest mirrored xray-core tag
// ("LatestXrayCoreTag"). The zero value is usable: a default HTTP
// client, the real GitHub API, DefaultCacheFor. Safe for concurrent use.
type Checker struct {
	HTTP     *http.Client
	CacheFor time.Duration
	BaseURL  string // "" -> https://api.github.com/repos/kuzzrus/keenetic-xray-go

	now func() time.Time // test seam; nil -> time.Now

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	value string
	at    time.Time
}

// bareVersionRe matches a plain "vX.Y.Z" (or "X.Y.Z") tag -- the shape
// both keenetic-xray's own release tags and upstream XTLS/Xray-core's
// tags happen to share, which is what lets one comparator serve both.
var bareVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// CompareVersions compares two "vX.Y.Z"-shaped tags numerically,
// component by component -- a plain lexical compare would sort "v0.9.0"
// after "v0.10.0", which is wrong. A tag that doesn't match the shape
// parses as all-zero, so a malformed value never panics; it just never
// outranks a well-formed one.
func CompareVersions(a, b string) int {
	pa, pb := parseVersionParts(a), parseVersionParts(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseVersionParts(tag string) [3]int {
	m := bareVersionRe.FindStringSubmatch(tag)
	if m == nil {
		return [3]int{}
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out
}

// LatestAppVersion returns the highest-versioned keenetic-xray app
// release tag (e.g. "v0.29.3") -- ignoring the xray-core/* and
// naive-core/* releases published to the same repo.
func (c *Checker) LatestAppVersion(ctx context.Context) (string, error) {
	return c.latest(ctx, "app", "")
}

// LatestXrayCoreTag returns the highest-versioned mirrored
// "xray-core/<tag>" release (tag stripped) -- what `keenetic-xray
// internal ensure-xray-core --tag=<tag>` could actually fetch right
// now, as opposed to whatever xraycore.PrereleaseTag was compiled into
// a given control-server build.
func (c *Checker) LatestXrayCoreTag(ctx context.Context) (string, error) {
	return c.latest(ctx, "xray-core", "xray-core/")
}

func (c *Checker) latest(ctx context.Context, cacheKey, tagPrefix string) (string, error) {
	if v, ok := c.cached(cacheKey); ok {
		return v, nil
	}

	releases, err := c.fetchReleases(ctx)
	if err != nil {
		return "", err
	}

	best := ""
	for _, r := range releases {
		if r.Draft {
			continue
		}
		rest, ok := strings.CutPrefix(r.TagName, tagPrefix)
		if !ok || !bareVersionRe.MatchString(rest) {
			continue
		}
		if best == "" || CompareVersions(rest, best) > 0 {
			best = rest
		}
	}
	if best == "" {
		return "", fmt.Errorf("no matching release found in %s (tag prefix %q)", repo, tagPrefix)
	}

	c.store(cacheKey, best)
	return best, nil
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Draft   bool   `json:"draft"`
}

func (c *Checker) fetchReleases(ctx context.Context) ([]ghRelease, error) {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: fetchTimeout}
	}
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	url := strings.TrimRight(base, "/") + "/releases?per_page=100"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "keenetic-xray-go-control-server")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	var releases []ghRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("parsing response from %s: %w", url, err)
	}
	return releases, nil
}

func (c *Checker) nowOrReal() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *Checker) cached(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok {
		return "", false
	}
	ttl := c.CacheFor
	if ttl <= 0 {
		ttl = DefaultCacheFor
	}
	if c.nowOrReal().Sub(e.at) > ttl {
		return "", false
	}
	return e.value, true
}

func (c *Checker) store(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]cacheEntry{}
	}
	c.cache[key] = cacheEntry{value: value, at: c.nowOrReal()}
}
