package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// mixedReleasesJSON mirrors the real repo's release list: app tags
// interleaved with xray-core/* and naive-core/* releases, and a draft
// that must never win.
const mixedReleasesJSON = `[
  {"tag_name":"v0.29.3","draft":false,"prerelease":false},
  {"tag_name":"v0.29.2","draft":false,"prerelease":false},
  {"tag_name":"xray-core/v26.9.9","draft":false,"prerelease":false},
  {"tag_name":"xray-core/v26.3.27","draft":false,"prerelease":false},
  {"tag_name":"naive-core/v150.0.7871.63-1","draft":false,"prerelease":false},
  {"tag_name":"v0.30.0","draft":true,"prerelease":false},
  {"tag_name":"v0.9.9","draft":false,"prerelease":false}
]`

func fakeReleasesServer(t *testing.T, body string) (url string, calls *int32) {
	t.Helper()
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		if r.URL.Path != "/repos/"+repo+"/releases" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/repos/" + repo, &n
}

func TestChecker_LatestAppVersion_IgnoresOtherNamespaces(t *testing.T) {
	base, _ := fakeReleasesServer(t, mixedReleasesJSON)
	c := &Checker{BaseURL: base}
	got, err := c.LatestAppVersion(context.Background())
	if err != nil {
		t.Fatalf("LatestAppVersion: %v", err)
	}
	if got != "v0.29.3" {
		t.Errorf("LatestAppVersion = %q, want v0.29.3 (ignoring xray-core/naive-core entries and a higher draft)", got)
	}
}

func TestChecker_LatestXrayCoreTag_StripsPrefix(t *testing.T) {
	base, _ := fakeReleasesServer(t, mixedReleasesJSON)
	c := &Checker{BaseURL: base}
	got, err := c.LatestXrayCoreTag(context.Background())
	if err != nil {
		t.Fatalf("LatestXrayCoreTag: %v", err)
	}
	if got != "v26.9.9" {
		t.Errorf("LatestXrayCoreTag = %q, want v26.9.9", got)
	}
}

func TestChecker_NoMatchingRelease(t *testing.T) {
	base, _ := fakeReleasesServer(t, `[{"tag_name":"naive-core/v1.0.0-1","draft":false}]`)
	c := &Checker{BaseURL: base}
	if _, err := c.LatestAppVersion(context.Background()); err == nil {
		t.Error("expected an error when nothing matches the app tag shape")
	}
}

func TestChecker_CachesAcrossCalls(t *testing.T) {
	base, calls := fakeReleasesServer(t, mixedReleasesJSON)
	c := &Checker{BaseURL: base}

	for i := 0; i < 3; i++ {
		if _, err := c.LatestAppVersion(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	// Both methods share nothing -- LatestXrayCoreTag has its own cache key.
	if _, err := c.LatestXrayCoreTag(context.Background()); err != nil {
		t.Fatalf("LatestXrayCoreTag: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("HTTP calls = %d, want 2 (one per distinct cache key, repeats served from cache)", got)
	}
}

func TestChecker_CacheExpires(t *testing.T) {
	base, calls := fakeReleasesServer(t, mixedReleasesJSON)
	now := time.Now()
	c := &Checker{BaseURL: base, CacheFor: time.Minute, now: func() time.Time { return now }}

	if _, err := c.LatestAppVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute) // past CacheFor
	if _, err := c.LatestAppVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("HTTP calls = %d, want 2 (cache should have expired)", got)
	}
}

func TestChecker_FetchFailureIsNotCached(t *testing.T) {
	var fail int32 = 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&fail) == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mixedReleasesJSON))
	}))
	t.Cleanup(srv.Close)
	c := &Checker{BaseURL: srv.URL + "/repos/" + repo}

	if _, err := c.LatestAppVersion(context.Background()); err == nil {
		t.Fatal("expected an error from the failing server")
	}
	atomic.StoreInt32(&fail, 0)
	got, err := c.LatestAppVersion(context.Background())
	if err != nil {
		t.Fatalf("expected the retry to succeed once the server recovers, got: %v", err)
	}
	if got != "v0.29.3" {
		t.Errorf("got = %q, want v0.29.3", got)
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.29.3", "v0.29.3", 0},
		{"v0.9.0", "v0.10.0", -1}, // numeric, not lexical
		{"v0.10.0", "v0.9.0", 1},
		{"v26.9.9", "v26.9.8", 1},
		{"v1.0.0", "v2.0.0", -1},
		{"garbage", "v1.0.0", -1}, // malformed parses as all-zero
		{"v1.0.0", "garbage", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); sign(got) != sign(c.want) {
			t.Errorf("CompareVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func TestChecker_UserAgentSet(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mixedReleasesJSON))
	}))
	t.Cleanup(srv.Close)
	c := &Checker{BaseURL: srv.URL + "/repos/" + repo}
	if _, err := c.LatestAppVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ua == "" {
		t.Error("GitHub's API requires a non-empty User-Agent; none was sent")
	}
}

func TestChecker_ZeroValueUsable(t *testing.T) {
	// The zero value must not panic -- it'll just try to reach the real
	// GitHub API. Bound it so this test can't hang, and only assert it
	// doesn't panic; hitting the network for real is not this test's job.
	c := &Checker{}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	_, _ = c.LatestAppVersion(ctx) // expected to error out (deadline), must not panic
}

func TestChecker_PerPage100Requested(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mixedReleasesJSON))
	}))
	t.Cleanup(srv.Close)
	c := &Checker{BaseURL: srv.URL + "/repos/" + repo}
	if _, err := c.LatestAppVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if query != "per_page=100" {
		t.Errorf("query = %q, want per_page=100", query)
	}
}

func TestChecker_DistinctCacheKeysDoNotCollide(t *testing.T) {
	base, calls := fakeReleasesServer(t, mixedReleasesJSON)
	c := &Checker{BaseURL: base}
	app, err := c.LatestAppVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	core, err := c.LatestXrayCoreTag(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if app == core {
		t.Fatalf("test fixture bug: app (%s) and core (%s) tags coincide", app, core)
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Errorf("HTTP calls = %d, want 2", got)
	}
}
