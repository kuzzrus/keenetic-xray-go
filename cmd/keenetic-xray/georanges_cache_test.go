package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
)

// A small cache body, deliberately far smaller than the embedded
// snapshot, so georanges.CurrentLen() alone tells which copy got loaded.
const testCacheBody = "10.0.0.0/8\n172.16.0.0/12\n"

const testCacheLen = 2

// withGeorangesCache points the cache at a fresh temp path and resets
// every piece of process-wide state these tests touch.
func withGeorangesCache(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "georanges-ru.txt")
	t.Setenv("KEENETIC_XRAY_GEORANGES_CACHE", path)
	t.Cleanup(func() {
		georanges.SetCurrent(nil)
		georangesCacheSeen.Store(0)
	})
	georanges.SetCurrent(nil)
	georangesCacheSeen.Store(0)
	return path
}

func stubEmbeddedAsOf(t *testing.T, at time.Time, known bool) {
	t.Helper()
	prev := georangesEmbeddedAsOf
	georangesEmbeddedAsOf = func() (time.Time, bool) { return at, known }
	t.Cleanup(func() { georangesEmbeddedAsOf = prev })
}

func writeCacheAt(t *testing.T, path, body string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

type logLines []string

func (l *logLines) logf(format string, a ...any) { *l = append(*l, fmt.Sprintf(format, a...)) }

func (l logLines) contains(sub string) bool {
	for _, s := range l {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestPickGeorangesSource(t *testing.T) {
	build := time.Date(2026, 9, 24, 20, 56, 47, 0, time.UTC)
	before := build.Add(-8 * 24 * time.Hour)
	after := build.Add(time.Hour)

	cases := []struct {
		name        string
		cacheUsable bool
		cacheMTime  time.Time
		asOfKnown   bool
		want        georangesSource
	}{
		{"no cache", false, time.Time{}, true, georangesFromEmbedded},
		// The 2026-09-26 bug: an update's newer snapshot used to sit
		// behind whatever cache was already on disk, for up to a day.
		{"cache older than the build", true, before, true, georangesFromEmbedded},
		{"cache fetched after the build", true, after, true, georangesFromCache},
		{"cache fetched at the build instant", true, build, true, georangesFromCache},
		// A dev build has no trustworthy time: nothing proves the
		// snapshot newer, so the cache keeps its old precedence.
		{"build time unknown", true, before, false, georangesFromCache},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickGeorangesSource(c.cacheUsable, c.cacheMTime, build, c.asOfKnown); got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestGeorangesFirstRefreshDelay(t *testing.T) {
	if got := georangesFirstRefreshDelay(false, 0); got != georangesRetryBackoff[0] {
		t.Errorf("empty table: %v, want the first backoff step %v -- the veto is off until data loads", got, georangesRetryBackoff[0])
	}
	if got := georangesFirstRefreshDelay(true, 10); got != georangesRefreshInterval {
		t.Errorf("just fetched: %v, want %v -- fetching again at once is pointless", got, georangesRefreshInterval)
	}
	// The latent bug this closes: a daemon restarted more often than
	// once a day used to never refresh at all, because every restart
	// began a fresh 24h wait.
	if got := georangesFirstRefreshDelay(false, 10); got != georangesRefreshSettle {
		t.Errorf("loaded from disk or embedded: %v, want %v", got, georangesRefreshSettle)
	}
	if georangesRefreshSettle >= 10*time.Minute {
		t.Errorf("georangesRefreshSettle = %v, must stay short -- restarts are exactly when a stale list needs replacing", georangesRefreshSettle)
	}
}

// TestGeorangesLoadLocal_EmbeddedNewerThanCacheWins is the headline
// regression: after an update, the new binary's snapshot must not sit
// unused behind a cache fetched days before that build existed.
func TestGeorangesLoadLocal_EmbeddedNewerThanCacheWins(t *testing.T) {
	path := withGeorangesCache(t)
	build := time.Now().Add(-time.Hour)
	stubEmbeddedAsOf(t, build, true)
	writeCacheAt(t, path, testCacheBody, build.Add(-8*24*time.Hour))

	var log logLines
	if usable := georangesLoadLocal(log.logf); !usable {
		t.Error("cacheUsable = false, want true -- the cache is fine, just older")
	}
	if got, want := georanges.CurrentLen(), georanges.Embedded().Len(); got != want {
		t.Fatalf("loaded %d ranges, want the embedded %d", got, want)
	}
	if !log.contains("older than this build's embedded snapshot") {
		t.Errorf("log = %q, want it to say why the cache was passed over", log)
	}
}

func TestGeorangesLoadLocal_CacheNewerThanBuildWins(t *testing.T) {
	path := withGeorangesCache(t)
	build := time.Now().Add(-48 * time.Hour)
	stubEmbeddedAsOf(t, build, true)
	writeCacheAt(t, path, testCacheBody, build.Add(24*time.Hour))

	var log logLines
	georangesLoadLocal(log.logf)
	if got := georanges.CurrentLen(); got != testCacheLen {
		t.Fatalf("loaded %d ranges, want the cache's %d", got, testCacheLen)
	}
	if !log.contains("from cache") {
		t.Errorf("log = %q", log)
	}
}

func TestGeorangesLoadLocal_UnknownBuildTimeKeepsCache(t *testing.T) {
	path := withGeorangesCache(t)
	stubEmbeddedAsOf(t, time.Time{}, false)
	writeCacheAt(t, path, testCacheBody, time.Now().Add(-30*24*time.Hour))

	georangesLoadLocal(func(string, ...any) {})
	if got := georanges.CurrentLen(); got != testCacheLen {
		t.Errorf("loaded %d ranges, want the cache's %d", got, testCacheLen)
	}
}

// TestGeorangesLoadLocal_UnusableCacheFallsBackToEmbedded: an empty or
// garbled cache used to be loaded as-is, leaving an empty table -- the
// veto silently off -- even though a full snapshot sat in the binary.
func TestGeorangesLoadLocal_UnusableCacheFallsBackToEmbedded(t *testing.T) {
	path := withGeorangesCache(t)
	stubEmbeddedAsOf(t, time.Time{}, false) // would otherwise favour the cache
	writeCacheAt(t, path, "# only a header, the rest got truncated\n", time.Now())

	var log logLines
	if usable := georangesLoadLocal(log.logf); usable {
		t.Error("cacheUsable = true for a cache with no ranges in it")
	}
	if got := georanges.CurrentLen(); got == 0 {
		t.Fatal("table is empty -- the veto would be off with a full snapshot in the binary")
	}
	if !log.contains("unusable") {
		t.Errorf("log = %q, want it to say the cache was unusable", log)
	}
}

func TestGeorangesLoadLocal_NoCache(t *testing.T) {
	withGeorangesCache(t)
	stubEmbeddedAsOf(t, time.Now(), true)

	var log logLines
	if usable := georangesLoadLocal(log.logf); usable {
		t.Error("cacheUsable = true with no cache on disk")
	}
	if georanges.CurrentLen() == 0 {
		t.Fatal("table is empty -- the embedded snapshot should have loaded")
	}
	if !log.contains("no cache on disk") {
		t.Errorf("log = %q", log)
	}
}

// TestReloadGeorangesIfCacheChanged covers the cache watch that hands a
// `georanges refresh` result to the running daemon without a signal.
func TestReloadGeorangesIfCacheChanged(t *testing.T) {
	path := withGeorangesCache(t)
	stubEmbeddedAsOf(t, time.Time{}, false)
	first := time.Now().Add(-2 * time.Hour)
	writeCacheAt(t, path, testCacheBody, first)
	georangesLoadLocal(func(string, ...any) {})

	var log logLines
	if reloadGeorangesIfCacheChanged(log.logf) {
		t.Fatal("reloaded an unchanged cache")
	}
	if len(log) != 0 {
		t.Errorf("an unchanged cache must be silent -- this runs every %v; got %q", georangesCacheWatchInterval, log)
	}

	// Somebody else rewrites it -- what the CLI refresh does.
	writeCacheAt(t, path, testCacheBody+"192.168.0.0/16\n", first.Add(time.Hour))
	if !reloadGeorangesIfCacheChanged(log.logf) {
		t.Fatal("did not pick up a rewritten cache")
	}
	if got := georanges.CurrentLen(); got != testCacheLen+1 {
		t.Errorf("loaded %d ranges, want %d from the rewritten cache", got, testCacheLen+1)
	}
	if reloadGeorangesIfCacheChanged(log.logf) {
		t.Error("reloaded the same rewrite twice")
	}
}

func TestReloadGeorangesIfCacheChanged_UnusableRewriteKeepsTable(t *testing.T) {
	path := withGeorangesCache(t)
	stubEmbeddedAsOf(t, time.Time{}, false)
	writeCacheAt(t, path, testCacheBody, time.Now().Add(-2*time.Hour))
	georangesLoadLocal(func(string, ...any) {})

	writeCacheAt(t, path, "garbage\n", time.Now())
	var log logLines
	if reloadGeorangesIfCacheChanged(log.logf) {
		t.Fatal("swapped in a cache with no ranges")
	}
	if got := georanges.CurrentLen(); got != testCacheLen {
		t.Errorf("table now has %d ranges, want the previous %d kept", got, testCacheLen)
	}
	if len(log) != 1 {
		t.Fatalf("log = %q, want exactly one line saying the new cache is unusable", log)
	}
	// Same bad file on the next tick: already reported, stay quiet.
	reloadGeorangesIfCacheChanged(log.logf)
	if len(log) != 1 {
		t.Errorf("the same unusable file was reported again: %q", log)
	}
}

func TestReloadGeorangesIfCacheChanged_NoCacheIsQuiet(t *testing.T) {
	withGeorangesCache(t)
	var log logLines
	if reloadGeorangesIfCacheChanged(log.logf) || len(log) != 0 {
		t.Errorf("no cache on disk must be a silent no-op, got %q", log)
	}
}

func serveGeoranges(t *testing.T, status int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	prev := georangesFetchURL
	georangesFetchURL = srv.URL
	t.Cleanup(func() { georangesFetchURL = prev })
}

// TestRunGeorangesRefresh_OwnWriteIsNotNews: the daemon's own refresh
// rewrites the cache, and the watch must not then "discover" that write
// as an outside change and reload it for nothing.
func TestRunGeorangesRefresh_OwnWriteIsNotNews(t *testing.T) {
	path := withGeorangesCache(t)
	serveGeoranges(t, http.StatusOK, testCacheBody)

	if !runGeorangesRefresh(context.Background(), func(string, ...any) {}) {
		t.Fatal("refresh failed against a healthy source")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != testCacheBody {
		t.Fatalf("cache = %q, %v; want the fetched body persisted", b, err)
	}
	var log logLines
	if reloadGeorangesIfCacheChanged(log.logf) {
		t.Error("the watch treated the daemon's own write as an outside change")
	}
}

func TestRunGeorangesRefresh_EmptyResponseKeepsTable(t *testing.T) {
	path := withGeorangesCache(t)
	serveGeoranges(t, http.StatusOK, "# nothing here\n")
	georanges.SetCurrent(georanges.Parse(testCacheBody))

	var log logLines
	if runGeorangesRefresh(context.Background(), log.logf) {
		t.Fatal("refresh reported success for a response with no ranges")
	}
	if got := georanges.CurrentLen(); got != testCacheLen {
		t.Errorf("table now has %d ranges, want the previous %d kept", got, testCacheLen)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("an empty response must never reach the cache")
	}
}

func TestGeorangesRefreshCLI(t *testing.T) {
	path := withGeorangesCache(t)
	serveGeoranges(t, http.StatusOK, testCacheBody)

	var out bytes.Buffer
	if err := georangesRefreshCLI(context.Background(), &out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != testCacheBody {
		t.Fatalf("cache = %q, %v; want the fetched body", b, err)
	}
	if !strings.Contains(out.String(), fmt.Sprintf("сохранено: %d диапазонов", testCacheLen)) {
		t.Errorf("output = %q, want the saved count", out.String())
	}
	// And the running daemon's watch sees it as news.
	if !reloadGeorangesIfCacheChanged(func(string, ...any) {}) {
		t.Error("a CLI refresh was not picked up by the cache watch")
	}
}

func TestGeorangesRefreshCLI_FailureLeavesCacheAlone(t *testing.T) {
	path := withGeorangesCache(t)
	writeCacheAt(t, path, testCacheBody, time.Now().Add(-time.Hour))

	for name, srv := range map[string]struct {
		status int
		body   string
	}{
		"server error":   {http.StatusInternalServerError, "oops"},
		"empty response": {http.StatusOK, "# header only\n"},
	} {
		t.Run(name, func(t *testing.T) {
			serveGeoranges(t, srv.status, srv.body)
			if err := georangesRefreshCLI(context.Background(), &bytes.Buffer{}); err == nil {
				t.Fatal("want an error")
			}
			if b, _ := os.ReadFile(path); string(b) != testCacheBody {
				t.Errorf("cache = %q, want the previous copy untouched", b)
			}
		})
	}
}

func TestGeorangesShow(t *testing.T) {
	path := withGeorangesCache(t)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

	stubEmbeddedAsOf(t, now.Add(-2*24*time.Hour), true)
	writeCacheAt(t, path, testCacheBody, now.Add(-10*24*time.Hour))
	var out bytes.Buffer
	georangesShow(&out, now)
	for _, want := range []string{
		fmt.Sprintf("%d диапазонов, скачан 2026-09-16 12:00 UTC (10 д 0 ч назад)", testCacheLen),
		"по состоянию на 2026-09-24 12:00 UTC",
		"при старте демон возьмёт: встроенный",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}

	writeCacheAt(t, path, testCacheBody, now.Add(-time.Hour))
	out.Reset()
	georangesShow(&out, now)
	if !strings.Contains(out.String(), "при старте демон возьмёт: кэш") {
		t.Errorf("a cache newer than the build should be the pick:\n%s", out.String())
	}
}

func TestAgeRU(t *testing.T) {
	for d, want := range map[time.Duration]string{
		30 * time.Second:                 "меньше минуты",
		7 * time.Minute:                  "7 мин",
		5*time.Hour + 12*time.Minute:     "5 ч 12 мин",
		3*24*time.Hour + 4*time.Hour:     "3 д 4 ч",
		10*24*time.Hour + 59*time.Minute: "10 д 0 ч",
	} {
		if got := ageRU(d); got != want {
			t.Errorf("ageRU(%v) = %q, want %q", d, got, want)
		}
	}
}
