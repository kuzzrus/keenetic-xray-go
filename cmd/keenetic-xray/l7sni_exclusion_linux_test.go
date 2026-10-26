//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
)

func exclusionsFrom(t *testing.T, text string) *adaptiveroute.Exclusions {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adaptive-exclude.txt")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	ex, err := adaptiveroute.LoadExclusions(path)
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

func resetL7SNIExcludedLog() {
	l7sniExcludedLogged.Lock()
	l7sniExcludedLogged.at = map[string]time.Time{}
	l7sniExcludedLogged.Unlock()
}

// A routes-list match on an address the operator excluded must not be
// redirected, and must say why -- but only once in a while, not on every
// connection to a busy excluded address.
func TestL7SNIBlockedByExclusion(t *testing.T) {
	resetL7SNIExcludedLog()
	t.Cleanup(resetL7SNIExcludedLog)
	snap := l7sniSnapshot{excluded: exclusionsFrom(t, "142.251.153.4\n31.13.72.0/24\n")}
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
	t0 := time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC)

	if !l7sniBlockedByExclusion(snap, "youtube.com", "142.251.153.4", 443, t0, logf) {
		t.Fatal("an excluded address was not blocked")
	}
	if !l7sniBlockedByExclusion(snap, "instagram.com", "31.13.72.200", 443, t0, logf) {
		t.Fatal("an address inside an excluded network was not blocked")
	}
	if l7sniBlockedByExclusion(snap, "youtube.com", "142.251.153.5", 443, t0, logf) {
		t.Error("a neighbouring address that is NOT on the list was blocked")
	}
	if len(logged) != 2 || !strings.Contains(logged[0], "youtube.com -> 142.251.153.4:443") || !strings.Contains(logged[0], "exclusion list") {
		t.Errorf("log = %q, want one line per blocked address naming the host and the reason", logged)
	}

	// the same address again, soon after: blocked, but not logged again
	logged = nil
	l7sniBlockedByExclusion(snap, "youtube.com", "142.251.153.4", 443, t0.Add(time.Minute), logf)
	if len(logged) != 0 {
		t.Errorf("log = %q, want the repeat suppressed", logged)
	}
	// ... and again once the quiet period is over
	l7sniBlockedByExclusion(snap, "youtube.com", "142.251.153.4", 443, t0.Add(l7sniExcludedLogEvery+time.Second), logf)
	if len(logged) != 1 {
		t.Errorf("log = %q, want the line back after %v", logged, l7sniExcludedLogEvery)
	}
}

func TestL7SNIBlockedByExclusion_NoListBlocksNothing(t *testing.T) {
	resetL7SNIExcludedLog()
	t.Cleanup(resetL7SNIExcludedLog)
	var logged []string
	logf := func(format string, args ...any) { logged = append(logged, format) }
	for _, snap := range []l7sniSnapshot{{}, {excluded: &adaptiveroute.Exclusions{}}} {
		if l7sniBlockedByExclusion(snap, "youtube.com", "142.251.153.4", 443, time.Now(), logf) {
			t.Errorf("snapshot %+v blocked an address with no list", snap)
		}
	}
	if len(logged) != 0 {
		t.Errorf("log = %q, want nothing", logged)
	}
}

func TestL7SNIShouldLogExcluded_StaysBounded(t *testing.T) {
	resetL7SNIExcludedLog()
	t.Cleanup(resetL7SNIExcludedLog)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		l7sniShouldLogExcluded(fmt.Sprintf("10.%d.%d.1", i/250, i%250), now)
	}
	l7sniExcludedLogged.Lock()
	n := len(l7sniExcludedLogged.at)
	l7sniExcludedLogged.Unlock()
	if n > 256 {
		t.Errorf("the rate-limit table grew to %d entries", n)
	}
}
