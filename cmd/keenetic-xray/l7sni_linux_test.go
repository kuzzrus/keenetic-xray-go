//go:build linux

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestL7SNIClassifySession_DisabledReturnsNotStarted confirms the
// contract l7SNIClassifyLoop's own retry logic depends on (L7-02): a
// session that never actually began capturing must report
// started=false, so the outer loop doesn't spin retrying a condition
// (the feature being off) that won't resolve itself moments later.
func TestL7SNIClassifySession_DisabledReturnsNotStarted(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = false
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	started, err := l7SNIClassifySession(context.Background(), func(string, ...any) {})
	if started {
		t.Error("started = true, want false -- L7SNI.Enabled is off")
	}
	if err != nil {
		t.Errorf("err = %v, want nil for a deliberately-off feature", err)
	}
}

// TestL7SNIClassifySession_NoRouterReturnsNotStarted mirrors
// adaptiveRouteClassifyLoop's own no-router test: this dev/CI
// environment has no real keenetic.Available(), so an enabled feature
// still can't actually start, and must report that cleanly (not
// started, no error) rather than being treated as a failure worth
// retrying.
func TestL7SNIClassifySession_NoRouterReturnsNotStarted(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = true
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	started, err := l7SNIClassifySession(context.Background(), func(string, ...any) {})
	if started {
		t.Error("started = true, want false -- no real router in this environment")
	}
	if err != nil {
		t.Errorf("err = %v, want nil -- no ndmc is a clean not-started outcome, not a failure", err)
	}
}

// TestL7SNIClassifyLoop_DisabledStopsWithoutRetrying is L7-02's own
// regression test for the retry-vs-give-up split: a genuinely disabled
// feature must not spin l7SNIClassifyLoop's new retry loop -- it should
// return promptly, the same one-shot behavior the pre-L7-02 code always
// had for this exact case. Uses an uncancelled context deliberately: if
// this regressed into retrying a condition that will never resolve, the
// goroutine would still be running when the timeout below fires, which
// is exactly the failure this guards against.
func TestL7SNIClassifyLoop_DisabledStopsWithoutRetrying(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = false
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		l7SNIClassifyLoop(context.Background(), func(string, ...any) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("l7SNIClassifyLoop did not return promptly for a disabled feature -- it must not retry a condition that won't resolve on its own")
	}
}
