package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

const twoProfileSubBody = "vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=tcp&security=none#alpha\n" +
	"vless://22222222-3333-4444-5555-666666666666@b.example.com:443?type=tcp&security=none#beta\n"

func TestCmdSubscription_SetURLThenRefresh(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	if err := run([]string{"subscription", "set-url", backend.URL}); err != nil {
		t.Fatalf("subscription set-url: %v", err)
	}
	if err := run([]string{"subscription", "refresh"}); err != nil {
		t.Fatalf("subscription refresh: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(cfg.Profiles))
	}
	if cfg.Subscription == nil || cfg.Subscription.URL != backend.URL {
		t.Fatalf("Subscription = %#v", cfg.Subscription)
	}
	if cfg.Subscription.LastFetchedAt.IsZero() {
		t.Error("LastFetchedAt should be set after a refresh")
	}

	if err := run([]string{"subscription", "list"}); err != nil {
		t.Fatalf("subscription list: %v", err)
	}
}

func TestCmdSubscription_RefreshWithoutURLErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"subscription", "refresh"}); err == nil {
		t.Error("expected error refreshing with no subscription URL set")
	}
}

func TestCmdSubscription_RefreshPreservesMatchedSelection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	if err := run([]string{"subscription", "set-url", backend.URL}); err != nil {
		t.Fatalf("set-url: %v", err)
	}
	if err := run([]string{"subscription", "refresh"}); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if err := run([]string{"subscription", "set-primary", "0"}); err != nil {
		t.Fatalf("set-primary: %v", err)
	}
	if err := run([]string{"subscription", "set-backup", "1"}); err != nil {
		t.Fatalf("set-backup: %v", err)
	}

	// Refresh again against the identical body -- remarks are unchanged,
	// so the selection must survive by remark-matching, not by accident.
	if err := run([]string{"subscription", "refresh"}); err != nil {
		t.Fatalf("second refresh: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Primary() == nil || cfg.Primary().Remark != "alpha" {
		t.Errorf("Primary = %#v, want remark \"alpha\"", cfg.Primary())
	}
	if cfg.Backup() == nil || cfg.Backup().Remark != "beta" {
		t.Errorf("Backup = %#v, want remark \"beta\"", cfg.Backup())
	}
}
