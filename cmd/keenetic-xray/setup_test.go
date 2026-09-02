package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestRunSetup_SingleVlessLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	input := strings.NewReader(testVLESSURI + "\n0\n")
	if err := runSetup(input); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1", len(cfg.Profiles))
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 0 {
		t.Errorf("primary=%d backup=%d, want 0,0 (single profile)", cfg.PrimaryIndex, cfg.BackupIndex)
	}
}

func TestRunSetup_Subscription(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	input := strings.NewReader(backend.URL + "\n0\n1\n") // subscription URL, primary=0, backup=1
	if err := runSetup(input); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(cfg.Profiles))
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Errorf("primary=%d backup=%d, want 0,1", cfg.PrimaryIndex, cfg.BackupIndex)
	}
	if cfg.Subscription == nil || cfg.Subscription.URL != backend.URL {
		t.Errorf("Subscription = %#v, want URL %s", cfg.Subscription, backend.URL)
	}
}

func TestRunSetup_DefaultBackupSelection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// Press Enter (blank line) for both prompts -> defaults: primary=0, backup=1.
	input := strings.NewReader(backend.URL + "\n\n\n")
	if err := runSetup(input); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Errorf("primary=%d backup=%d, want 0,1 (defaults)", cfg.PrimaryIndex, cfg.BackupIndex)
	}
}

func TestRunSetup_RejectsUnrecognizedInput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	input := strings.NewReader("not-a-link-or-url\n")
	if err := runSetup(input); err == nil {
		t.Error("expected error for unrecognized input")
	}
}
