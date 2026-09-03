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
	if err := runSetup(input, setupOpts{}); err != nil {
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
	if err := runSetup(input, setupOpts{}); err != nil {
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
	if err := runSetup(input, setupOpts{}); err != nil {
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
	if err := runSetup(input, setupOpts{}); err == nil {
		t.Error("expected error for unrecognized input")
	}
}

func TestRunSetup_NonInteractive(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// No stdin -- everything comes from opts. This is the postinst path.
	if err := runSetup(strings.NewReader(""), setupOpts{From: backend.URL, Yes: true, Proxy0: "no"}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 2 || cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Fatalf("profiles=%d primary=%d backup=%d, want 2/0/1", len(cfg.Profiles), cfg.PrimaryIndex, cfg.BackupIndex)
	}
	if cfg.Subscription == nil || cfg.Subscription.URL != backend.URL {
		t.Errorf("subscription not recorded: %#v", cfg.Subscription)
	}
}

func TestResolveProfileSelector(t *testing.T) {
	ps := []config.Profile{{Remark: "Netherlands A"}, {Remark: "Germany B"}, {Remark: "netherlands C"}}
	cases := []struct {
		sel     string
		want    int
		wantErr bool
	}{
		{"", 1, false},           // default
		{"2", 2, false},          // index
		{"germany", 1, false},    // unique, case-insensitive
		{"netherlands", 0, true}, // matches 0 and 2
		{"france", 0, true},      // no match
		{"9", 0, true},           // out of range
	}
	for _, c := range cases {
		got, err := resolveProfileSelector(ps, c.sel, 1)
		if (err != nil) != c.wantErr {
			t.Errorf("sel %q: err=%v, wantErr=%v", c.sel, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("sel %q: got %d, want %d", c.sel, got, c.want)
		}
	}
}
