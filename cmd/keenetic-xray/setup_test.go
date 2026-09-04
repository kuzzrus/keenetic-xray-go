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

// secondTestVLESSURI is a distinct link from testVLESSURI, for tests
// that need two independently-configured slots -- the interactive
// wizard always asks primary and backup separately now, so a bare
// single link (the old single-slot fixture) only ever answers primary.
const secondTestVLESSURI = "vless://22222222-3333-4444-5555-666666666666@backup.example.com:443?type=tcp&security=none#backup-node"

func TestRunSetupInteractive_TwoIndependentVlessLinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// primary link, backup link, then Enter/Enter for default ports.
	input := strings.NewReader(testVLESSURI + "\n" + secondTestVLESSURI + "\n\n\n")
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
	if cfg.PrimarySource == nil || cfg.PrimarySource.URL != testVLESSURI {
		t.Errorf("PrimarySource = %+v, want URL %s", cfg.PrimarySource, testVLESSURI)
	}
	if cfg.BackupSource == nil || cfg.BackupSource.URL != secondTestVLESSURI {
		t.Errorf("BackupSource = %+v, want URL %s", cfg.BackupSource, secondTestVLESSURI)
	}
	if cfg.Failover.SOCKSPort != 1080 || cfg.Failover.HTTPPort != 1081 {
		t.Errorf("ports = %d/%d, want defaults 1080/1081", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	}
}

func TestRunSetupInteractive_BothFromSubscriptionDifferentIndices(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// primary: subscription -> index 0 (alpha). backup: same subscription
	// (fetched independently) -> index 1 (beta). Then default ports.
	input := strings.NewReader(backend.URL + "\n0\n" + backend.URL + "\n1\n\n\n")
	if err := runSetup(input, setupOpts{}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2 (same two profiles both fetches, merged not duplicated)", len(cfg.Profiles))
	}
	if cfg.Profiles[cfg.PrimaryIndex].Remark != "alpha" {
		t.Errorf("primary remark = %q, want alpha", cfg.Profiles[cfg.PrimaryIndex].Remark)
	}
	if cfg.Profiles[cfg.BackupIndex].Remark != "beta" {
		t.Errorf("backup remark = %q, want beta", cfg.Profiles[cfg.BackupIndex].Remark)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.Selector != "0" {
		t.Errorf("PrimarySource = %+v, want selector 0", cfg.PrimarySource)
	}
	if cfg.BackupSource == nil || cfg.BackupSource.Selector != "1" {
		t.Errorf("BackupSource = %+v, want selector 1", cfg.BackupSource)
	}
	// Unlike non-interactive setup, per-slot sources never touch the
	// shared subscription -- same as the bot's 🔗 Источники.
	if cfg.Subscription != nil {
		t.Errorf("Subscription = %+v, want nil (per-slot sources don't set it)", cfg.Subscription)
	}
}

func TestRunSetupInteractive_BlankIndexDefaultsToZero(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, twoProfileSubBody)
	}))
	defer backend.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// primary: subscription, blank Enter -> default index 0 (alpha).
	// backup: a plain link, to keep this test focused on the default.
	input := strings.NewReader(backend.URL + "\n\n" + testVLESSURI + "\n\n\n")
	if err := runSetup(input, setupOpts{}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profiles[cfg.PrimaryIndex].Remark != "alpha" {
		t.Errorf("primary remark = %q, want alpha (blank Enter -> default index 0)", cfg.Profiles[cfg.PrimaryIndex].Remark)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.Selector != "0" {
		t.Errorf("PrimarySource = %+v, want selector 0", cfg.PrimarySource)
	}
}

func TestRunSetupInteractive_CustomPorts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	input := strings.NewReader(testVLESSURI + "\n" + secondTestVLESSURI + "\n9090\n9091\n")
	if err := runSetup(input, setupOpts{}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Failover.SOCKSPort != 9090 || cfg.Failover.HTTPPort != 9091 {
		t.Errorf("ports = %d/%d, want 9090/9091", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	}
}

func TestRunSetupInteractive_CollidingPortsReprompt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// First attempt collides (9090/9090); must re-prompt for both rather
	// than silently accepting or erroring out.
	input := strings.NewReader(testVLESSURI + "\n" + secondTestVLESSURI + "\n9090\n9090\n9090\n9091\n")
	if err := runSetup(input, setupOpts{}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Failover.SOCKSPort != 9090 || cfg.Failover.HTTPPort != 9091 {
		t.Errorf("ports = %d/%d, want 9090/9091 after re-prompt", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
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
