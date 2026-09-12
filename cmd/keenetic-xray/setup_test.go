package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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

// thirdTestVLESSURI is a third distinct link, for the field-editor tests
// that swap a slot's source to something not already configured.
const thirdTestVLESSURI = "vless://33333333-4444-5555-6666-777777777777@third.example.com:443?type=tcp&security=none#third"

// seedTwoLinkConfig runs the wizard once (primary + backup as two vless
// links, default ports) so a follow-up `runSetup` lands in the field
// editor rather than the wizard.
func seedTwoLinkConfig(t *testing.T) {
	t.Helper()
	in := strings.NewReader(testVLESSURI + "\n" + secondTestVLESSURI + "\n\n\n")
	if err := runSetup(in, setupOpts{}); err != nil {
		t.Fatalf("seed runSetup: %v", err)
	}
}

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

func TestRunSetupInteractive_VlessPrimaryNaiveBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	const naiveBackupURI = "naive+https://alice:s3cret@n.example.com:443#naive-backup"
	// primary vless link, backup naive link, then Enter/Enter for default ports.
	input := strings.NewReader(testVLESSURI + "\n" + naiveBackupURI + "\n\n\n")
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
	if got := cfg.Profiles[cfg.PrimaryIndex]; got.Protocol != "" || got.Remark != "test" {
		t.Errorf("primary = %+v, want the vless profile", got)
	}
	if got := cfg.Profiles[cfg.BackupIndex]; got.Protocol != "naive" || got.Remark != "naive-backup" || got.User != "alice" {
		t.Errorf("backup = %+v, want the naive profile", got)
	}
	if cfg.BackupSource == nil || cfg.BackupSource.URL != naiveBackupURI {
		t.Errorf("BackupSource = %+v, want URL %s", cfg.BackupSource, naiveBackupURI)
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

func TestRunSetupInteractive_SkipBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	// primary link, empty Enter for backup (skip), Enter/Enter for ports,
	// Enter for transport.
	input := strings.NewReader(testVLESSURI + "\n\n\n\n\n")
	if err := runSetup(input, setupOpts{}); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 1 {
		t.Fatalf("len(Profiles) = %d, want 1 (backup skipped)", len(cfg.Profiles))
	}
	if cfg.BackupSource != nil {
		t.Errorf("BackupSource = %+v, want nil after skip", cfg.BackupSource)
	}
	if cfg.BackupIndex != cfg.PrimaryIndex {
		t.Errorf("BackupIndex = %d, want == PrimaryIndex %d (single-profile marker)", cfg.BackupIndex, cfg.PrimaryIndex)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.URL != testVLESSURI {
		t.Errorf("PrimarySource = %+v", cfg.PrimarySource)
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

func TestRunSetupEdit_ChangePortsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	seedTwoLinkConfig(t)

	// "3" -> ports edit; 7070/7071; then Enter to leave the editor.
	if err := runSetup(strings.NewReader("3\n7070\n7071\n\n"), setupOpts{}); err != nil {
		t.Fatalf("runSetup (edit): %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Failover.SOCKSPort != 7070 || cfg.Failover.HTTPPort != 7071 {
		t.Errorf("ports = %d/%d, want 7070/7071", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	}
	// Everything else must be untouched.
	if len(cfg.Profiles) != 2 || cfg.PrimaryIndex != 0 || cfg.BackupIndex != 1 {
		t.Errorf("profiles disturbed: n=%d primary=%d backup=%d", len(cfg.Profiles), cfg.PrimaryIndex, cfg.BackupIndex)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.URL != testVLESSURI {
		t.Errorf("PrimarySource changed: %+v", cfg.PrimarySource)
	}
	if cfg.BackupSource == nil || cfg.BackupSource.URL != secondTestVLESSURI {
		t.Errorf("BackupSource changed: %+v", cfg.BackupSource)
	}
}

func TestRunSetupEdit_BareEnterNoChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	seedTwoLinkConfig(t)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := runSetup(strings.NewReader("\n"), setupOpts{}); err != nil {
		t.Fatalf("runSetup (edit): %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("config rewritten on a no-op editor session:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestRunSetupEdit_ChangePrimarySource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	seedTwoLinkConfig(t)

	// "1" -> primary edit; a link not already configured; Enter to leave.
	if err := runSetup(strings.NewReader("1\n"+thirdTestVLESSURI+"\n\n"), setupOpts{}); err != nil {
		t.Fatalf("runSetup (edit): %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.URL != thirdTestVLESSURI {
		t.Errorf("PrimarySource = %+v, want %s", cfg.PrimarySource, thirdTestVLESSURI)
	}
	if p := cfg.Primary(); p == nil || p.Remark != "third" {
		t.Errorf("Primary() = %+v, want remark 'third'", p)
	}
	// Backup slot must be left alone.
	if cfg.BackupSource == nil || cfg.BackupSource.URL != secondTestVLESSURI {
		t.Errorf("BackupSource = %+v, want %s (untouched)", cfg.BackupSource, secondTestVLESSURI)
	}
}

func TestRunSetupEdit_WizardFlagForcesWizard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	seedTwoLinkConfig(t)

	// --wizard skips the editor: this input is the linear flow (new
	// primary link, skip backup, default ports, Enter through transport).
	if err := runSetup(strings.NewReader(thirdTestVLESSURI+"\n\n\n\n\n"), setupOpts{Wizard: true}); err != nil {
		t.Fatalf("runSetup --wizard: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrimarySource == nil || cfg.PrimarySource.URL != thirdTestVLESSURI {
		t.Errorf("PrimarySource = %+v, want %s (wizard ran)", cfg.PrimarySource, thirdTestVLESSURI)
	}
	if cfg.BackupSource != nil {
		t.Errorf("BackupSource = %+v, want nil (wizard skipped backup)", cfg.BackupSource)
	}
}

func TestSourceLabel(t *testing.T) {
	cases := []struct{ in, want string }{
		{"vless://11111111-2222-3333-4444-555555555555@ex.com:443?type=tcp#n", "vless://…@ex.com:443"},
		{"https://sub.example.com/abcSECRETtoken", "https://sub.example.com/…"},
		{"https://sub.example.com/", "https://sub.example.com"},
		{"http://host:8080", "http://host:8080"},
		{"not a url", "(источник задан)"},
	}
	for _, c := range cases {
		if got := sourceLabel(c.in); got != c.want {
			t.Errorf("sourceLabel(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTransportIface(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"proxy0 default name", &config.Config{Proxy0: config.Proxy0Config{Enabled: true}}, "Proxy0"},
		{"proxy0 explicit name", &config.Config{Proxy0: config.Proxy0Config{Enabled: true, Interface: "Proxy2"}}, "Proxy2"},
		{"wg transport", &config.Config{WGTransport: config.WGTransportConfig{Enabled: true, Iface: "Wireguard3"}}, "Wireguard3"},
		{
			"wg wins over proxy0",
			&config.Config{
				Proxy0:      config.Proxy0Config{Enabled: true},
				WGTransport: config.WGTransportConfig{Enabled: true, Iface: "Wireguard3"},
			},
			"Wireguard3",
		},
		{"wg enabled but no iface pinned", &config.Config{WGTransport: config.WGTransportConfig{Enabled: true}}, ""},
		{"nothing wired (option 4 / not a router)", &config.Config{}, ""},
	}
	for _, c := range cases {
		if got := transportIface(c.cfg); got != c.want {
			t.Errorf("%s: transportIface = %q, want %q", c.name, got, c.want)
		}
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
