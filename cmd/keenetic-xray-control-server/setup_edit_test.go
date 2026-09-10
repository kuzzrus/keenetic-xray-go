package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func configuredSettings(dir string) settings {
	s := testDefaults(dir)
	s.TelegramToken = "111222333:AA_this_is_a_pretend_bot_token_value_00"
	s.AllowedChatIDs = []int64{111, 222}
	s.PublicURL = "https://old.example.com:8443"
	return s
}

func runEdit(t *testing.T, dir string, s settings, script string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "config.json")
	if err := s.save(cfgPath); err != nil {
		t.Fatalf("seeding config: %v", err)
	}
	var out strings.Builder
	if err := runSetupEdit(bufio.NewReader(strings.NewReader(script)), &out, cfgPath, s); err != nil {
		t.Fatalf("runSetupEdit: %v", err)
	}
	return out.String()
}

func TestRunSetupEdit_HeaderShowsCurrentSettingsWithoutTheTokenItself(t *testing.T) {
	dir := t.TempDir()
	s := configuredSettings(dir)
	out := runEdit(t, dir, s, "\n") // Enter -> quit immediately

	if !strings.Contains(out, "1) Telegram-токен       задан") {
		t.Errorf("header should say the token is set, not print it:\n%s", out)
	}
	if strings.Contains(out, s.TelegramToken) {
		t.Errorf("the raw token must never appear in editor output:\n%s", out)
	}
	if !strings.Contains(out, "111, 222") {
		t.Errorf("header missing chat IDs:\n%s", out)
	}
	if !strings.Contains(out, "https://old.example.com:8443") {
		t.Errorf("header missing current PublicURL:\n%s", out)
	}
	if !strings.Contains(out, "без изменений") {
		t.Errorf("quitting with no edits should say so:\n%s", out)
	}
}

func TestRunSetupEdit_UnknownChoiceReprompts(t *testing.T) {
	dir := t.TempDir()
	s := configuredSettings(dir)
	out := runEdit(t, dir, s, "9\n\n")
	if !strings.Contains(out, "нет такого пункта") {
		t.Errorf("expected a re-prompt for an invalid choice:\n%s", out)
	}
}

func TestRunSetupEdit_ChangeChatIDs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	out := runEdit(t, dir, s, "2\n7, 8, 9\n\n")

	if !strings.Contains(out, "chat ID обновлены") {
		t.Errorf("expected a confirmation:\n%s", out)
	}
	if !strings.Contains(out, "перезапустить сервис") {
		t.Errorf("a real change should remind the operator to restart:\n%s", out)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if len(got.AllowedChatIDs) != 3 || got.AllowedChatIDs[0] != 7 || got.AllowedChatIDs[2] != 9 {
		t.Errorf("AllowedChatIDs = %v, want [7 8 9]", got.AllowedChatIDs)
	}
	// Untouched fields survive the edit.
	if got.TelegramToken != s.TelegramToken {
		t.Errorf("TelegramToken changed unexpectedly: %q", got.TelegramToken)
	}
}

func TestRunSetupEdit_ChangeListenAddrKeepsDomainPublicURLInSync(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	s.Domain = "vps.example.com"
	s.PublicURL = "https://vps.example.com:8443"
	old := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.1"}, nil }
	defer func() { lookupHost = old }()

	out := runEdit(t, dir, s, "3\n:9443\n\n")
	if !strings.Contains(out, "адрес прослушивания: :9443") {
		t.Errorf("expected a confirmation:\n%s", out)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.ListenAddr != ":9443" {
		t.Errorf("ListenAddr = %q, want :9443", got.ListenAddr)
	}
	if got.PublicURL != "https://vps.example.com:9443" {
		t.Errorf("PublicURL = %q, want the domain re-derived with the new port", got.PublicURL)
	}
}

func TestRunSetupEdit_ChangeListenAddrNoOpWhenBlankOrSame(t *testing.T) {
	dir := t.TempDir()
	s := configuredSettings(dir)
	out := runEdit(t, dir, s, "3\n\n\n") // blank keeps the default -> no-op
	if !strings.Contains(out, "без изменений") {
		t.Errorf("blank input should be a no-op:\n%s", out)
	}
}

func TestRunSetupEdit_TurnOnDomain(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	old := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.1"}, nil }
	defer func() { lookupHost = old }()

	// item 4 / blank (keep current PublicURL prompt default) / yes domain / the domain itself
	out := runEdit(t, dir, s, "4\n\ny\nnew.example.com\n\n")
	if !strings.Contains(out, "Let's Encrypt") {
		t.Errorf("expected the Let's Encrypt note on turning a domain on:\n%s", out)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.Domain != "new.example.com" {
		t.Errorf("Domain = %q, want new.example.com", got.Domain)
	}
	if got.PublicURL != "https://new.example.com:8443" {
		t.Errorf("PublicURL = %q, want derived from the new domain", got.PublicURL)
	}
	if got.AutocertCacheDir == "" {
		t.Error("AutocertCacheDir should default, not stay empty")
	}
}

func TestRunSetupEdit_TurnOffDomain(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	s.Domain = "vps.example.com"
	s.PublicURL = "https://vps.example.com:8443"

	// item 4 / new plain public URL / no domain
	out := runEdit(t, dir, s, "4\nhttps://1.2.3.4:8443\nn\n\n")
	if !strings.Contains(out, "без домена") {
		t.Errorf("expected the no-domain confirmation:\n%s", out)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.Domain != "" {
		t.Errorf("Domain = %q, want cleared", got.Domain)
	}
	if got.PublicURL != "https://1.2.3.4:8443" {
		t.Errorf("PublicURL = %q, want the freshly typed value", got.PublicURL)
	}
}

func TestRunSetupEdit_WizardEscapeHatchRunsFullWizard(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	if err := s.save(cfgPath); err != nil {
		t.Fatal(err)
	}
	// "w" from the editor, then a full first-run wizard script (which
	// will ask to overwrite since the file already exists).
	script := "w\ny\n999:brand_new_token_brand_new_token_brand\n5\n\n\nn\n"
	var out strings.Builder
	if err := runSetupEdit(bufio.NewReader(strings.NewReader(script)), &out, cfgPath, s); err != nil {
		t.Fatalf("runSetupEdit: %v", err)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.TelegramToken != "999:brand_new_token_brand_new_token_brand" {
		t.Errorf("TelegramToken = %q, want the wizard's new value -- \"w\" should have handed off to the full wizard", got.TelegramToken)
	}
}

func TestCmdSetup_ExistingConfigGoesToEditorNotWizard(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	if err := s.save(cfgPath); err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	go func() {
		w.WriteString("\n") // Enter -> quit the editor immediately
		w.Close()
	}()

	if err := cmdSetup(cfgPath, nil); err != nil {
		t.Fatalf("cmdSetup: %v", err)
	}
	// If this had gone to the full wizard instead, the single blank
	// line above would have been consumed as (at best) an empty
	// Telegram token, which askNonEmpty rejects and then blocks -- the
	// pipe would be closed with more required prompts unanswered, and
	// runSetup would come back with a "reading input" error. Reaching
	// here at all, with the config unchanged, is the proof this took
	// the editor path.
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.TelegramToken != s.TelegramToken {
		t.Errorf("config should be untouched by a no-op editor session: TelegramToken = %q", got.TelegramToken)
	}
}

func TestCmdSetup_WizardFlagForcesFullWizardEvenWithExistingConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	s := configuredSettings(dir)
	if err := s.save(cfgPath); err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	go func() {
		w.WriteString("y\n555:forced_wizard_token_forced_wizard_token\n3\n\n\nn\n")
		w.Close()
	}()

	if err := cmdSetup(cfgPath, []string{"--wizard"}); err != nil {
		t.Fatalf("cmdSetup: %v", err)
	}
	got, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if got.TelegramToken != "555:forced_wizard_token_forced_wizard_token" {
		t.Errorf("TelegramToken = %q, want the wizard's value -- --wizard should skip the editor", got.TelegramToken)
	}
}
