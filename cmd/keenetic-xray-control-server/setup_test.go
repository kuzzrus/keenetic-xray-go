package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testDefaults returns defaultSettings with the TLS/queue paths pointed
// into dir so runSetup's cert generation doesn't touch /etc or /var.
func testDefaults(dir string) settings {
	s := defaultSettings()
	s.CertPath = filepath.Join(dir, "server.crt")
	s.KeyPath = filepath.Join(dir, "server.key")
	s.QueuePath = filepath.Join(dir, "queue.json")
	return s
}

func TestRunSetup_WritesValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// bot token / chat IDs / listen addr (blank = default) / public URL / has domain?
	in := strings.NewReader("111222333:AA_this_is_a_pretend_bot_token_value_00\n111, 222\n\nhttps://vps.example.com:8443\nn\n")
	var out strings.Builder

	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	s, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings on the written file: %v", err)
	}
	if s.TelegramToken != "111222333:AA_this_is_a_pretend_bot_token_value_00" {
		t.Errorf("TelegramToken = %q", s.TelegramToken)
	}
	if len(s.AllowedChatIDs) != 2 || s.AllowedChatIDs[0] != 111 || s.AllowedChatIDs[1] != 222 {
		t.Errorf("AllowedChatIDs = %v, want [111 222]", s.AllowedChatIDs)
	}
	if s.PublicURL != "https://vps.example.com:8443" {
		t.Errorf("PublicURL = %q", s.PublicURL)
	}
	if len(s.Routers) != 0 {
		t.Errorf("Routers = %v, want none (registered at runtime now)", s.Routers)
	}
	if s.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want default :8443", s.ListenAddr)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("config file mode = %o, want 0600", perm)
		}
	}

	if _, err := os.Stat(filepath.Join(dir, "server.crt")); err != nil {
		t.Errorf("certificate not generated: %v", err)
	}
	got := out.String()
	for _, want := range []string{"SHA-256", "/add_router"} {
		if !strings.Contains(got, want) {
			t.Errorf("wizard output missing %q\n---\n%s", want, got)
		}
	}
}

func TestRunSetup_RejectsBadChatIDsThenRecovers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	in := strings.NewReader("123:token_token_token_token_token_token\nnope\n42\n\n\nn\n")
	var out strings.Builder

	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}
	s, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if len(s.AllowedChatIDs) != 1 || s.AllowedChatIDs[0] != 42 {
		t.Errorf("AllowedChatIDs = %v, want [42] (after re-prompt)", s.AllowedChatIDs)
	}
	if !strings.Contains(out.String(), "попробуйте ещё раз") {
		t.Errorf("expected a re-prompt message, got:\n%s", out.String())
	}
}

func TestRunSetup_AbortsOnExistingConfigWithoutConfirm(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"telegram_token":"keep"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	in := strings.NewReader("n\n")
	var out strings.Builder
	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err == nil {
		t.Fatal("expected runSetup to abort when the operator declines the overwrite")
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "keep") {
		t.Errorf("existing config was modified: %s", data)
	}
}

func TestRunSetup_OverwritesExistingConfigOnConfirm(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"telegram_token":"old"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	in := strings.NewReader("y\n999:brand_new_token_brand_new_token_brand\n7\n\n\nn\n")
	var out strings.Builder
	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}
	s, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if s.TelegramToken != "999:brand_new_token_brand_new_token_brand" {
		t.Errorf("TelegramToken = %q, want the new value", s.TelegramToken)
	}
}

func TestRunSetup_TruncatedInputErrors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	in := strings.NewReader("123:token_token_token_token_token_token\n") // EOF before chat IDs answered
	var out strings.Builder
	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err == nil {
		t.Fatal("expected an error when stdin ends mid-wizard")
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("config.json should not have been written on a failed run")
	}
}

func TestRunSetup_DomainStepSetsFieldsAndDerivesPublicURL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	old := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.1"}, nil }
	defer func() { lookupHost = old }()

	// token / chat IDs / listen addr (blank) / public URL (blank, derived
	// from domain instead) / has domain? / domain
	in := strings.NewReader("123:token_token_token_token_token_token\n42\n\n\ny\nvps.example.com\n")
	var out strings.Builder
	if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err != nil {
		t.Fatalf("runSetup: %v", err)
	}

	s, err := loadSettings(cfgPath)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if s.Domain != "vps.example.com" {
		t.Errorf("Domain = %q, want vps.example.com", s.Domain)
	}
	if s.PublicURL != "https://vps.example.com:8443" {
		t.Errorf("PublicURL = %q, want derived from domain + default port", s.PublicURL)
	}
	if s.AutocertCacheDir == "" {
		t.Error("AutocertCacheDir should default, not stay empty")
	}
	for _, want := range []string{"Let's Encrypt", "БЕЗ отпечатка"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("wizard output missing %q\n---\n%s", want, out.String())
		}
	}
}

func TestRunSetup_DomainNotResolvingAsksToContinue(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	old := lookupHost
	lookupHost = func(string) ([]string, error) { return nil, errors.New("no such host") }
	defer func() { lookupHost = old }()

	t.Run("declines -> aborts", func(t *testing.T) {
		in := strings.NewReader("123:token_token_token_token_token_token\n42\n\n\ny\nnew.example.com\nn\n")
		var out strings.Builder
		if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err == nil {
			t.Fatal("expected runSetup to abort when the operator declines to continue on a non-resolving domain")
		}
		if _, err := os.Stat(cfgPath); err == nil {
			t.Error("config.json should not have been written")
		}
	})

	t.Run("confirms -> proceeds anyway", func(t *testing.T) {
		in := strings.NewReader("123:token_token_token_token_token_token\n42\n\n\ny\nnew.example.com\ny\n")
		var out strings.Builder
		if err := runSetup(in, &out, cfgPath, testDefaults(dir)); err != nil {
			t.Fatalf("runSetup: %v", err)
		}
		s, err := loadSettings(cfgPath)
		if err != nil {
			t.Fatalf("loadSettings: %v", err)
		}
		if s.Domain != "new.example.com" {
			t.Errorf("Domain = %q, want new.example.com", s.Domain)
		}
	})
}

func TestLooksLikeTelegramToken(t *testing.T) {
	yes := []string{"123456789:AAE1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q", "1:0123456789012345678901234567890123"}
	no := []string{"", "no-colon-here", "123456789", ":onlyrest", "abc:def", "123:short"}
	for _, s := range yes {
		if !looksLikeTelegramToken(s) {
			t.Errorf("looksLikeTelegramToken(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeTelegramToken(s) {
			t.Errorf("looksLikeTelegramToken(%q) = true, want false", s)
		}
	}
}
