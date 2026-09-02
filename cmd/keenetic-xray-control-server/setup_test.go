package main

import (
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

	// token / chat IDs / router count / router id / listen addr (blank = default)
	in := strings.NewReader("111222333:AA_this_is_a_pretend_bot_token_value_00\n111, 222\n2\nhome-router\noffice-router\n\n")
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
	if len(s.Routers) != 2 {
		t.Fatalf("Routers = %v, want 2 entries", s.Routers)
	}
	for _, id := range []string{"home-router", "office-router"} {
		if len(s.Routers[id]) != 64 { // hex-encoded 32 bytes
			t.Errorf("Routers[%q] = %q, want a 64-hex-char token", id, s.Routers[id])
		}
	}
	if s.Routers["home-router"] == s.Routers["office-router"] {
		t.Error("both routers got the same token")
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
	for _, want := range []string{"SHA-256", "keenetic-xray agent configure https://<this-server-host>:8443 home-router", "office-router"} {
		if !strings.Contains(got, want) {
			t.Errorf("wizard output missing %q\n---\n%s", want, got)
		}
	}
}

func TestRunSetup_RejectsBadChatIDsThenRecovers(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	in := strings.NewReader("123:token_token_token_token_token_token\nnope\n42\n1\nr1\n\n")
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

	in := strings.NewReader("y\n999:brand_new_token_brand_new_token_brand\n7\n1\nr1\n\n")
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
