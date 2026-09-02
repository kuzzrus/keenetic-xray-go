package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing test config: %v", err)
	}
	return path
}

func TestLoadSettings_MissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	if _, err := loadSettings(path); err == nil {
		t.Error("expected error for a missing config file")
	}
}

func TestLoadSettings_MissingTelegramToken(t *testing.T) {
	path := writeConfig(t, `{"allowed_chat_ids":[1],"routers":{"r1":"t1"}}`)
	if _, err := loadSettings(path); err == nil {
		t.Error("expected error when telegram_token is missing")
	}
}

func TestLoadSettings_MissingAllowedChats(t *testing.T) {
	path := writeConfig(t, `{"telegram_token":"x","routers":{"r1":"t1"}}`)
	if _, err := loadSettings(path); err == nil {
		t.Error("expected error when allowed_chat_ids is empty")
	}
}

func TestLoadSettings_RoutersOptional(t *testing.T) {
	// Routers are registered at runtime through the bot, so a config
	// without a `routers` block is valid.
	path := writeConfig(t, `{"telegram_token":"x","allowed_chat_ids":[1]}`)
	s, err := loadSettings(path)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if len(s.Routers) != 0 {
		t.Errorf("Routers = %v, want empty", s.Routers)
	}
}

func TestLoadSettings_ValidConfigAppliesDefaults(t *testing.T) {
	path := writeConfig(t, `{"telegram_token":"x","allowed_chat_ids":[123],"routers":{"r1":"t1"}}`)
	s, err := loadSettings(path)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if s.ListenAddr != ":8443" {
		t.Errorf("ListenAddr = %q, want default \":8443\"", s.ListenAddr)
	}
	if s.CertPath == "" || s.KeyPath == "" || s.QueuePath == "" {
		t.Errorf("expected default paths to be populated, got %+v", s)
	}
	if len(s.AllowedChatIDs) != 1 || s.AllowedChatIDs[0] != 123 {
		t.Errorf("AllowedChatIDs = %v, want [123]", s.AllowedChatIDs)
	}
	if s.Routers["r1"] != "t1" {
		t.Errorf("Routers[r1] = %q, want t1", s.Routers["r1"])
	}
}

func TestLoadSettings_OverridesDefaults(t *testing.T) {
	path := writeConfig(t, `{"listen_addr":":9999","telegram_token":"x","allowed_chat_ids":[1],"routers":{"r1":"t1"}}`)
	s, err := loadSettings(path)
	if err != nil {
		t.Fatalf("loadSettings: %v", err)
	}
	if s.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q, want \":9999\" (explicit value should override the default)", s.ListenAddr)
	}
}

func TestLoadSettings_InvalidJSON(t *testing.T) {
	path := writeConfig(t, `{not valid json`)
	if _, err := loadSettings(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
