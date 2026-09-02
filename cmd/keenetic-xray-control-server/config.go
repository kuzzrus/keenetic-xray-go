package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// settings is the control server's own on-disk configuration. It has
// nothing to do with the router-side internal/config package -- this
// binary never runs on a router, and its shape (listen address, TLS
// material paths, Telegram token, per-router tokens) is entirely
// different. Kept in one file, expected at 0600, since most of its
// fields are secrets.
type settings struct {
	ListenAddr     string            `json:"listen_addr"`
	CertPath       string            `json:"cert_path"`
	KeyPath        string            `json:"key_path"`
	QueuePath      string            `json:"queue_path"`
	TelegramToken  string            `json:"telegram_token"`
	AllowedChatIDs []int64           `json:"allowed_chat_ids"`
	Routers        map[string]string `json:"routers"` // router ID -> bearer token
}

func defaultSettings() settings {
	return settings{
		ListenAddr: ":8443",
		CertPath:   "/etc/keenetic-xray-control-server/server.crt",
		KeyPath:    "/etc/keenetic-xray-control-server/server.key",
		QueuePath:  "/var/lib/keenetic-xray-control-server/queue.json",
		Routers:    map[string]string{},
	}
}

// loadSettings reads and validates path. Unlike the router's
// config.Load, a missing or incomplete file is a hard error here -- there
// is no sensible "not configured yet" mode for a Telegram bot with no
// token or chat allowlist, so failing fast with a clear message beats
// starting up into a useless, half-configured state.
func loadSettings(path string) (settings, error) {
	s := defaultSettings()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return settings{}, fmt.Errorf("config file %s does not exist -- see docs/bot-control-design.md for the expected format", path)
	}
	if err != nil {
		return settings{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if info, statErr := os.Stat(path); statErr == nil && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "keenetic-xray-control-server: warning: %s is mode %04o (group/other can read it); it holds the Telegram token and per-router secrets -- run: chmod 600 %s\n", path, info.Mode().Perm(), path)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return settings{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.TelegramToken == "" {
		return settings{}, fmt.Errorf("telegram_token is required in %s", path)
	}
	if len(s.AllowedChatIDs) == 0 {
		return settings{}, fmt.Errorf("allowed_chat_ids must list at least one chat ID in %s", path)
	}
	if len(s.Routers) == 0 {
		return settings{}, fmt.Errorf("routers must list at least one router ID -> token pair in %s", path)
	}
	return s, nil
}
