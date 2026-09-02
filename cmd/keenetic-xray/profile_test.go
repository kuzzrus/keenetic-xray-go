package main

import (
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

const testVLESSURI = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#test"

func TestCmdProfile_AddListRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	if err := run([]string{"profile", "add", testVLESSURI}); err != nil {
		t.Fatalf("profile add: %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Remark != "test" {
		t.Fatalf("Profiles = %#v", cfg.Profiles)
	}

	if err := run([]string{"profile", "list"}); err != nil {
		t.Fatalf("profile list: %v", err)
	}

	if err := run([]string{"profile", "remove", "0"}); err != nil {
		t.Fatalf("profile remove: %v", err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatalf("Load after remove: %v", err)
	}
	if len(cfg.Profiles) != 0 {
		t.Fatalf("Profiles after remove = %#v, want empty", cfg.Profiles)
	}
}

func TestCmdProfile_AddRejectsInvalidURI(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"profile", "add", "not-a-vless-link"}); err == nil {
		t.Error("expected error for an invalid vless URI")
	}
}

func TestCmdProfile_RemoveOutOfRange(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(dir, "config.json"))

	if err := run([]string{"profile", "remove", "0"}); err == nil {
		t.Error("expected error removing from an empty profile list")
	}
}

func TestReindexAfterRemoval(t *testing.T) {
	cases := []struct{ current, removed, want int }{
		{-1, 2, -1},
		{2, 2, -1},
		{5, 2, 4},
		{1, 2, 1},
		{0, 2, 0},
	}
	for _, tc := range cases {
		if got := reindexAfterRemoval(tc.current, tc.removed); got != tc.want {
			t.Errorf("reindexAfterRemoval(%d, %d) = %d, want %d", tc.current, tc.removed, got, tc.want)
		}
	}
}

func TestCmdProfile_RemoveReindexesPrimaryBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)

	cfg := config.Default()
	cfg.Profiles = []config.Profile{
		{UUID: "a", Address: "a.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "a"},
		{UUID: "b", Address: "b.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "b"},
		{UUID: "c", Address: "c.example.com", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "c"},
	}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 2
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := run([]string{"profile", "remove", "1"}); err != nil { // remove "b", between primary and backup
		t.Fatalf("profile remove: %v", err)
	}

	got, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.PrimaryIndex != 0 {
		t.Errorf("PrimaryIndex = %d, want 0 (unaffected)", got.PrimaryIndex)
	}
	if got.BackupIndex != 1 {
		t.Errorf("BackupIndex = %d, want 1 (shifted down)", got.BackupIndex)
	}
	if got.Backup().Remark != "c" {
		t.Errorf("Backup().Remark = %q, want \"c\"", got.Backup().Remark)
	}
}
