package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

func TestNotifyIfUpdated_FirstRunIsSilent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last_version.txt")
	notified := false
	if err := notifyIfUpdated(path, func(string) { notified = true }); err != nil {
		t.Fatalf("notifyIfUpdated: %v", err)
	}
	if notified {
		t.Error("expected no notification on a first-ever run (no prior version recorded)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected the version file to be written: %v", err)
	}
	if string(data) != version.String() {
		t.Errorf("version file = %q, want %q", data, version.String())
	}
}

func TestNotifyIfUpdated_UnchangedVersionIsSilent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last_version.txt")
	if err := os.WriteFile(path, []byte(version.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	notified := false
	if err := notifyIfUpdated(path, func(string) { notified = true }); err != nil {
		t.Fatalf("notifyIfUpdated: %v", err)
	}
	if notified {
		t.Error("expected no notification when the version hasn't changed -- a plain restart, not an update")
	}
}

func TestNotifyIfUpdated_ChangedVersionNotifiesAndUpdatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last_version.txt")
	if err := os.WriteFile(path, []byte("0.0.1-previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := notifyIfUpdated(path, func(s string) { got = s }); err != nil {
		t.Fatalf("notifyIfUpdated: %v", err)
	}
	if got == "" {
		t.Fatal("expected a notification when the recorded version differs from the running one")
	}
	if !strings.Contains(got, "0.0.1-previous") || !strings.Contains(got, version.String()) {
		t.Errorf("notification = %q, want it to mention both the old and new version", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != version.String() {
		t.Errorf("version file after notifying = %q, want it updated to %q", data, version.String())
	}
}
