package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestWriteDiag_SectionsAndRedaction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	t.Setenv("KEENETIC_XRAY_OPT", dir)

	cfg := config.Default()
	cfg.Profiles = []config.Profile{{
		Remark: "s1", UUID: "SECRET-UUID-abcdef", Address: "vpn.example.com",
		Port: 443, Network: "tcp", Security: "none", Encryption: "none",
	}}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 0
	cfg.Subscription = &config.Subscription{URL: "https://sub.example/T0K3N"}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	writeDiag(&b)
	out := b.String()

	for _, want := range []string{
		"==== keenetic-xray diag",
		"---- config (secrets redacted) ----",
		"---- local resolvers ----",
		"---- addons ----",
		"---- rci ----",
		"---- keenetic ----",
		"---- daemon log",
		"==== end ====",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diag output missing section %q", want)
		}
	}
	if strings.Contains(out, "SECRET-UUID-abcdef") {
		t.Error("diag leaked the profile UUID")
	}
	if strings.Contains(out, "T0K3N") {
		t.Error("diag leaked the subscription token")
	}
	if !strings.Contains(out, "<redacted>") {
		t.Error("diag config section has no redaction markers")
	}
	if !strings.Contains(out, "vpn.example.com") {
		t.Error("diag dropped the (non-secret) server address")
	}
}
