package config

import (
	"path/filepath"
	"testing"
)

func validProfile() Profile {
	return Profile{
		Remark:     "test",
		UUID:       "11111111-2222-3333-4444-555555555555",
		Address:    "example.com",
		Port:       443,
		Encryption: "none",
		Network:    "tcp",
		Security:   "none",
	}
}

func TestProfileValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *Profile)
		wantErr bool
	}{
		{"valid", func(p *Profile) {}, false},
		{"missing uuid", func(p *Profile) { p.UUID = "" }, true},
		{"missing address", func(p *Profile) { p.Address = "" }, true},
		{"port zero", func(p *Profile) { p.Port = 0 }, true},
		{"port too large", func(p *Profile) { p.Port = 70000 }, true},
		{"bad network", func(p *Profile) { p.Network = "kcp" }, true},
		{"xhttp network valid", func(p *Profile) { p.Network = "xhttp" }, false},
		{"http network valid", func(p *Profile) { p.Network = "http" }, false},
		{"h2 network valid (alias)", func(p *Profile) { p.Network = "h2" }, false},
		{"bad security", func(p *Profile) { p.Security = "aes" }, true},
		{"reality without pbk/sid", func(p *Profile) { p.Security = "reality" }, true},
		{"reality without sni", func(p *Profile) {
			p.Security = "reality"
			p.PublicKey = "pk"
			p.ShortID = "sid"
		}, true},
		{"reality with pbk/sid/sni", func(p *Profile) {
			p.Security = "reality"
			p.PublicKey = "pk"
			p.ShortID = "sid"
			p.SNI = "www.example.com"
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigDefault(t *testing.T) {
	c := Default()
	if c.Variant != VariantFull {
		t.Errorf("Default().Variant = %q, want %q", c.Variant, VariantFull)
	}
	if c.PrimaryIndex != -1 || c.BackupIndex != -1 {
		t.Errorf("Default() indices = (%d, %d), want (-1, -1)", c.PrimaryIndex, c.BackupIndex)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Default() should validate cleanly: %v", err)
	}
	if c.Primary() != nil || c.Backup() != nil {
		t.Errorf("Default() should have no primary/backup profile")
	}
}

func TestConfigLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load of missing file should not error, got: %v", err)
	}
	if c.Variant != VariantFull || len(c.Profiles) != 0 {
		t.Errorf("Load of missing file should return Default(), got %#v", c)
	}
}

func TestConfigSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c := Default()
	c.Profiles = []Profile{validProfile(), validProfile()}
	c.Profiles[1].Remark = "backup"
	c.Profiles[1].Address = "backup.example.com"
	c.PrimaryIndex = 0
	c.BackupIndex = 1
	c.Subscription = &Subscription{URL: "https://sub.example.com/feed"}

	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Variant != c.Variant {
		t.Errorf("Variant = %q, want %q", loaded.Variant, c.Variant)
	}
	if len(loaded.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(loaded.Profiles))
	}
	if loaded.Primary().Address != "example.com" {
		t.Errorf("Primary().Address = %q, want %q", loaded.Primary().Address, "example.com")
	}
	if loaded.Backup().Address != "backup.example.com" {
		t.Errorf("Backup().Address = %q, want %q", loaded.Backup().Address, "backup.example.com")
	}
	if loaded.Subscription == nil || loaded.Subscription.URL != "https://sub.example.com/feed" {
		t.Errorf("Subscription = %#v, want URL https://sub.example.com/feed", loaded.Subscription)
	}
}

func TestConfigSave_RefusesInvalid(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	c.PrimaryIndex = 5 // out of range, no profiles configured
	if err := c.Save(filepath.Join(dir, "config.json")); err == nil {
		t.Error("Save should refuse an invalid config, got nil error")
	}
}

func TestConfigValidate_ProfileIndicesOutOfRange(t *testing.T) {
	c := Default()
	c.Profiles = []Profile{validProfile()}

	c.PrimaryIndex = 1 // only index 0 exists
	if err := c.Validate(); err == nil {
		t.Error("expected error for out-of-range primary_index")
	}

	c.PrimaryIndex = 0
	c.BackupIndex = -2 // below the -1 "unset" sentinel
	if err := c.Validate(); err == nil {
		t.Error("expected error for backup_index below the -1 unset sentinel")
	}
}
