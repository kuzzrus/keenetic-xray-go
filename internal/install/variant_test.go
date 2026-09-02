package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestDecideVariant(t *testing.T) {
	cases := []struct {
		free, threshold int64
		want            string
	}{
		{10 * 1024 * 1024, 43 * 1024 * 1024, config.VariantMini},
		{42 * 1024 * 1024, 43 * 1024 * 1024, config.VariantMini},
		{43 * 1024 * 1024, 43 * 1024 * 1024, config.VariantFull},
		{100 * 1024 * 1024, 43 * 1024 * 1024, config.VariantFull},
	}
	for _, tc := range cases {
		if got := DecideVariant(tc.free, tc.threshold); got != tc.want {
			t.Errorf("DecideVariant(%d, %d) = %q, want %q", tc.free, tc.threshold, got, tc.want)
		}
	}
}

func TestPostinstSetup_FreshInstall(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		ConfigDir:     filepath.Join(dir, "etc"),
		ConfigFile:    filepath.Join(dir, "etc", "config.json"),
		LibDir:        filepath.Join(dir, "lib"),
		LogDir:        filepath.Join(dir, "log"),
		RunDir:        filepath.Join(dir, "run"),
		DiskCheckPath: dir,
	}

	// A 1-byte threshold should reliably land on Full given real tmpdir free space.
	if err := PostinstSetup(paths, 1); err != nil {
		t.Fatalf("PostinstSetup: %v", err)
	}

	for _, d := range []string{paths.ConfigDir, paths.LibDir, paths.LogDir, paths.RunDir} {
		if info, err := os.Stat(d); err != nil || !info.IsDir() {
			t.Errorf("expected directory %s to exist", d)
		}
	}

	cfg, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Variant != config.VariantFull {
		t.Errorf("Variant = %q, want %q", cfg.Variant, config.VariantFull)
	}
}

func TestPostinstSetup_NeverOverwritesExistingConfig(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		ConfigDir:     filepath.Join(dir, "etc"),
		ConfigFile:    filepath.Join(dir, "etc", "config.json"),
		DiskCheckPath: dir,
	}
	if err := os.MkdirAll(paths.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}

	existing := config.Default()
	existing.Variant = config.VariantMini
	existing.Profiles = []config.Profile{{
		UUID: "u", Address: "a", Port: 443, Network: "tcp", Security: "none", Encryption: "none", Remark: "keep-me",
	}}
	existing.PrimaryIndex = 0
	if err := existing.Save(paths.ConfigFile); err != nil {
		t.Fatal(err)
	}

	// A huge threshold would pick Mini if PostinstSetup actually ran its
	// decision logic -- it must not, since config.json already exists.
	if err := PostinstSetup(paths, 1<<40); err != nil {
		t.Fatalf("PostinstSetup: %v", err)
	}

	got, err := config.Load(paths.ConfigFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Profiles) != 1 || got.Profiles[0].Remark != "keep-me" {
		t.Errorf("existing config was overwritten: %#v", got)
	}
	if got.Variant != config.VariantMini {
		t.Errorf("Variant = %q, want unchanged %q", got.Variant, config.VariantMini)
	}
}

func TestPrermCleanup_NoPurgeLeavesFilesAlone(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := PrermCleanup(Paths{ConfigDir: configDir}, false); err != nil {
		t.Fatalf("PrermCleanup: %v", err)
	}
	if _, err := os.Stat(configDir); err != nil {
		t.Errorf("ConfigDir should still exist without --purge: %v", err)
	}
}

func TestPrermCleanup_PurgeRemoves(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "etc")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := PrermCleanup(Paths{ConfigDir: configDir}, true); err != nil {
		t.Fatalf("PrermCleanup: %v", err)
	}
	if _, err := os.Stat(configDir); !os.IsNotExist(err) {
		t.Errorf("ConfigDir should be removed with --purge, stat err = %v", err)
	}
}
