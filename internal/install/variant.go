// Package install holds the logic behind the .ipk's postinst/prerm
// scripts: creating the runtime directory layout, choosing Mini vs Full,
// and writing an initial config.json without ever clobbering one that
// already exists (the upgrade case).
package install

import (
	"fmt"
	"os"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// VariantEnv is the environment variable install.sh sets from its
// `--mini` flag. Anything other than "mini" (case-insensitive), or
// unset, means Full -- Full is the default and the only variant that was
// ever meaningfully different is a small log/history retention cap.
const VariantEnv = "KEENETIC_XRAY_VARIANT"

// VariantFromEnv returns the variant a fresh install should get: Mini
// only when explicitly asked for, Full otherwise.
func VariantFromEnv() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(VariantEnv)), config.VariantMini) {
		return config.VariantMini
	}
	return config.VariantFull
}

// Paths are the directories/files postinst and prerm operate on.
type Paths struct {
	ConfigDir  string // e.g. /opt/etc/keenetic-xray
	ConfigFile string // e.g. /opt/etc/keenetic-xray/config.json
	LibDir     string // e.g. /opt/var/lib/keenetic-xray
	LogDir     string // e.g. /opt/var/log/keenetic-xray
	RunDir     string // e.g. /opt/var/run
}

// PostinstSetup creates the runtime directory layout and, only if no
// config.json exists yet, writes a fresh skeleton config with the
// chosen variant (Full unless KEENETIC_XRAY_VARIANT=mini). An existing
// config.json (the upgrade case) is left completely untouched.
func PostinstSetup(paths Paths) error {
	for _, dir := range []string{paths.ConfigDir, paths.LibDir, paths.LogDir, paths.RunDir} {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}

	if _, err := os.Stat(paths.ConfigFile); err == nil {
		return nil // upgrade: config.json already exists, never overwrite
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking %s: %w", paths.ConfigFile, err)
	}

	cfg := config.Default()
	cfg.Variant = VariantFromEnv()
	if err := cfg.Save(paths.ConfigFile); err != nil {
		return fmt.Errorf("writing initial config: %w", err)
	}
	return nil
}

// PrermCleanup is invoked by the ipk's prerm script. By design it never
// deletes state on a normal remove/upgrade -- opkg's postinst/prerm
// upgrade-vs-remove argument convention isn't reliably documented, unlike
// dpkg's, so this design sidesteps needing to rely on it. A full wipe is
// only ever the explicit --purge path (purge=true).
func PrermCleanup(paths Paths, purge bool) error {
	if !purge {
		return nil
	}
	for _, dir := range []string{paths.ConfigDir, paths.LibDir, paths.LogDir} {
		if dir == "" {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("removing %s: %w", dir, err)
		}
	}
	return nil
}
