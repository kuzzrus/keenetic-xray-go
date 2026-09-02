// Package install holds the logic behind the .ipk's postinst/prerm
// scripts: creating the runtime directory layout, deciding Mini vs Full,
// and writing an initial config.json without ever clobbering one that
// already exists (the upgrade case).
package install

import (
	"fmt"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
)

// DefaultMiniThresholdBytes is the free-space cutoff below which a fresh
// install gets the Mini variant instead of Full. Measured at postinst
// time, after opkg has already unpacked the xray-core dependency (that's
// what Depends: guarantees), so this reading already nets out xray-core's
// own footprint for free -- no subtraction needed.
const DefaultMiniThresholdBytes = 43 * 1024 * 1024

// DecideVariant picks Mini or Full based on free space at the point
// postinst runs.
func DecideVariant(freeBytes, thresholdBytes int64) string {
	if freeBytes < thresholdBytes {
		return config.VariantMini
	}
	return config.VariantFull
}

// Paths are the directories/files postinst and prerm operate on.
type Paths struct {
	ConfigDir     string // e.g. /opt/etc/keenetic-xray
	ConfigFile    string // e.g. /opt/etc/keenetic-xray/config.json
	LibDir        string // e.g. /opt/var/lib/keenetic-xray
	LogDir        string // e.g. /opt/var/log/keenetic-xray
	RunDir        string // e.g. /opt/var/run
	DiskCheckPath string // e.g. /opt -- where free space is measured
}

// PostinstSetup creates the runtime directory layout and, only if no
// config.json exists yet, decides Mini/Full from free space and writes a
// fresh skeleton config. An existing config.json (the upgrade case) is
// left completely untouched.
func PostinstSetup(paths Paths, thresholdBytes int64) error {
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

	free, err := diskspace.FreeBytes(paths.DiskCheckPath)
	if err != nil {
		return fmt.Errorf("checking free disk space: %w", err)
	}

	cfg := config.Default()
	cfg.Variant = DecideVariant(free, thresholdBytes)
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
