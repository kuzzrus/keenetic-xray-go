package l7capture

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// The points below are the only places this file touches the system --
// injectable, same convention as this package's own iptablesRun/
// iptablesListFORWARD, so the decision logic (skip if already loaded,
// skip if this kernel built it in rather than shipping it as a loadable
// module, surface a genuine insmod failure) is testable without a real
// kernel.
var (
	insmodRun = func(ctx context.Context, path string) error {
		return runLoggedCmd(ctx, "insmod", path)
	}
	unameRelease = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "uname", "-r").Output()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	statFile = func(path string) error {
		_, err := os.Stat(path)
		return err
	}
)

// EnsureNFLOGModule loads the kernel modules NFLOG needs if they aren't
// already active: nfnetlink_log (the core netlink logging subsystem
// Capture's own socket talks to) and xt_NFLOG (the iptables target
// EnsureRules' own rules reference). Mirrors HydraRoute Neo's own
// l7_firewall_load_nflog_modules/module_already_loaded, in the same
// order.
//
// Found live (2026-09-15): EnsureRules failed outright with "iptables:
// No chain/target/match by that name" on a real router until this was
// done -- xt_NFLOG's .ko file was already present on disk
// (/lib/modules/<release>/xt_NFLOG.ko) but never loaded. Unlike ipset/
// conntrack (see internal/adaptiveroute's EnsureIPSetTool, internal/
// keenetic's EnsureConntrackTool, both opkg-install their tool on
// demand), this project's opkg feed doesn't carry a separate
// installable package for either NFLOG module at all -- confirmed live,
// `opkg list | grep -iE "kmod-ipt|kmod-nf|iptables-mod"` came back
// empty. There is nothing to install here, only something to load.
func EnsureNFLOGModule(ctx context.Context) error {
	return ensureNFLOGModule(ctx, "/proc/modules")
}

func ensureNFLOGModule(ctx context.Context, procModulesPath string) error {
	if err := loadKmodIfPresent(ctx, "nfnetlink_log", procModulesPath); err != nil {
		return err
	}
	return loadKmodIfPresent(ctx, "xt_NFLOG", procModulesPath)
}

// loadKmodIfPresent insmods name.ko for the running kernel unless it's
// already loaded (checked via procModulesPath -- insmod on an already-
// loaded module errors, which would otherwise make every daemon
// restart after the first print a confusing failure) or has no .ko
// file at the expected path for this kernel at all. The latter isn't
// treated as an error: confirmed live that at least one of these two
// modules can be built directly into a given router's kernel rather
// than shipped as a loadable module, and there's nothing to load in
// that case, not a problem to report.
func loadKmodIfPresent(ctx context.Context, name, procModulesPath string) error {
	if kmodLoaded(name, procModulesPath) {
		return nil
	}
	release, err := unameRelease(ctx)
	if err != nil {
		return fmt.Errorf("l7capture: kernel release: %w", err)
	}
	path := fmt.Sprintf("/lib/modules/%s/%s.ko", release, name)
	if err := statFile(path); err != nil {
		return nil
	}
	if err := insmodRun(ctx, path); err != nil {
		return fmt.Errorf("l7capture: loading %s (%s): %w", name, path, err)
	}
	return nil
}

// kmodLoaded reports whether name appears in the given /proc/modules-
// shaped file -- one module per line, name first. An unreadable file
// (shouldn't happen for the real /proc/modules on a real Linux kernel)
// is treated as "not loaded", same fail-open reasoning as the rest of
// this best-effort check: worst case, this attempts an insmod that then
// errors with a clear "File exists", rather than silently skipping a
// module that genuinely isn't loaded.
func kmodLoaded(name, procModulesPath string) bool {
	data, err := os.ReadFile(procModulesPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == name || strings.HasPrefix(line, name+" ") {
			return true
		}
	}
	return false
}
