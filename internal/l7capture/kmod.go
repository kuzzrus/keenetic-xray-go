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

// requiredKmods is loaded, in order, by EnsureNFLOGModule: nfnetlink_log
// (the core netlink logging subsystem Capture's own socket talks to),
// then every iptables extension the rules EnsureRules installs actually
// reference -- xt_NFLOG (the NFLOG target itself) and xt_connbytes/
// xt_length (the `-m connbytes`/`-m length` matches ruleSpecs' own doc
// comment explains are what keep this cheap enough to run on embedded
// hardware in the first place).
//
// Found live (2026-09-15): loading only nfnetlink_log+xt_NFLOG wasn't
// enough -- EnsureRules still failed with the same generic "iptables:
// No chain/target/match by that name" iptables gives for ANY missing
// match or target, not only a missing NFLOG target specifically. The
// manual test that first confirmed xt_NFLOG.ko loads and works
// (`iptables -A FORWARD -j NFLOG --nflog-group N`, no other flags) had
// no `-m connbytes`/`-m length` in it, so it never actually exercised
// those two modules at all -- both turned out to have the exact same
// "present on disk, never loaded, no opkg package for it" situation
// already confirmed for xt_NFLOG.
var requiredKmods = []string{"nfnetlink_log", "xt_NFLOG", "xt_connbytes", "xt_length"}

// EnsureNFLOGModule loads every kernel module in requiredKmods that
// isn't already active. Mirrors HydraRoute Neo's own
// l7_firewall_load_nflog_modules/module_already_loaded. Unlike ipset/
// conntrack (see internal/adaptiveroute's EnsureIPSetTool, internal/
// keenetic's EnsureConntrackTool, both opkg-install their tool on
// demand), this project's opkg feed doesn't carry a separate
// installable package for any of these -- confirmed live, `opkg list |
// grep -iE "kmod-ipt|kmod-nf|iptables-mod"` came back empty. There is
// nothing to install here, only something to load.
func EnsureNFLOGModule(ctx context.Context) error {
	return ensureNFLOGModule(ctx, "/proc/modules")
}

func ensureNFLOGModule(ctx context.Context, procModulesPath string) error {
	for _, name := range requiredKmods {
		if err := loadKmodIfPresent(ctx, name, procModulesPath); err != nil {
			return err
		}
	}
	return nil
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
