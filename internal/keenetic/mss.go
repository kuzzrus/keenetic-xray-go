package keenetic

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// mssComment tags the one mangle rule this project manages, so it can be
// found and replaced idempotently and removed cleanly -- same idea as
// the watchdog cron marker and the Proxy0 interface description.
const mssComment = "keenetic-xray-mss"

// The four points below are the only places the MSS helpers touch the
// system -- injectable (same convention as ndmcRun) so the rule-shaping
// logic is testable without a real iptables.
var (
	iptablesRun = func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "iptables", args...).Run()
	}
	iptablesListForward = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "iptables", "-t", "mangle", "-S", "FORWARD").Output()
		return string(out), err
	}
	iptablesPresent     = func() bool { return exec.Command("iptables", "-V").Run() == nil }
	opkgInstallIptables = func(ctx context.Context) error {
		return exec.CommandContext(ctx, "opkg", "install", "iptables").Run()
	}
)

// IptablesPresent reports whether `iptables` is runnable right now (no
// install attempt). Handy for telling the operator when a call had to
// pull the package in.
func IptablesPresent() bool { return iptablesPresent() }

// EnsureIptables makes sure `iptables` is runnable, installing the
// Entware package if not. Best-effort: callers treat a failure as "skip
// MSS clamping", not fatal.
func EnsureIptables(ctx context.Context) error {
	if iptablesPresent() {
		return nil
	}
	if err := opkgInstallIptables(ctx); err != nil {
		return fmt.Errorf("installing iptables via opkg: %w", err)
	}
	if !iptablesPresent() {
		return fmt.Errorf("iptables still not runnable after opkg install")
	}
	return nil
}

// mssRuleSpec is the mangle FORWARD rule minus the -A/-D verb: clamp the
// MSS of every forwarded TCP SYN to mss.
func mssRuleSpec(mss int) []string {
	return []string{
		"-t", "mangle", "FORWARD",
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-m", "comment", "--comment", mssComment,
		"-j", "TCPMSS", "--set-mss", strconv.Itoa(mss),
	}
}

// SetMSSClamp installs this project's one MSS-clamp rule at mss, removing
// any stale copy of ours first (e.g. a different value). mss < 1 clears.
func SetMSSClamp(ctx context.Context, mss int) error {
	if mss < 1 {
		return ClearMSSClamp(ctx)
	}
	clearOurRules(ctx)
	if err := iptablesRun(ctx, append([]string{"-A"}, mssRuleSpec(mss)...)...); err != nil {
		return fmt.Errorf("adding MSS-clamp rule (--set-mss %d): %w", mss, err)
	}
	return nil
}

// MSSClampInPlace reports whether our FORWARD mangle rule for exactly
// this mss is live right now. The daemon polls this to catch the router
// firmware flushing the rule on a reconfig event (interface up/down, a
// policy edit, a schedule) -- which is what makes the stalls "come back
// after a while".
func MSSClampInPlace(ctx context.Context, mss int) bool {
	out, err := iptablesListForward(ctx)
	if err != nil {
		return false
	}
	want := "--set-mss " + strconv.Itoa(mss)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "-A FORWARD ") && strings.Contains(line, mssComment) && strings.Contains(line, want) {
			return true
		}
	}
	return false
}

// ClearMSSClamp removes this project's MSS-clamp rule(s). A no-op when
// none exist or iptables isn't installed.
func ClearMSSClamp(ctx context.Context) error {
	if !iptablesPresent() {
		return nil
	}
	clearOurRules(ctx)
	return nil
}

// clearOurRules deletes every FORWARD mangle rule carrying our comment,
// reading the live spec back with `-S` so the -D matches exactly
// whatever --set-mss value is there.
func clearOurRules(ctx context.Context) {
	out, err := iptablesListForward(ctx)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") || !strings.Contains(line, mssComment) {
			continue
		}
		spec := strings.Fields(strings.TrimPrefix(line, "-A "))
		_ = iptablesRun(ctx, append([]string{"-t", "mangle", "-D"}, spec...)...)
	}
}
