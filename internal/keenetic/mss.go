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

// mssMatch is the match+target half of our rule -- everything that comes
// *after* `-t mangle -A FORWARD`: clamp the MSS of every forwarded TCP
// SYN to mss. withComment tags it so it's trivial to find again, but the
// `comment` match module isn't on every iptables build, so SetMSSClamp
// retries without it.
func mssMatch(mss int, withComment bool) []string {
	m := []string{"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"}
	if withComment {
		m = append(m, "-m", "comment", "--comment", mssComment)
	}
	return append(m, "-j", "TCPMSS", "--set-mss", strconv.Itoa(mss))
}

// SetMSSClamp installs this project's one MSS-clamp rule at mss, removing
// any stale copy of ours first (e.g. a different value). mss < 1 clears.
func SetMSSClamp(ctx context.Context, mss int) error {
	if mss < 1 {
		return ClearMSSClamp(ctx)
	}
	clearOurRules(ctx)
	// `-t mangle` and the `-A FORWARD` verb+chain must lead; the match
	// follows. (Getting this order wrong is an iptables "exit status 2".)
	add := func(withComment bool) error {
		args := append([]string{"-t", "mangle", "-A", "FORWARD"}, mssMatch(mss, withComment)...)
		return iptablesRun(ctx, args...)
	}
	if add(true) == nil {
		return nil
	}
	if err := add(false); err != nil {
		return fmt.Errorf("adding MSS-clamp rule (--set-mss %d): %w", mss, err)
	}
	return nil
}

// isOurMSSRule matches an `iptables -S FORWARD` line this project would
// have produced: our comment, or (on a build without the comment match)
// our exact SYN-clamp signature.
func isOurMSSRule(line string) bool {
	if strings.Contains(line, mssComment) {
		return true
	}
	return strings.Contains(line, "--tcp-flags SYN,RST SYN") &&
		strings.Contains(line, "TCPMSS") && strings.Contains(line, "--set-mss")
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
		if strings.HasPrefix(line, "-A FORWARD ") && strings.Contains(line, want) && isOurMSSRule(line) {
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

// clearOurRules deletes every FORWARD mangle rule that is ours (see
// isOurMSSRule), reading the live spec back with `-S` so the -D matches
// byte-for-byte whatever is there.
func clearOurRules(ctx context.Context) {
	out, err := iptablesListForward(ctx)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") || !isOurMSSRule(line) {
			continue
		}
		spec := strings.Fields(strings.TrimPrefix(line, "-A "))
		_ = iptablesRun(ctx, append([]string{"-t", "mangle", "-D"}, spec...)...)
	}
}
