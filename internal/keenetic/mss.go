package keenetic

import (
	"context"
	"errors"
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
		// `opkg update` first, best-effort: a router that's never run it
		// (or hasn't in a while) can have a stale/empty local package
		// index, which makes `opkg install <name>` fail as "not found"
		// even though the package genuinely exists in the feed -- same
		// reasoning as internal/addons' own opkgInstall helper.
		_ = exec.CommandContext(ctx, "opkg", "update").Run()
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
// A cleanup failure (see clearOurRules) doesn't stop the new rule from
// being added -- MSS clamping working right now matters more than a
// leftover stale rule -- but is still reported rather than swallowed,
// unless adding the new rule fails too (that error takes priority).
func SetMSSClamp(ctx context.Context, mss int) error {
	if mss < 1 {
		return ClearMSSClamp(ctx)
	}
	clearErr := clearOurRules(ctx)
	// `-t mangle` and the `-A FORWARD` verb+chain must lead; the match
	// follows. (Getting this order wrong is an iptables "exit status 2".)
	add := func(withComment bool) error {
		args := append([]string{"-t", "mangle", "-A", "FORWARD"}, mssMatch(mss, withComment)...)
		return iptablesRun(ctx, args...)
	}
	if add(true) == nil {
		return clearErr
	}
	if err := add(false); err != nil {
		return fmt.Errorf("adding MSS-clamp rule (--set-mss %d): %w", mss, err)
	}
	return clearErr
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
	return clearOurRules(ctx)
}

// clearOurRules deletes every FORWARD mangle rule that is ours (see
// isOurMSSRule), reading the live spec back with `-S` so the -D matches
// byte-for-byte whatever is there. Each field is unquoted (FW-01): real
// `iptables -S` wraps a string-valued match argument like our own
// `--comment` in double quotes so its own output round-trips as a shell
// command, but iptablesRun execs iptables directly (no shell in
// between), so passing a field through with its quotes still attached
// sends iptables a value it never actually stored -- the delete then
// fails to match anything, silently, forever, since -D reports no error
// for "no such rule". Every previous version of this function's own test
// fixtures fed back *unquoted* fake -S output, which is why this went
// unnoticed: it isn't what real iptables actually prints.
func clearOurRules(ctx context.Context) error {
	out, err := iptablesListForward(ctx)
	if err != nil {
		return nil // nothing to list; not a cleanup failure worth reporting
	}
	var errs []error
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") || !isOurMSSRule(line) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "-A "))
		spec := make([]string, len(fields))
		for i, f := range fields {
			spec[i] = unquote(f)
		}
		if err := iptablesRun(ctx, append([]string{"-t", "mangle", "-D"}, spec...)...); err != nil {
			errs = append(errs, fmt.Errorf("removing stale rule %q: %w", line, err))
		}
	}
	return errors.Join(errs...)
}
