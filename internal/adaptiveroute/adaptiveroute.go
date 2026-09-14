// Package adaptiveroute is the dataplane half of Susanin Phase 2 (see
// docs/HANDOFF-susanin.md and internal/config.TransparentOptions): an
// ipset holding IPs this project's own classifier has confirmed are
// blocked, and an iptables REDIRECT rule in nat/PREROUTING that sends
// any packet to one of those IPs to xray's local dokodemo-door inbound
// instead of DIRECT. Set membership is the classifier's job (not built
// here); this package only owns the ipset CRUD and the REDIRECT rule
// itself.
//
// Deliberately scoped to only the ipset named by RedirectOptions.SetName
// -- REDIRECT must never match a blanket "port 443" or anything derived
// from this project's own routes/preset object-groups, only IPs the
// classifier put there itself (see the "Phase 2 concrete design" note in
// memory / the plan doc for why: traffic our own routes/presets already
// send DIRECT-and-then-some-other-way must never be pulled into this
// path too).
package adaptiveroute

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RedirectSetName is the one ipset this project's adaptive-routing
// feature uses everywhere -- both cmd/keenetic-xray's CLI (`transport
// adaptive`) and internal/botcontrol's bot screen need to agree on the
// exact same set to create/query, so it lives here (rather than as a
// private constant duplicated in each caller) as the single source of
// truth.
const RedirectSetName = "keenetic_xray_adaptive"

// The points below are the only places this package touches the system
// -- injectable, same convention as keenetic.iptablesRun/ndmcRun, so the
// rule-shaping logic is testable without real iptables/ipset.
//
// iptablesRun/ipsetRun deliberately use CombinedOutput, not Run: a plain
// Run leaves stdout+stderr connected to nothing, so a failure surfaces
// as a bare "exit status 1" with the tool's own real complaint (e.g.
// ipset's "Kernel error received: ..." when a set type's kernel module
// isn't loaded) silently discarded -- confirmed live, this exact gap
// hid the actual reason `ipset create ... hash:net ...` failed on one
// router. runLogged folds that output into the returned error so it
// reaches whoever's reporting the failure (CLI stdout, `keenetic-xray
// logs`, ...) instead of vanishing.
var (
	iptablesRun = func(ctx context.Context, args ...string) error {
		return runLogged(ctx, "iptables", args...)
	}
	iptablesListNAT = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "iptables", "-t", "nat", "-S", "PREROUTING").Output()
		return string(out), err
	}
	ipsetRun = func(ctx context.Context, args ...string) error {
		return runLogged(ctx, "ipset", args...)
	}
	ipsetOutput = func(ctx context.Context, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, "ipset", args...).Output()
		return string(out), err
	}
	ipsetPresent     = func() bool { return exec.Command("ipset", "-v").Run() == nil }
	opkgInstallIPSet = func(ctx context.Context) error {
		// `opkg update` first, best-effort -- same reasoning as
		// internal/addons' own opkgInstall helper and keenetic.
		// opkgInstallIptables: a stale/empty local package index makes
		// `opkg install <name>` fail as "not found" even when the
		// package genuinely exists in the feed.
		_ = exec.CommandContext(ctx, "opkg", "update").Run()
		return exec.CommandContext(ctx, "opkg", "install", "ipset").Run()
	}
)

// runLogged runs name with args and, on failure, folds the process's
// combined stdout+stderr into the returned error -- see the var block
// above for why a bare exec error isn't enough here.
func runLogged(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if msg := bytes.TrimSpace(out); len(msg) > 0 {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// IPSetPresent reports whether `ipset` is runnable right now (no install
// attempt).
func IPSetPresent() bool { return ipsetPresent() }

// EnsureIPSetTool makes sure `ipset` is runnable, installing the Entware
// package if not. Unlike iptables (already guaranteed present -- this
// project's own WAN masquerading needs it), ipset is not something
// anything else in this project installs.
func EnsureIPSetTool(ctx context.Context) error {
	if ipsetPresent() {
		return nil
	}
	if err := opkgInstallIPSet(ctx); err != nil {
		return fmt.Errorf("installing ipset via opkg: %w", err)
	}
	if !ipsetPresent() {
		return fmt.Errorf("ipset still not runnable after opkg install")
	}
	return nil
}

// EnsureIPSet creates the named hash:net set if it doesn't already exist,
// with per-entry timeout support enabled (default 0 = an entry added
// without its own timeout never expires; AddIP can still give any
// individual entry a shorter one). hash:net (rather than hash:ip) is
// deliberate: it accepts a bare IP exactly as hash:ip would (stored as an
// implicit /32) *and* an arbitrary CIDR block in the same set, which is
// what lets the classifier's block-aggregation pass (ClrBlockPromote)
// redirect a whole subnet once enough of its individual addresses are
// confirmed, without a second set or a dataplane change of its own.
// "-exist" makes a repeat create a no-op instead of an error -- *when*
// the existing set's own create parameters match exactly; ipset(8) is
// explicit that a name collision with a *different* type is still a
// real error even with "-exist". That's not hypothetical here: any
// router that had adaptive routing on before this project switched the
// set from hash:ip to hash:net already has one under this exact name,
// so the plain create below fails deterministically on every such
// upgrade until something clears it -- confirmed live. On that failure,
// clear our own REDIRECT rule (an existing rule referencing the set is
// exactly what stops "ipset destroy" from working -- "in use by a
// kernel component") and destroy+recreate: membership is disposable,
// freshly re-added by the classifier on its own TTLs, so losing it here
// costs nothing. Whatever EnsureRedirect the caller runs right after
// this re-adds the rule against the now-recreated set.
//
// Membership itself is managed by AddIP/RemoveIP (the classifier's
// job), not here.
func EnsureIPSet(ctx context.Context, name string) error {
	create := func() error {
		return ipsetRun(ctx, "create", name, "hash:net", "timeout", "0", "-exist")
	}
	if err := create(); err != nil {
		clearOurRedirectRules(ctx)
		_ = ipsetRun(ctx, "destroy", name)
		if err := create(); err != nil {
			return fmt.Errorf("recreating %s as hash:net (a stale hash:ip set from an older version?): %w", name, err)
		}
	}
	return nil
}

// AddIP adds ip -- a bare address or a CIDR block, hash:net accepts both
// -- to setName. ttl > 0 gives that entry a kernel-level expiry (ipset's
// own `timeout`, in whole seconds) so a crashed or killed classifier
// doesn't leave a redirect stuck on forever -- the classifier's own
// state (which this mirrors) is what decides *when*, but the kernel is
// the backstop if the classifier process itself never gets to run that
// decision again. ttl <= 0 adds with no per-entry timeout (the set's own
// default, set by EnsureIPSet). "-exist" makes adding an already-present
// entry a no-op instead of an error (this also refreshes that entry's
// timeout to the new value, ipset's own behavior).
func AddIP(ctx context.Context, setName, ip string, ttl time.Duration) error {
	args := []string{"add", setName, ip, "-exist"}
	if ttl > 0 {
		args = append(args, "timeout", strconv.Itoa(int(ttl/time.Second)))
	}
	return ipsetRun(ctx, args...)
}

// RemoveIP removes ip from setName. "-exist" makes removing an absent IP
// a no-op instead of an error.
func RemoveIP(ctx context.Context, setName, ip string) error {
	return ipsetRun(ctx, "del", setName, ip, "-exist")
}

// Flush empties setName without deleting the set itself.
func Flush(ctx context.Context, setName string) error {
	return ipsetRun(ctx, "flush", setName)
}

// Members lists the IPs currently in setName.
func Members(ctx context.Context, setName string) ([]string, error) {
	out, err := ipsetOutput(ctx, "list", setName, "-output", "save")
	if err != nil {
		return nil, err
	}
	prefix := "add " + setName + " "
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		if ip, ok := strings.CutPrefix(line, prefix); ok {
			ips = append(ips, strings.TrimSpace(ip))
		}
	}
	return ips, nil
}

// redirectComment tags the iptables REDIRECT rules this package manages,
// same idempotent-find/remove idea as keenetic.mssComment.
const redirectComment = "keenetic-xray-adaptive"

// RedirectOptions describes the REDIRECT rule set EnsureRedirect installs:
// one rule per (LAN interface, protocol) pair, redirecting any packet
// whose destination is in SetName to Port on this same host -- where the
// xray dokodemo-door inbound (internal/config.TransparentOptions, same
// Port) picks it up and, per that inbound's followRedirect setting,
// recovers the real destination and forwards to whatever outbound is
// currently live.
type RedirectOptions struct {
	SetName       string   // the ipset EnsureIPSet already created
	Port          int      // must match the xray Transparent inbound's port
	LANInterfaces []string // e.g. ["br0"]; at least one required
}

func (o RedirectOptions) validate() error {
	if o.SetName == "" {
		return fmt.Errorf("adaptiveroute: SetName required")
	}
	if o.Port <= 0 || o.Port > 65535 {
		return fmt.Errorf("adaptiveroute: bad port %d", o.Port)
	}
	if len(o.LANInterfaces) == 0 {
		return fmt.Errorf("adaptiveroute: at least one LAN interface required")
	}
	return nil
}

// redirectSpecs renders the match+target half of every rule opts wants --
// everything after `-t nat -A PREROUTING` -- one entry per (interface,
// protocol) pair, tcp then udp per interface, in a stable order.
func redirectSpecs(o RedirectOptions, withComment bool) [][]string {
	var specs [][]string
	for _, iface := range o.LANInterfaces {
		for _, proto := range []string{"tcp", "udp"} {
			spec := []string{"-i", iface, "-p", proto, "-m", "set", "--match-set", o.SetName, "dst"}
			if withComment {
				spec = append(spec, "-m", "comment", "--comment", redirectComment)
			}
			spec = append(spec, "-j", "REDIRECT", "--to-ports", strconv.Itoa(o.Port))
			specs = append(specs, spec)
		}
	}
	return specs
}

// EnsureRedirect installs opts' REDIRECT rules in nat/PREROUTING,
// removing any stale copy of ours first (e.g. a different port, set, or
// interface list) -- same clear-then-add idempotency as
// keenetic.SetMSSClamp. Falls back to rules without the `comment` match
// if this iptables build doesn't have that module, same as MSS clamping.
func EnsureRedirect(ctx context.Context, opts RedirectOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	clearOurRedirectRules(ctx)
	add := func(withComment bool) error {
		for _, spec := range redirectSpecs(opts, withComment) {
			args := append([]string{"-t", "nat", "-A", "PREROUTING"}, spec...)
			if err := iptablesRun(ctx, args...); err != nil {
				return err
			}
		}
		return nil
	}
	if add(true) == nil {
		return nil
	}
	clearOurRedirectRules(ctx) // clean up any partial add before retrying
	if err := add(false); err != nil {
		return fmt.Errorf("adding REDIRECT rules (port %d): %w", opts.Port, err)
	}
	return nil
}

// RedirectInPlace reports whether every rule opts currently wants is live
// right now -- the reconcile loop's own drift check, same idea as
// keenetic.MSSClampInPlace. Matches by signature (interface + protocol +
// the exact ipset + REDIRECT + port), not full-line equality, so it
// doesn't care whether the comment match is present -- a config change
// goes through EnsureRedirect directly (always clears first), so this
// only needs to catch the firmware silently dropping what should still
// be there, not detect a stale *different* config on its own.
func RedirectInPlace(ctx context.Context, opts RedirectOptions) bool {
	if opts.validate() != nil {
		return false
	}
	out, err := iptablesListNAT(ctx)
	if err != nil {
		return false
	}
	lines := strings.Split(out, "\n")
	matchSet := "--match-set " + opts.SetName + " dst"
	toPorts := "--to-ports " + strconv.Itoa(opts.Port)
	for _, iface := range opts.LANInterfaces {
		for _, proto := range []string{"tcp", "udp"} {
			if !anyLineHasAll(lines, "-i "+iface+" ", "-p "+proto+" ", matchSet, "-j REDIRECT", toPorts) {
				return false
			}
		}
	}
	return true
}

func anyLineHasAll(lines []string, want ...string) bool {
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A PREROUTING ") {
			continue
		}
		ok := true
		for _, w := range want {
			if !strings.Contains(line, w) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// isOurRedirectRule matches an `iptables -t nat -S PREROUTING` line this
// package would have produced: our comment, or (on a build without the
// comment match) the match-set + REDIRECT + to-ports signature, which is
// specific enough on its own -- nothing else in this project's own
// iptables use (MSS clamp is `mangle`/`FORWARD`; Proxy0/WAN masquerading
// don't use `--match-set`) produces a nat/PREROUTING REDIRECT rule.
func isOurRedirectRule(line string) bool {
	if strings.Contains(line, redirectComment) {
		return true
	}
	return strings.Contains(line, "--match-set") &&
		strings.Contains(line, "-j REDIRECT") && strings.Contains(line, "--to-ports")
}

// ClearRedirect removes this package's REDIRECT rule(s). A no-op when
// none exist; iptables itself is already guaranteed present elsewhere in
// this project (Keenetic's own WAN masquerading needs it), so unlike
// ipset there's no separate presence guard here -- clearOurRedirectRules
// already tolerates a listing failure by doing nothing.
func ClearRedirect(ctx context.Context) error {
	clearOurRedirectRules(ctx)
	return nil
}

// clearOurRedirectRules deletes every nat/PREROUTING rule that is ours
// (see isOurRedirectRule), reading the live spec back with `-S` so the
// `-D` matches byte-for-byte whatever is actually there.
func clearOurRedirectRules(ctx context.Context) {
	out, err := iptablesListNAT(ctx)
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A PREROUTING ") || !isOurRedirectRule(line) {
			continue
		}
		spec := strings.Fields(strings.TrimPrefix(line, "-A "))
		_ = iptablesRun(ctx, append([]string{"-t", "nat", "-D"}, spec...)...)
	}
}
