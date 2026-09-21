// This file is the iptables half of l7capture: the rules that feed
// packets into NFLOG in the first place. Deliberately scoped like
// internal/adaptiveroute's own REDIRECT rule (see that package's doc
// comment): only ever matches the specific traffic this feature needs,
// never anything derived from this project's own routes/preset object-
// groups.
package l7capture

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// The points below are the only places this file touches the system --
// injectable, same convention as internal/adaptiveroute's own
// iptablesRun/iptablesListNAT, so the rule-shaping logic is testable
// without real iptables.
var (
	iptablesRun = func(ctx context.Context, args ...string) error {
		return runLoggedCmd(ctx, "iptables", args...)
	}
	iptablesListFORWARD = func(ctx context.Context) (string, error) {
		out, err := exec.CommandContext(ctx, "iptables", "-S", "FORWARD").Output()
		return string(out), err
	}
)

// runLoggedCmd runs name with args and, on failure, folds the process's
// combined stdout+stderr into the returned error -- a bare exec error
// is just "exit status 1" with the tool's own real complaint silently
// discarded otherwise. Duplicated from internal/adaptiveroute's own
// runLogged rather than imported: that helper is unexported, and this
// project's own convention throughout (see cmd/keenetic-xray's
// adaptiveRouteLAN, duplicated from internal/botcontrol's copy of the
// same logic) is to duplicate a handful of lines across a package
// boundary rather than reach into another package's internals for it.
func runLoggedCmd(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		if msg := bytes.TrimSpace(out); len(msg) > 0 {
			return fmt.Errorf("%w: %s", err, msg)
		}
		return err
	}
	return nil
}

// ResolveWANInterface returns the network interface the default route
// (destination 0.0.0.0) currently goes out -- the same /proc/net/route
// scan HydraRoute Neo's own l7_firewall_resolve_wan falls back to when
// no interface is configured explicitly. Keenetic routers run a real
// Linux kernel underneath, so this file is exactly as meaningful there
// as it is on any other Linux box.
//
// path is the file to read, "" meaning the real /proc/net/route -- the
// same empty-string-means-default convention internal/classifier's own
// ScanConntrack uses, so a test can point this at a fixture file
// instead (this project's dev box is Windows, with no /proc at all).
func ResolveWANInterface(path string) (string, error) {
	if path == "" {
		path = "/proc/net/route"
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("l7capture: reading %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Scan() // header line
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("l7capture: reading %s: %w", path, err)
	}
	return "", fmt.Errorf("l7capture: no default route found in %s", path)
}

// l7RuleComment tags the iptables rules this file manages, same
// idempotent-find/remove idea as internal/adaptiveroute's own
// redirectComment.
const l7RuleComment = "keenetic-xray-l7sni"

// RuleOptions describes the NFLOG-triggering rules EnsureRules installs:
// one rule per (WANInterface, port) pair, logging only the first few
// packets of a *new* TCP connection to that port -- see ruleSpecs' own
// doc comment for exactly why that specific shape.
type RuleOptions struct {
	WANInterface string
	Group        uint16 // the NFLOG group internal/l7capture.Open listens on
}

func (o RuleOptions) validate() error {
	if o.WANInterface == "" {
		return fmt.Errorf("l7capture: WAN interface required")
	}
	if o.Group == 0 {
		return fmt.Errorf("l7capture: NFLOG group required")
	}
	return nil
}

// ruleSpecs renders the match+target half of every rule opts wants --
// everything after `-A FORWARD` -- one entry for port 443 (TLS) and one
// for port 80 (plaintext HTTP). QUIC (UDP/443) is deliberately not
// covered here -- see the l7sni-build-plan memory file for why.
//
// The connbytes+length filter is the whole reason this is cheap enough
// to run on embedded router hardware, reproduced exactly from
// HydraRoute Neo's own l7_firewall_emit_rules: `--tcp-flags SYN,ACK ACK`
// matches established-connection data packets, not the SYN itself (a
// ClientHello/request line is sent as data right after the handshake,
// never inside the SYN); `--connbytes-dir original --connbytes-mode
// packets --connbytes 2:N` means NFLOG only fires while this
// connection's own client-to-server packet count is between 2 and N --
// i.e. only during a *new* connection's first few packets, not for the
// rest of that connection's life. `-m length --length 60:` drops
// anything too small to plausibly carry a TLS record header or HTTP
// request line at all (a bare ACK, for instance).
func ruleSpecs(o RuleOptions) [][]string {
	type portSpec struct {
		port         int
		connbytesMax int
	}
	ports := []portSpec{
		{443, 8},
		{80, 4},
	}
	var specs [][]string
	for _, p := range ports {
		specs = append(specs, []string{
			"-o", o.WANInterface,
			"-p", "tcp", "--dport", strconv.Itoa(p.port),
			"--tcp-flags", "SYN,ACK", "ACK",
			"-m", "connbytes", "--connbytes-dir", "original", "--connbytes-mode", "packets",
			"--connbytes", fmt.Sprintf("2:%d", p.connbytesMax),
			"-m", "length", "--length", "60:",
			"-j", "NFLOG", "--nflog-group", strconv.Itoa(int(o.Group)),
		})
	}
	return specs
}

// EnsureRules installs opts' NFLOG rules in filter/FORWARD, removing any
// stale copy of ours first (a different WAN interface or group) --
// same clear-then-add idempotency as internal/adaptiveroute's own
// EnsureRedirect. Falls back to rules without the `comment` match if
// this iptables build doesn't have that module, same fallback that
// function already established for this project.
func EnsureRules(ctx context.Context, opts RuleOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	clearOurRules(ctx)
	add := func(withComment bool) error {
		for _, spec := range ruleSpecs(opts) {
			args := append([]string{"-A", "FORWARD"}, spec...)
			if withComment {
				args = append(args, "-m", "comment", "--comment", l7RuleComment)
			}
			if err := iptablesRun(ctx, args...); err != nil {
				return err
			}
		}
		return nil
	}
	if add(true) == nil {
		return nil
	}
	clearOurRules(ctx) // clean up any partial add before retrying
	if err := add(false); err != nil {
		return fmt.Errorf("adding NFLOG rules (group %d): %w", opts.Group, err)
	}
	return nil
}

// RulesInPlace reports whether every rule opts currently wants is live
// right now -- the reconcile loop's own drift check, same idea as
// internal/adaptiveroute's own RedirectInPlace. Matches by signature
// (interface + port + connbytes range + nflog-group), not full-line
// equality, so it doesn't care whether the comment match is present.
func RulesInPlace(ctx context.Context, opts RuleOptions) bool {
	if opts.validate() != nil {
		return false
	}
	out, err := iptablesListFORWARD(ctx)
	if err != nil {
		return false
	}
	lines := strings.Split(out, "\n")
	group := "--nflog-group " + strconv.Itoa(int(opts.Group))
	for _, spec := range ruleSpecs(opts) {
		dport := ""
		for i, tok := range spec {
			if tok == "--dport" && i+1 < len(spec) {
				dport = "--dport " + spec[i+1]
				break
			}
		}
		if !anyForwardLineHasAll(lines, "-o "+opts.WANInterface+" ", dport, group) {
			return false
		}
	}
	return true
}

func anyForwardLineHasAll(lines []string, want ...string) bool {
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A FORWARD ") {
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

// isOurRule matches an `iptables -S FORWARD` line this file would have
// produced: our comment, or (on a build without the comment match) the
// NFLOG target with our own group's signature. group is passed as a
// literal number, not a struct, since ClearRules doesn't otherwise need
// to know which options originally installed the rules it's removing.
func isOurRule(line, comment string) bool {
	if strings.Contains(line, comment) {
		return true
	}
	return strings.Contains(line, "-j NFLOG") && strings.Contains(line, "--connbytes-dir original")
}

// ClearRules removes this file's NFLOG rules. A no-op when none exist.
func ClearRules(ctx context.Context) error {
	return clearOurRules(ctx)
}

// unquote strips one layer of surrounding double quotes -- real
// `iptables -S` wraps a string-valued match argument (our own --comment)
// in double quotes so its own output round-trips as a shell command, but
// iptablesRun execs iptables directly, no shell in between, so a field
// passed through with its quotes still attached is a value iptables
// never actually stored and the delete silently fails to match anything.
// Duplicated from internal/keenetic/wireguard.go's own unquote (same
// project convention as runLoggedCmd above, a package boundary rather
// than a 5-line import) -- internal/keenetic/mss.go had the identical bug
// for the exact same reason (FW-01), found and fixed first; this is the
// same fix applied here.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// clearOurRules deletes every filter/FORWARD rule that is ours (see
// isOurRule), reading the live spec back with `-S` so the `-D` matches
// byte-for-byte whatever is actually there.
func clearOurRules(ctx context.Context) error {
	out, err := iptablesListFORWARD(ctx)
	if err != nil {
		return nil // nothing to list; not a cleanup failure worth reporting
	}
	var errs []error
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A FORWARD ") || !isOurRule(line, l7RuleComment) {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "-A "))
		spec := make([]string, len(fields))
		for i, f := range fields {
			spec[i] = unquote(f)
		}
		if err := iptablesRun(ctx, append([]string{"-D"}, spec...)...); err != nil {
			errs = append(errs, fmt.Errorf("removing stale rule %q: %w", line, err))
		}
	}
	return errors.Join(errs...)
}
