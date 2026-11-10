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
	"sync"
)

// The points below are the only places this file touches the system --
// injectable, same convention as internal/adaptiveroute's own
// iptablesRun/iptablesListNAT, so the rule-shaping logic is testable
// without real iptables.
var (
	iptablesRun = func(ctx context.Context, args ...string) error {
		return runLoggedCmd(ctx, "iptables", args...)
	}
	// iptablesListFORWARD is `iptables -t <table> -S FORWARD`: the rules, as
	// commands that would recreate them.
	iptablesListFORWARD = func(ctx context.Context, table string) (string, error) {
		out, err := exec.CommandContext(ctx, "iptables", "-t", table, "-S", "FORWARD").Output()
		return string(out), err
	}
	// iptablesListCounters is `iptables -t <table> -L FORWARD -v -n -x`: the
	// same chain as a table with the packet and byte count of every rule (-x:
	// exact numbers, not 12K).
	iptablesListCounters = func(ctx context.Context, table string) (string, error) {
		out, err := exec.CommandContext(ctx, "iptables", "-t", table, "-L", "FORWARD", "-v", "-n", "-x").Output()
		return string(out), err
	}
)

// ruleTable is the iptables table our NFLOG rules live in, in its FORWARD
// chain; legacyRuleTable is where every build up to v0.32.111 put them.
//
// mangle, not filter. Found live (2026-11-10, after the capture's counters had
// stayed empty on a router since the feature shipped): on a Keenetic
// filter/FORWARD has the policy DROP and the firmware ACCEPTs what it allows
// inside the chain, so a rule appended there sees only what nothing before it
// let through -- never a client's ClientHello. The rules matched nothing, the
// NFLOG socket never read a packet, and the log said "capturing" the whole
// time. Reproduced on a real kernel in a network namespace: with a DROP-policy
// FORWARD chain that accepts ESTABLISHED first, the filter rules counted 0
// packets while the accept rule counted them all. mangle/FORWARD is traversed
// before filter/FORWARD and carries no verdicts of its own; it is where
// HydraRoute puts the same rules and where this project's MSS clamp already
// lives.
const (
	ruleTable       = "mangle"
	legacyRuleTable = "filter"
)

// DefaultGroup is the NFLOG group number this project uses for its own
// capture. ClearRules, which is told nothing about its caller's options, knows
// our rules by it.
const DefaultGroup uint16 = 4210

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
// packets of a *new* connection to that port -- see ruleSpecs' own doc
// comment for exactly why that specific shape.
type RuleOptions struct {
	WANInterface string
	Group        uint16 // the NFLOG group internal/l7capture.Open listens on

	// QUIC adds the UDP/443 rule that captures QUIC Initial datagrams. Off
	// by default: it is a different (and costlier) kind of capture than the
	// two TCP rules, and its first use is to look, not to act.
	QUIC bool
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

// tcpMinLength is the lower bound of the TCP rules' `-m length` match, in
// bytes of IPv4 total length: 41 = a 20-byte IPv4 header + a 20-byte TCP
// header + one byte of payload, i.e. "carries any data at all". It used to
// be 60 (HydraRoute Neo's older value), which also threw away a segment
// with under 8 bytes of payload -- exactly what a client-side DPI bypass
// (zapret, GoodbyeDPI, ByeDPI, ...) produces when it cuts the ClientHello
// into pieces of one or two bytes; the SNI of such a connection was
// invisible. HydraRoute lowered it for the same reason. The price is that
// empty ACKs carrying TCP options (a timestamp makes them 52 bytes) now
// pass the filter too, inside the connbytes window; the packet handler
// (cmd/keenetic-xray/l7sni_handler.go) returns on an empty payload before
// doing anything else, and the window keeps it to a few packets per new
// connection.
const tcpMinLength = "41:"

// quicMinLength and quicWindow are the QUIC rule's `-m length` bound and
// connbytes window. A client must pad every datagram that carries an Initial
// packet to at least 1200 bytes (RFC 9000 section 14.1), so a length filter
// alone picks the Initials out of UDP/443 without looking at a payload; the
// window keeps it to the first four datagrams of a flow (HydraRoute Neo
// notes that KeeneticOS counts connbytes one lower than the packet number,
// hence 0:3 for datagrams one to four) -- the first flight, its repeats, and
// the second datagram of a ClientHello that does not fit in one.
const (
	quicMinLength = "1200:"
	quicWindow    = "0:3"
)

// ruleSpec is one NFLOG-triggering rule as data. It renders both the
// iptables arguments that install the rule (args) and the substrings that
// recognise it in `iptables -S` output (signature) from the same fields, so
// a property that is added to the one cannot be forgotten in the other --
// which is how a changed length bound once stayed invisible to the drift
// check.
type ruleSpec struct {
	iface  string
	proto  string // "tcp" or "udp"
	dport  int
	window string // connbytes packet-count window, "2:8"
	minLen string // length lower bound, "41:"
	group  uint16
}

// args is everything after `-A FORWARD`.
func (s ruleSpec) args() []string {
	a := []string{"-o", s.iface, "-p", s.proto, "--dport", strconv.Itoa(s.dport)}
	if s.proto == "tcp" {
		// established-connection data packets, not the SYN itself (a
		// ClientHello/request line is sent as data right after the
		// handshake, never inside the SYN)
		a = append(a, "--tcp-flags", "SYN,ACK", "ACK")
	}
	return append(a,
		"-m", "connbytes", "--connbytes-dir", "original", "--connbytes-mode", "packets",
		"--connbytes", s.window,
		"-m", "length", "--length", s.minLen,
		"-j", "NFLOG", "--nflog-group", strconv.Itoa(int(s.group)),
	)
}

// signature is the set of substrings an `iptables -S FORWARD` line must
// contain to be this rule: interface, protocol, port, connbytes window,
// length bound and our NFLOG group. Not a full-line comparison on purpose --
// the line `-S` prints reorders the match arguments, spells the length range
// out (`41:65535`) and may or may not carry the comment match.
func (s ruleSpec) signature() []string {
	return []string{
		"-o " + s.iface + " ",
		"-p " + s.proto + " ",
		"--dport " + strconv.Itoa(s.dport),
		"--connbytes " + s.window,
		"--length " + s.minLen,
		"--nflog-group " + strconv.Itoa(int(s.group)),
	}
}

// ruleSpecs lists every rule opts wants: one for port 443 (TLS) and one for
// port 80 (plaintext HTTP), plus UDP/443 (QUIC) when opts.QUIC is set.
//
// The connbytes+length filter is the whole reason this is cheap enough
// to run on embedded router hardware, reproduced from HydraRoute Neo's own
// l7_firewall_emit_rules: `--connbytes-dir original --connbytes-mode
// packets --connbytes 2:N` means NFLOG only fires while this connection's
// own client-to-server packet count is between 2 and N -- i.e. only during
// a *new* connection's first few packets, not for the rest of that
// connection's life. `-m length --length 41:` drops anything that carries
// no payload at all (see tcpMinLength).
func ruleSpecs(o RuleOptions) []ruleSpec {
	specs := []ruleSpec{
		{iface: o.WANInterface, proto: "tcp", dport: 443, window: "2:8", minLen: tcpMinLength, group: o.Group},
		{iface: o.WANInterface, proto: "tcp", dport: 80, window: "2:4", minLen: tcpMinLength, group: o.Group},
	}
	if o.QUIC {
		specs = append(specs, ruleSpec{iface: o.WANInterface, proto: "udp", dport: 443, window: quicWindow, minLen: quicMinLength, group: o.Group})
	}
	return specs
}

// rulesMu serialises the in-process changers of our rules. EnsureRules is
// clear-then-add, a handful of iptables runs, and three goroutines of the
// daemon reach it: the capture session at its start, the reconcile loop, and
// the bot (a QUIC mode button). Two of them interleaving leave the chain with
// duplicated rules -- every packet captured and processed twice -- until the
// next reconcile counts them. (The CLI is another process and cannot share
// this; its worst case is the same self-healing duplicate.)
var rulesMu sync.Mutex

// EnsureRules installs opts' NFLOG rules in mangle/FORWARD (see ruleTable for
// why not filter), removing any stale copy of ours first -- a different WAN
// interface or group, and the copies an older build put in filter/FORWARD --
// same clear-then-add idempotency as internal/adaptiveroute's own
// EnsureRedirect. Falls back to rules without the `comment` match if this
// iptables build doesn't have that module, same fallback that function already
// established for this project.
//
// The rules are INSERTED at the head of the chain (positions 1..n, in the order
// of ruleSpecs), not appended: nothing the firmware keeps in the chain, now or
// in a later release, can then decide a packet before the capture has seen it.
// That is the exact failure the move out of filter fixed, and the one place
// where a silent zero would cost a router's worth of guessing again.
func EnsureRules(ctx context.Context, opts RuleOptions) error {
	if err := opts.validate(); err != nil {
		return err
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	clearOurRules(ctx, opts.Group)
	add := func(withComment bool) error {
		for i, spec := range ruleSpecs(opts) {
			args := append([]string{"-t", ruleTable, "-I", "FORWARD", strconv.Itoa(i + 1)}, spec.args()...)
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
	clearOurRules(ctx, opts.Group) // clean up any partial add before retrying
	if err := add(false); err != nil {
		return fmt.Errorf("adding NFLOG rules (group %d): %w", opts.Group, err)
	}
	return nil
}

// RulesInPlace reports whether exactly the rules opts wants are live
// right now -- the reconcile loop's own drift check, same idea as
// internal/adaptiveroute's own RedirectInPlace. Matches by signature
// (see ruleSpec.signature), not full-line equality, so it doesn't care whether
// the comment match is present.
//
// "Exactly": a rule of ours that no wanted spec accounts for -- one an
// older build installed with a different length bound, a duplicate, or one
// for a mode that has since been switched off -- makes this false, so the
// next reconcile runs EnsureRules (clear ours, add the wanted set) instead
// of leaving the old filter in place forever because everything the new
// code asks for happens to be there too.
//
// A rule of ours still sitting in the table an older build used (filter, see
// ruleTable) counts as drift too: it matches nothing there, but only EnsureRules
// removes it, and a router that was updated in place has it until then.
func RulesInPlace(ctx context.Context, opts RuleOptions) bool {
	if opts.validate() != nil {
		return false
	}
	out, err := iptablesListFORWARD(ctx, ruleTable)
	if err != nil {
		return false
	}
	lines := strings.Split(out, "\n")
	specs := ruleSpecs(opts)
	for _, spec := range specs {
		if !anyForwardLineHasAll(lines, spec.signature()...) {
			return false
		}
	}
	if ownRuleCount(lines, opts.Group) != len(specs) {
		return false
	}
	if legacy, err := iptablesListFORWARD(ctx, legacyRuleTable); err == nil && ownRuleCount(strings.Split(legacy, "\n"), opts.Group) > 0 {
		return false
	}
	return true
}

// ownRuleCount counts the FORWARD lines that feed our NFLOG group. Counted by
// group rather than by comment: another tool's NFLOG rule with connbytes in the
// same chain (HydraRoute keeps its own in mangle/FORWARD, with its own group)
// must not read as ours here, or this would call the chain drifted forever and
// reinstall on every reconcile.
func ownRuleCount(lines []string, group uint16) int {
	n := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "-A FORWARD ") && feedsGroup(line, group) {
			n++
		}
	}
	return n
}

// feedsGroup reports whether an `iptables -S` line ends in the NFLOG target of
// the given group.
func feedsGroup(line string, group uint16) bool {
	want := "-j NFLOG --nflog-group " + strconv.Itoa(int(group))
	i := strings.Index(line, want)
	if i < 0 {
		return false
	}
	rest := line[i+len(want):]
	return rest == "" || rest[0] == ' '
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
// produced: our comment, or (on a build without the comment match) the NFLOG
// target of our own group. Not "any NFLOG rule with connbytes", which an
// earlier version of this matched: with the rules in mangle/FORWARD that is
// the chain HydraRoute keeps its own L7 rules in, and clearing ours would have
// taken its rules with them.
func isOurRule(line string, group uint16) bool {
	if !strings.HasPrefix(line, "-A FORWARD ") {
		return false
	}
	return strings.Contains(line, l7RuleComment) || feedsGroup(line, group)
}

// ClearRules removes this file's NFLOG rules, from mangle and from the table an
// older build used. A no-op when none exist. Our rules are told apart from
// anyone else's by comment, or by DefaultGroup on a build without the comment
// match.
func ClearRules(ctx context.Context) error {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	return clearOurRules(ctx, DefaultGroup)
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

// clearOurRules deletes every rule of ours (see isOurRule) from FORWARD in both
// tables we have ever used -- the current one and the one an older build
// installed into -- reading the live spec back with `-S` so the `-D` matches
// byte-for-byte whatever is actually there. A table that cannot be listed is
// skipped, not reported: nothing to remove from it.
func clearOurRules(ctx context.Context, group uint16) error {
	var errs []error
	for _, table := range []string{ruleTable, legacyRuleTable} {
		out, err := iptablesListFORWARD(ctx, table)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if !isOurRule(line, group) {
				continue
			}
			fields := strings.Fields(strings.TrimPrefix(line, "-A "))
			spec := make([]string, len(fields))
			for i, f := range fields {
				spec[i] = unquote(f)
			}
			if err := iptablesRun(ctx, append([]string{"-t", table, "-D"}, spec...)...); err != nil {
				errs = append(errs, fmt.Errorf("removing stale rule %q from %s: %w", line, table, err))
			}
		}
	}
	return errors.Join(errs...)
}

// RuleStat is how many packets one of our NFLOG rules has matched since it was
// installed -- the kernel's own count, taken before anything reaches the NFLOG
// socket, which is what tells "the rule never fires" from "it fires and nothing
// arrives" when the capture's own counters stay at zero.
type RuleStat struct {
	Table   string // ruleTable, or legacyRuleTable for a leftover of an older build
	Iface   string // the output interface the rule matches
	Proto   string // "tcp" or "udp"
	DPort   int
	Packets uint64
	Bytes   uint64
}

// RuleCounters reads the packet counters of every NFLOG rule feeding group in
// mangle/FORWARD, then of any left in the table an older build used. The
// current table failing to list is an error (iptables missing, no permission);
// the old one failing is not, there is nothing to report from it.
func RuleCounters(ctx context.Context, group uint16) ([]RuleStat, error) {
	var out []RuleStat
	for _, table := range []string{ruleTable, legacyRuleTable} {
		listing, err := iptablesListCounters(ctx, table)
		if err != nil {
			if table == ruleTable {
				return nil, fmt.Errorf("l7capture: listing %s/FORWARD: %w", table, err)
			}
			continue
		}
		for _, line := range strings.Split(listing, "\n") {
			if st, ok := parseCounterLine(line, group); ok {
				st.Table = table
				out = append(out, st)
			}
		}
	}
	return out, nil
}

// parseCounterLine reads one rule line of `iptables -L FORWARD -v -n -x`:
//
//	pkts bytes target prot opt in out source destination [matches...]
//	   3  1348 NFLOG  tcp  --  *  eth1 0.0.0.0/0 0.0.0.0/0 tcp dpt:443 ... nflog-group 4210
//
// ok is false for the header lines, for any other target, and for an NFLOG rule
// of another group. The protocol column reads `tcp` from some iptables builds
// and `6` from others.
func parseCounterLine(line string, group uint16) (RuleStat, bool) {
	f := strings.Fields(line)
	if len(f) < 9 || f[2] != "NFLOG" {
		return RuleStat{}, false
	}
	pkts, err1 := strconv.ParseUint(f[0], 10, 64)
	bytes, err2 := strconv.ParseUint(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return RuleStat{}, false
	}
	want := "nflog-group " + strconv.Itoa(int(group))
	i := strings.Index(line, want)
	if i < 0 {
		return RuleStat{}, false
	}
	if rest := line[i+len(want):]; rest != "" && rest[0] != ' ' {
		return RuleStat{}, false // group 42100 is not group 4210
	}
	st := RuleStat{Iface: f[6], Packets: pkts, Bytes: bytes}
	switch f[3] {
	case "tcp", "6":
		st.Proto = "tcp"
	case "udp", "17":
		st.Proto = "udp"
	default:
		return RuleStat{}, false
	}
	for _, tok := range f[9:] {
		if v, ok := strings.CutPrefix(tok, "dpt:"); ok {
			st.DPort, _ = strconv.Atoi(v)
		}
	}
	return st, true
}
