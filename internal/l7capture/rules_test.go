package l7capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func testOpts() RuleOptions {
	return RuleOptions{WANInterface: "eth1", Group: 4210}
}

// fakeIptables gives EnsureRules/ClearRules/RulesInPlace in-memory FORWARD
// chains instead of a real iptables binary -- same "fake exec layer via the
// package's own injectable vars" approach internal/adaptiveroute's own tests
// use. lines is mangle/FORWARD, the chain our rules live in; legacy is
// filter/FORWARD, where builds up to v0.32.111 put them.
type fakeIptables struct {
	lines  []string
	legacy []string
	sent   []string // every command run, as one string each
}

func (f *fakeIptables) chain(table string) (*[]string, error) {
	switch table {
	case "mangle":
		return &f.lines, nil
	case "filter":
		return &f.legacy, nil
	}
	return nil, fmt.Errorf("fakeIptables: no table %q", table)
}

func installFakeIptables(t *testing.T) *fakeIptables {
	t.Helper()
	f := &fakeIptables{}
	origRun, origList := iptablesRun, iptablesListFORWARD
	iptablesRun = func(_ context.Context, args ...string) error {
		return f.apply(args)
	}
	iptablesListFORWARD = func(_ context.Context, table string) (string, error) {
		c, err := f.chain(table)
		if err != nil {
			return "", err
		}
		return strings.Join(*c, "\n"), nil
	}
	t.Cleanup(func() { iptablesRun, iptablesListFORWARD = origRun, origList })
	return f
}

// apply runs one command the way iptables would: every command of ours names
// its table first (`-t <table> -A|-I|-D FORWARD ...`).
func (f *fakeIptables) apply(args []string) error {
	f.sent = append(f.sent, strings.Join(args, " "))
	if len(args) < 3 || args[0] != "-t" {
		return fmt.Errorf("fakeIptables: a command must start with -t <table>: %v", args)
	}
	chain, err := f.chain(args[1])
	if err != nil {
		return err
	}
	args = args[2:]
	switch args[0] {
	case "-A":
		*chain = append(*chain, "-A "+strings.Join(args[1:], " "))
		return nil
	case "-I": // -I FORWARD <position> spec...
		if len(args) < 4 {
			return fmt.Errorf("fakeIptables: -I needs a chain, a position and a rule: %v", args)
		}
		pos, err := strconv.Atoi(args[2])
		if err != nil || pos < 1 || pos-1 > len(*chain) {
			return fmt.Errorf("fakeIptables: bad insert position in %v", args)
		}
		line := "-A " + args[1] + " " + strings.Join(args[3:], " ")
		*chain = append((*chain)[:pos-1], append([]string{line}, (*chain)[pos-1:]...)...)
		return nil
	case "-D":
		want := "-A " + strings.Join(args[1:], " ")
		for i, l := range *chain {
			// Real `iptables -S` wraps a --comment value in double quotes
			// as shell quoting; the -D that clearOurRules sends has them
			// stripped (see unquote), and iptables matches on the stored
			// value, not on the quoting.
			if strings.ReplaceAll(l, `"`, "") == want {
				*chain = append((*chain)[:i], (*chain)[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("no matching rule to delete: %s", want)
	default:
		return fmt.Errorf("fakeIptables: unhandled args %v", args)
	}
}

func TestEnsureRules_InstallsBothPorts(t *testing.T) {
	f := installFakeIptables(t)
	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	if len(f.lines) != 2 {
		t.Fatalf("FORWARD chain has %d rules, want 2 (port 443 and port 80): %v", len(f.lines), f.lines)
	}
	var has443, has80 bool
	for _, l := range f.lines {
		if strings.Contains(l, "--dport 443") {
			has443 = true
		}
		if strings.Contains(l, "--dport 80") {
			has80 = true
		}
		if !strings.Contains(l, "-o eth1") {
			t.Errorf("rule missing WAN interface match: %s", l)
		}
		if !strings.Contains(l, "--nflog-group 4210") {
			t.Errorf("rule missing our NFLOG group: %s", l)
		}
	}
	if !has443 || !has80 {
		t.Errorf("expected rules for both :443 and :80, got: %v", f.lines)
	}
}

// TestEnsureRules_LengthBoundIsFortyOne pins the TCP length bound: a
// ClientHello a client-side DPI bypass cuts into one- or two-byte pieces
// has to get through the filter (see tcpMinLength).
func TestEnsureRules_LengthBoundIsFortyOne(t *testing.T) {
	f := installFakeIptables(t)
	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	for _, l := range f.lines {
		if !strings.Contains(l, "--length 41:") {
			t.Errorf("rule does not use the 41-byte lower bound: %s", l)
		}
		if strings.Contains(l, "--length 60:") {
			t.Errorf("rule still carries the old 60-byte bound: %s", l)
		}
	}
}

func TestEnsureRules_Idempotent(t *testing.T) {
	f := installFakeIptables(t)
	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules (1st): %v", err)
	}
	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules (2nd): %v", err)
	}
	if len(f.lines) != 2 {
		t.Fatalf("after two EnsureRules calls, FORWARD chain has %d rules, want 2 (no duplicates): %v", len(f.lines), f.lines)
	}
}

func TestEnsureRules_ReplacesStaleInterface(t *testing.T) {
	f := installFakeIptables(t)
	if err := EnsureRules(context.Background(), RuleOptions{WANInterface: "ppp0", Group: 4210}); err != nil {
		t.Fatalf("EnsureRules (ppp0): %v", err)
	}
	if err := EnsureRules(context.Background(), RuleOptions{WANInterface: "eth1", Group: 4210}); err != nil {
		t.Fatalf("EnsureRules (eth1): %v", err)
	}
	for _, l := range f.lines {
		if strings.Contains(l, "ppp0") {
			t.Errorf("stale ppp0 rule still present: %s", l)
		}
	}
	if len(f.lines) != 2 {
		t.Fatalf("FORWARD chain has %d rules, want 2", len(f.lines))
	}
}

func TestRulesInPlace(t *testing.T) {
	f := installFakeIptables(t)
	if RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace before EnsureRules: want false")
	}
	_ = EnsureRules(context.Background(), testOpts())
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace after EnsureRules: want true")
	}

	// The firmware dropped it (an ndm firewall rebuild, say).
	f.lines = nil
	if RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace after the rule vanished: want false")
	}
}

// realForwardLines renders the mangle/FORWARD lines `iptables -S` prints
// for the rules an install of the given length bound leaves behind -- the
// real output spells the open-ended range out (`60:65535`), keeps the
// comment in double quotes and orders the matches its own way, none of
// which the fake chain above reproduces.
func realForwardLines(wan, lengthRange string) []string {
	var out []string
	for _, p := range []struct{ port, window string }{{"443", "2:8"}, {"80", "2:4"}} {
		out = append(out, "-A FORWARD -o "+wan+" -p tcp -m tcp --dport "+p.port+
			" --tcp-flags SYN,ACK ACK -m connbytes --connbytes "+p.window+
			" --connbytes-dir original --connbytes-mode packets -m length --length "+lengthRange+
			" -m comment --comment \""+l7RuleComment+"\" -j NFLOG --nflog-group 4210")
	}
	return out
}

// TestRulesInPlace_RealIptablesOutput feeds RulesInPlace what a router
// really prints, not what the fake chain stores.
func TestRulesInPlace_RealIptablesOutput(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = realForwardLines("eth1", "41:65535")
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Errorf("RulesInPlace = false for the current rules as `iptables -S` prints them: %v", f.lines)
	}
}

// TestRulesInPlace_OldLengthBoundIsStale: a router updated from a build
// that installed `--length 60:` has every rule the new code wants -- same
// interface, port, window and group -- except for the length bound, and
// used to read as "in place" forever, so the old filter was never
// replaced. It must now read as drift, and EnsureRules must fix it.
func TestRulesInPlace_OldLengthBoundIsStale(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = realForwardLines("eth1", "60:65535")
	if RulesInPlace(context.Background(), testOpts()) {
		t.Fatal("RulesInPlace = true for rules with the old --length 60: bound, want false")
	}
	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	for _, l := range f.lines {
		if strings.Contains(l, "--length 60:") {
			t.Errorf("old bound survived EnsureRules: %s", l)
		}
	}
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Errorf("RulesInPlace = false after EnsureRules replaced the old rules: %v", f.lines)
	}
}

// TestRulesInPlace_ExtraRuleOfOursIsStale: a duplicate (or a leftover for
// something no longer wanted) is drift as well -- only EnsureRules
// removes it.
func TestRulesInPlace_ExtraRuleOfOursIsStale(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = append(realForwardLines("eth1", "41:65535"), realForwardLines("eth1", "41:65535")[0])
	if RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace = true with a duplicated rule, want false")
	}
}

// TestRulesInPlace_ForeignNFLOGRuleIsNotOurs: another tool's NFLOG rule in
// the same chain (a different group) must not make our own look drifted --
// that would reinstall on every reconcile tick.
func TestRulesInPlace_ForeignNFLOGRuleIsNotOurs(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = append(realForwardLines("eth1", "41:65535"),
		"-A FORWARD -o eth1 -p tcp -m tcp --dport 443 -m connbytes --connbytes 2:8 --connbytes-dir original --connbytes-mode packets -j NFLOG --nflog-group 210")
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Errorf("RulesInPlace = false because of a foreign NFLOG rule: %v", f.lines)
	}
}

func TestClearRules(t *testing.T) {
	f := installFakeIptables(t)
	_ = EnsureRules(context.Background(), testOpts())
	if err := ClearRules(context.Background()); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	if len(f.lines) != 0 {
		t.Errorf("FORWARD chain still has rules after ClearRules: %v", f.lines)
	}
}

func TestClearRules_LeavesUnrelatedRulesAlone(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = []string{"-A FORWARD -j ACCEPT -m comment --comment some-other-feature"}
	_ = EnsureRules(context.Background(), testOpts())
	_ = ClearRules(context.Background())
	if len(f.lines) != 1 || !strings.Contains(f.lines[0], "some-other-feature") {
		t.Errorf("ClearRules touched an unrelated rule: %v", f.lines)
	}
}

// TestClearRules_UnquotesCommentField is the regression test for the
// same bug FW-01 found and fixed in internal/keenetic/mss.go's own
// clearOurRules: real `iptables -S` wraps a string-valued match argument
// (our own --comment) in double quotes so its own output round-trips as
// a shell command, but iptablesRun execs iptables directly, no shell in
// between -- a field passed through with its quotes still attached is a
// value iptables never actually stored, so the delete silently fails to
// match anything. installFakeIptables's own EnsureRules-then-ClearRules
// round trip (see TestClearRules above) never exercises this, since
// EnsureRules builds its -A args directly rather than round-tripping
// through -S text -- this test feeds a realistic quoted -S line by hand
// instead, bypassing that fake, matching internal/keenetic/mss_test.go's
// own approach.
func TestClearRules_UnquotesCommentField(t *testing.T) {
	origRun, origList := iptablesRun, iptablesListFORWARD
	defer func() { iptablesRun, iptablesListFORWARD = origRun, origList }()

	iptablesListFORWARD = func(_ context.Context, table string) (string, error) {
		if table != ruleTable {
			return "", nil
		}
		return "-A FORWARD -p tcp --dport 443 -o eth1 -m comment --comment \"" + l7RuleComment +
			"\" -m connbytes --connbytes 1: --connbytes-dir original --connbytes-mode packets -j NFLOG --nflog-group 4210\n", nil
	}
	var sent []string
	iptablesRun = func(_ context.Context, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}

	if err := ClearRules(context.Background()); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	if len(sent) != 1 {
		t.Fatalf("iptables calls = %v, want exactly one -D", sent)
	}
	if !strings.HasPrefix(sent[0], "-t mangle -D FORWARD ") {
		t.Errorf("call = %q, want it to delete from mangle/FORWARD", sent[0])
	}
	if strings.Contains(sent[0], `"`) {
		t.Errorf("call = %q, want the comment unquoted -- iptablesRun execs directly, a literal quote in the field never matches what's actually stored", sent[0])
	}
	if !strings.Contains(sent[0], l7RuleComment) {
		t.Errorf("call = %q, want it to still target our rule by comment", sent[0])
	}
}

// TestClearRules_ReportsDeletionFailure is FW-01's other half applied
// here: a failed -D used to be silently discarded
// (`_ = iptablesRun(...)`) instead of surfacing anywhere. ClearRules must
// now return it.
func TestClearRules_ReportsDeletionFailure(t *testing.T) {
	origRun, origList := iptablesRun, iptablesListFORWARD
	defer func() { iptablesRun, iptablesListFORWARD = origRun, origList }()

	iptablesListFORWARD = func(_ context.Context, table string) (string, error) {
		if table != ruleTable {
			return "", nil
		}
		return "-A FORWARD -p tcp --dport 443 -m comment --comment " + l7RuleComment + " -j NFLOG --nflog-group 4210\n", nil
	}
	iptablesRun = func(context.Context, ...string) error { return fmt.Errorf("iptables: exit status 2") }

	if err := ClearRules(context.Background()); err == nil {
		t.Error("ClearRules = nil, want the -D failure to be reported")
	}
}

func TestRuleOptions_ValidateRequiresInterfaceAndGroup(t *testing.T) {
	if EnsureRules(context.Background(), RuleOptions{Group: 1}) == nil {
		t.Error("EnsureRules with no WANInterface: want error")
	}
	if EnsureRules(context.Background(), RuleOptions{WANInterface: "eth1"}) == nil {
		t.Error("EnsureRules with no Group: want error")
	}
}

func TestResolveWANInterface(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	fixture := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"br0\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n" + // a LAN route, not default
		"eth1\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n" // the default route
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	iface, err := ResolveWANInterface(path)
	if err != nil {
		t.Fatalf("ResolveWANInterface: %v", err)
	}
	if iface != "eth1" {
		t.Errorf("ResolveWANInterface = %q, want eth1", iface)
	}
}

func TestResolveWANInterface_NoDefaultRoute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	fixture := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"br0\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	if err := os.WriteFile(path, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveWANInterface(path); err == nil {
		t.Error("ResolveWANInterface with no default route in the fixture: want error")
	}
}

func TestResolveWANInterface_MissingFile(t *testing.T) {
	if _, err := ResolveWANInterface(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("ResolveWANInterface on a missing file: want error")
	}
}

func quicOpts() RuleOptions {
	o := testOpts()
	o.QUIC = true
	return o
}

// realQUICLine is the UDP/443 rule as `iptables -S` prints it.
func realQUICLine(wan string) string {
	return "-A FORWARD -o " + wan + " -p udp -m udp --dport 443 -m connbytes --connbytes 0:3" +
		" --connbytes-dir original --connbytes-mode packets -m length --length 1200:65535" +
		" -m comment --comment \"" + l7RuleComment + "\" -j NFLOG --nflog-group 4210"
}

// TestRuleSpec_SignatureMatchesItsOwnArgs: whatever a spec installs, the
// signature recognises it -- the two are rendered from the same fields, and
// this is the test that notices if that ever stops being true.
func TestRuleSpec_SignatureMatchesItsOwnArgs(t *testing.T) {
	for _, spec := range ruleSpecs(quicOpts()) {
		line := "-A FORWARD " + strings.Join(spec.args(), " ")
		for _, want := range spec.signature() {
			if !strings.Contains(line, want) {
				t.Errorf("rule %q does not contain its own signature part %q", line, want)
			}
		}
	}
}

func TestRuleSpec_SignatureRejectsOtherRules(t *testing.T) {
	udp := ruleSpec{iface: "eth1", proto: "udp", dport: 443, window: quicWindow, minLen: quicMinLength, group: 4210}
	tcp := ruleSpec{iface: "eth1", proto: "tcp", dport: 443, window: "2:8", minLen: tcpMinLength, group: 4210}
	udpLine := "-A FORWARD " + strings.Join(udp.args(), " ")
	tcpLine := "-A FORWARD " + strings.Join(tcp.args(), " ")
	has := func(line string, s ruleSpec) bool {
		for _, w := range s.signature() {
			if !strings.Contains(line, w) {
				return false
			}
		}
		return true
	}
	if has(tcpLine, udp) || has(udpLine, tcp) {
		t.Error("a TCP/443 rule and a UDP/443 rule read as each other")
	}
	other := udp
	other.window = "0:5"
	if has(udpLine, other) {
		t.Error("a different connbytes window reads as the same rule")
	}
}

func TestEnsureRules_QUICAddsTheUDPRule(t *testing.T) {
	f := installFakeIptables(t)
	if err := EnsureRules(context.Background(), quicOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	if len(f.lines) != 3 {
		t.Fatalf("FORWARD chain has %d rules, want 3 (443, 80 and the QUIC rule): %v", len(f.lines), f.lines)
	}
	var udp string
	for _, l := range f.lines {
		if strings.Contains(l, "-p udp") {
			udp = l
		}
	}
	for _, want := range []string{"-o eth1", "--dport 443", "--connbytes 0:3", "--length 1200:", "--nflog-group 4210", "-j NFLOG"} {
		if !strings.Contains(udp, want) {
			t.Errorf("QUIC rule %q lacks %q", udp, want)
		}
	}
	if strings.Contains(udp, "--tcp-flags") {
		t.Errorf("QUIC rule %q carries a TCP flags match", udp)
	}
}

// TestRulesInPlace_FollowsTheQUICMode: switching QUIC on installs the UDP
// rule, switching it off removes it again -- RulesInPlace reads the chain as
// drifted in both directions, so the next reconcile does the work.
func TestRulesInPlace_FollowsTheQUICMode(t *testing.T) {
	f := installFakeIptables(t)
	ctx := context.Background()

	_ = EnsureRules(ctx, testOpts())
	if !RulesInPlace(ctx, testOpts()) {
		t.Fatal("TCP-only rules not in place for TCP-only options")
	}
	if RulesInPlace(ctx, quicOpts()) {
		t.Error("QUIC wanted but no UDP rule installed: want drift")
	}

	_ = EnsureRules(ctx, quicOpts())
	if !RulesInPlace(ctx, quicOpts()) {
		t.Errorf("rules not in place after installing with QUIC: %v", f.lines)
	}
	if RulesInPlace(ctx, testOpts()) {
		t.Error("QUIC switched off but its UDP rule is still installed: want drift")
	}

	_ = EnsureRules(ctx, testOpts())
	if len(f.lines) != 2 {
		t.Errorf("after switching QUIC off the chain has %d rules, want 2: %v", len(f.lines), f.lines)
	}
}

func TestRulesInPlace_RealQUICLine(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = append(realForwardLines("eth1", "41:65535"), realQUICLine("eth1"))
	if !RulesInPlace(context.Background(), quicOpts()) {
		t.Errorf("not in place for the rules as iptables prints them: %v", f.lines)
	}
}

// lockedFakeIptables is fakeIptables for tests that run EnsureRules from
// several goroutines: the chain is guarded, and every run yields so that two
// calls really do interleave their iptables commands.
type lockedFakeIptables struct {
	mu    sync.Mutex
	inner fakeIptables
}

func installLockedFakeIptables(t *testing.T) *lockedFakeIptables {
	t.Helper()
	f := &lockedFakeIptables{}
	origRun, origList := iptablesRun, iptablesListFORWARD
	iptablesRun = func(_ context.Context, args ...string) error {
		runtime.Gosched()
		time.Sleep(200 * time.Microsecond)
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.inner.apply(args)
	}
	iptablesListFORWARD = func(_ context.Context, table string) (string, error) {
		runtime.Gosched()
		f.mu.Lock()
		defer f.mu.Unlock()
		c, err := f.inner.chain(table)
		if err != nil {
			return "", err
		}
		return strings.Join(*c, "\n"), nil
	}
	t.Cleanup(func() { iptablesRun, iptablesListFORWARD = origRun, origList })
	return f
}

// TestEnsureRules_ConcurrentCallsLeaveExactlyTheWantedRules: the capture
// session, the reconcile loop and the bot all reach EnsureRules, which is
// clear-then-add; interleaved, two calls leave duplicated rules behind.
func TestEnsureRules_ConcurrentCallsLeaveExactlyTheWantedRules(t *testing.T) {
	f := installLockedFakeIptables(t)
	opts := RuleOptions{WANInterface: "eth1", Group: 4210, QUIC: true}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = EnsureRules(context.Background(), opts)
		}()
	}
	wg.Wait()

	f.mu.Lock()
	defer f.mu.Unlock()
	if want := len(ruleSpecs(opts)); len(f.inner.lines) != want {
		t.Errorf("the chain holds %d rules after four concurrent EnsureRules calls, want %d:\n%s",
			len(f.inner.lines), want, strings.Join(f.inner.lines, "\n"))
	}
}

// ClearRules goes through the same lock, so it cannot cut an EnsureRules in
// half: after any mix of the two the chain holds either nothing or the whole
// wanted set, never a part of it.
func TestClearRulesAndEnsureRulesNeverLeaveAPartialSet(t *testing.T) {
	f := installLockedFakeIptables(t)
	opts := RuleOptions{WANInterface: "eth1", Group: 4210, QUIC: true}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = EnsureRules(context.Background(), opts) }()
		go func() { defer wg.Done(); _ = ClearRules(context.Background()) }()
	}
	wg.Wait()

	f.mu.Lock()
	defer f.mu.Unlock()
	if n, want := len(f.inner.lines), len(ruleSpecs(opts)); n != 0 && n != want {
		t.Errorf("the chain holds %d rules, want none or all %d:\n%s", n, want, strings.Join(f.inner.lines, "\n"))
	}
}
