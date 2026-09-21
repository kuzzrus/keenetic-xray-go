package l7capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testOpts() RuleOptions {
	return RuleOptions{WANInterface: "eth1", Group: 4210}
}

// fakeIptables gives EnsureRules/ClearRules/RulesInPlace an in-memory
// FORWARD chain instead of a real iptables binary -- same "fake exec
// layer via the package's own injectable vars" approach internal/
// adaptiveroute's own tests use.
type fakeIptables struct {
	lines []string
}

func installFakeIptables(t *testing.T) *fakeIptables {
	t.Helper()
	f := &fakeIptables{}
	origRun, origList := iptablesRun, iptablesListFORWARD
	iptablesRun = func(_ context.Context, args ...string) error {
		return f.apply(args)
	}
	iptablesListFORWARD = func(context.Context) (string, error) {
		return strings.Join(f.lines, "\n"), nil
	}
	t.Cleanup(func() { iptablesRun, iptablesListFORWARD = origRun, origList })
	return f
}

func (f *fakeIptables) apply(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no args")
	}
	switch args[0] {
	case "-A":
		f.lines = append(f.lines, "-A "+strings.Join(args[1:], " "))
		return nil
	case "-D":
		want := "-A " + strings.Join(args[1:], " ")
		for i, l := range f.lines {
			if l == want {
				f.lines = append(f.lines[:i], f.lines[i+1:]...)
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

	iptablesListFORWARD = func(context.Context) (string, error) {
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

	iptablesListFORWARD = func(context.Context) (string, error) {
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
