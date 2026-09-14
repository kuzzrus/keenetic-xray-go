package adaptiveroute

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// fakeSystem stubs every injectable hook for one test. natDump is what
// iptablesListNAT returns (an `iptables -t nat -S PREROUTING` dump);
// ipsetOK is what ipsetPresent reports. Every iptablesRun/ipsetRun call
// is recorded, joined by spaces, in its own slice. opkg install flips
// ipsetOK to true unless opkgErr is set.
func fakeSystem(t *testing.T, natDump string, ipsetOK bool, opkgErr error) (sentIptables, sentIpset *[]string) {
	t.Helper()
	var ipt, ips []string
	oRun, oList := iptablesRun, iptablesListNAT
	oSetRun, oSetOut, oSetPresent, oOpkg := ipsetRun, ipsetOutput, ipsetPresent, opkgInstallIPSet

	iptablesRun = func(_ context.Context, args ...string) error {
		ipt = append(ipt, strings.Join(args, " "))
		return nil
	}
	iptablesListNAT = func(_ context.Context) (string, error) { return natDump, nil }
	ipsetRun = func(_ context.Context, args ...string) error {
		ips = append(ips, strings.Join(args, " "))
		return nil
	}
	ipsetOutput = func(_ context.Context, args ...string) (string, error) {
		ips = append(ips, strings.Join(args, " "))
		return "", nil
	}
	ipsetPresent = func() bool { return ipsetOK }
	opkgInstallIPSet = func(_ context.Context) error {
		if opkgErr != nil {
			return opkgErr
		}
		ipsetOK = true
		return nil
	}
	t.Cleanup(func() {
		iptablesRun, iptablesListNAT = oRun, oList
		ipsetRun, ipsetOutput, ipsetPresent, opkgInstallIPSet = oSetRun, oSetOut, oSetPresent, oOpkg
	})
	return &ipt, &ips
}

func TestEnsureIPSet(t *testing.T) {
	_, sent := fakeSystem(t, "", true, nil)
	if err := EnsureIPSet(context.Background(), "susanin_ok"); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || (*sent)[0] != "create susanin_ok hash:net timeout 0 -exist" {
		t.Errorf("calls = %v", *sent)
	}
}

func TestAddRemoveFlushIP(t *testing.T) {
	_, sent := fakeSystem(t, "", true, nil)
	ctx := context.Background()
	if err := AddIP(ctx, "s", "1.2.3.4", 0); err != nil {
		t.Fatal(err)
	}
	if err := AddIP(ctx, "s", "5.6.7.8", 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := RemoveIP(ctx, "s", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	// hash:net accepts a CIDR block exactly like a bare IP -- AddIP
	// doesn't need to (and doesn't) treat the two differently.
	if err := AddIP(ctx, "s", "9.9.9.0/24", 0); err != nil {
		t.Fatal(err)
	}
	if err := Flush(ctx, "s"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"add s 1.2.3.4 -exist",
		"add s 5.6.7.8 -exist timeout 90",
		"del s 1.2.3.4 -exist",
		"add s 9.9.9.0/24 -exist",
		"flush s",
	}
	if len(*sent) != len(want) {
		t.Fatalf("calls = %v, want %v", *sent, want)
	}
	for i, w := range want {
		if (*sent)[i] != w {
			t.Errorf("call %d = %q, want %q", i, (*sent)[i], w)
		}
	}
}

func TestMembers(t *testing.T) {
	oOut := ipsetOutput
	t.Cleanup(func() { ipsetOutput = oOut })
	ipsetOutput = func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") != "list susanin_ok -output save" {
			t.Errorf("unexpected ipset args: %v", args)
		}
		return "create susanin_ok hash:net family inet hashsize 1024 maxelem 65536\n" +
			"add susanin_ok 1.2.3.4\n" +
			"add susanin_ok 5.6.7.8\n", nil
	}
	got, err := Members(context.Background(), "susanin_ok")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4", "5.6.7.8"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Members = %v, want %v", got, want)
	}
}

func TestEnsureRedirect_AddsOneRulePerInterfaceAndProtocol(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("calls = %v, want 2 (tcp + udp)", *sent)
	}
	for i, proto := range []string{"tcp", "udp"} {
		got := (*sent)[i]
		if !strings.HasPrefix(got, "-t nat -A PREROUTING -i br0 -p "+proto+" ") {
			t.Errorf("call %d = %q, wrong lead-in for %s", i, got, proto)
		}
		for _, want := range []string{
			"--match-set susanin_ok dst", "--comment " + redirectComment,
			"-j REDIRECT --to-ports 12345",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("call %d = %q, missing %q", i, got, want)
			}
		}
	}
}

func TestEnsureRedirect_MultipleInterfaces(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0", "br1"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 4 {
		t.Fatalf("calls = %v, want 4 (2 interfaces x 2 protocols)", *sent)
	}
	if !strings.Contains((*sent)[0], "-i br0 ") || !strings.Contains((*sent)[2], "-i br1 ") {
		t.Errorf("calls = %v, want br0's pair before br1's", *sent)
	}
}

func TestEnsureRedirect_ReplacesStaleRule(t *testing.T) {
	// A previous run left a rule for port 9999; asking for 12345 must
	// delete the old one (matched by its live spec) before adding new.
	dump := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 9999\n"
	sent, _ := fakeSystem(t, dump, true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 3 {
		t.Fatalf("calls = %v, want a -D of the stale rule then 2 -A calls", *sent)
	}
	if !strings.HasPrefix((*sent)[0], "-t nat -D PREROUTING ") || !strings.Contains((*sent)[0], "--to-ports 9999") {
		t.Errorf("first call = %q, want -D of the stale 9999 rule", (*sent)[0])
	}
	if !strings.HasPrefix((*sent)[1], "-t nat -A PREROUTING ") || !strings.Contains((*sent)[1], "--to-ports 12345") {
		t.Errorf("second call = %q, want -A of the new 12345 rule", (*sent)[1])
	}
}

func TestEnsureRedirect_FallsBackWithoutCommentMatch(t *testing.T) {
	fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	var sent []string
	iptablesRun = func(_ context.Context, args ...string) error {
		joined := strings.Join(args, " ")
		sent = append(sent, joined)
		if strings.Contains(joined, "-m comment") {
			return fmt.Errorf("exit status 2")
		}
		return nil
	}
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatalf("EnsureRedirect = %v, want nil after the no-comment retry", err)
	}
	// First attempt: one commented -A that fails immediately, no second
	// rule attempted (add() returns on first error). Retry: two plain
	// -A calls that both succeed.
	if len(sent) != 3 {
		t.Fatalf("calls = %v, want [failed commented -A, plain -A, plain -A]", sent)
	}
	if !strings.Contains(sent[0], "-m comment") {
		t.Errorf("first call = %q, want the commented attempt", sent[0])
	}
	for _, c := range sent[1:] {
		if strings.Contains(c, "-m comment") {
			t.Errorf("retry call = %q, should not carry -m comment", c)
		}
	}
}

func TestEnsureRedirect_Validation(t *testing.T) {
	fakeSystem(t, "", true, nil)
	ctx := context.Background()
	cases := []RedirectOptions{
		{SetName: "", Port: 1, LANInterfaces: []string{"br0"}},
		{SetName: "s", Port: 0, LANInterfaces: []string{"br0"}},
		{SetName: "s", Port: 70000, LANInterfaces: []string{"br0"}},
		{SetName: "s", Port: 1, LANInterfaces: nil},
	}
	for _, c := range cases {
		if err := EnsureRedirect(ctx, c); err == nil {
			t.Errorf("EnsureRedirect(%+v) should have failed validation", c)
		}
	}
}

func TestRedirectInPlace(t *testing.T) {
	dump := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 12345\n"
	fakeSystem(t, dump, true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if !RedirectInPlace(context.Background(), opts) {
		t.Error("want true: both rules are live")
	}
}

func TestRedirectInPlace_MissingProtocolIsDrift(t *testing.T) {
	// Only the tcp half survived (firmware flushed the other, or it was
	// never added) -- must report drift, not a partial pass.
	dump := "-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 12345\n"
	fakeSystem(t, dump, true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: the udp rule is missing")
	}
}

func TestRedirectInPlace_WrongPortIsDrift(t *testing.T) {
	dump := "-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 1\n" +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 1\n"
	fakeSystem(t, dump, true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: live rules redirect to a different port")
	}
}

func TestRedirectInPlace_InvalidOptions(t *testing.T) {
	fakeSystem(t, "", true, nil)
	if RedirectInPlace(context.Background(), RedirectOptions{}) {
		t.Error("want false for empty/invalid options")
	}
}

func TestClearRedirect(t *testing.T) {
	dump := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -j DNAT --to-destination 10.0.0.1\n" // not ours -- must survive
	sent, _ := fakeSystem(t, dump, true, nil)
	if err := ClearRedirect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("calls = %v, want exactly our 2 rules deleted, not the DNAT one", *sent)
	}
	for _, c := range *sent {
		if !strings.HasPrefix(c, "-t nat -D PREROUTING ") {
			t.Errorf("call = %q, want a -D", c)
		}
	}
}

func TestClearRedirect_NoRulesIsNoop(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	if err := ClearRedirect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 0 {
		t.Errorf("calls = %v, want none", *sent)
	}
}

func TestIPSetPresent_And_EnsureIPSetTool(t *testing.T) {
	fakeSystem(t, "", false, nil)
	if IPSetPresent() {
		t.Fatal("want not present")
	}
	if err := EnsureIPSetTool(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !IPSetPresent() {
		t.Error("want present after a successful opkg install")
	}
}

func TestEnsureIPSetTool_OpkgFailure(t *testing.T) {
	fakeSystem(t, "", false, fmt.Errorf("opkg: no feed"))
	if err := EnsureIPSetTool(context.Background()); err == nil {
		t.Fatal("want an error when opkg install fails")
	}
}

func TestEnsureIPSetTool_AlreadyPresentSkipsOpkg(t *testing.T) {
	_, sent := fakeSystem(t, "", true, nil)
	oOpkg := opkgInstallIPSet
	called := false
	opkgInstallIPSet = func(context.Context) error { called = true; return oOpkg(context.Background()) }
	t.Cleanup(func() { opkgInstallIPSet = oOpkg })
	if err := EnsureIPSetTool(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("opkg install should not run when ipset is already present")
	}
	_ = sent
}
