package adaptiveroute

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeSystem stubs every injectable hook for one test. natDump is what
// iptablesListNAT returns (an `iptables -t nat -S PREROUTING` dump); the
// filter/FORWARD listing comes back empty (see fakeSystemWithForward for a
// test that needs rules there); ipsetOK is what ipsetPresent reports.
// Every iptablesRun/ipsetRun call is recorded, joined by spaces, in its
// own slice. opkg install flips ipsetOK to true unless opkgErr is set.
func fakeSystem(t *testing.T, natDump string, ipsetOK bool, opkgErr error) (sentIptables, sentIpset *[]string) {
	t.Helper()
	return fakeSystemWithForward(t, natDump, "", ipsetOK, opkgErr)
}

// fakeSystemWithForward is fakeSystem with an `iptables -S FORWARD` dump
// too. It also forgets any QUIC-reject problem a previous test left behind
// (the package remembers it between calls) and again when this one ends.
func fakeSystemWithForward(t *testing.T, natDump, forwardDump string, ipsetOK bool, opkgErr error) (sentIptables, sentIpset *[]string) {
	t.Helper()
	var ipt, ips []string
	oRun, oList, oFwd := iptablesRun, iptablesListNAT, iptablesListFORWARD
	oSetRun, oSetOut, oSetPresent, oOpkg := ipsetRun, ipsetOutput, ipsetPresent, opkgInstallIPSet
	setRejectProblem("")

	iptablesRun = func(_ context.Context, args ...string) error {
		ipt = append(ipt, strings.Join(args, " "))
		return nil
	}
	iptablesListNAT = func(_ context.Context) (string, error) { return natDump, nil }
	iptablesListFORWARD = func(_ context.Context) (string, error) { return forwardDump, nil }
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
		iptablesRun, iptablesListNAT, iptablesListFORWARD = oRun, oList, oFwd
		ipsetRun, ipsetOutput, ipsetPresent, opkgInstallIPSet = oSetRun, oSetOut, oSetPresent, oOpkg
		setRejectProblem("")
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

// TestEnsureIPSet_RecoversFromStaleWrongTypeSet is the regression test
// for a real bug found live during a v0.30.x -> v0.31.3 upgrade: a
// router that already had a "keenetic_xray_adaptive" hash:ip set from
// before this project switched to hash:net hit a deterministic "create"
// failure on every subsequent EnsureIPSet call ("-exist" doesn't paper
// over a type mismatch, only an identical redefinition) -- with no
// automatic recovery, adaptive routing was permanently broken on that
// router until someone ran `ipset destroy` by hand. EnsureIPSet must
// clear any REDIRECT rule that still references the old set (ipset
// can't destroy a set a kernel component holds a reference to) and
// destroy+recreate it.
func TestEnsureIPSet_RecoversFromStaleWrongTypeSet(t *testing.T) {
	origIpset, origIptables, origList, origFwd := ipsetRun, iptablesRun, iptablesListNAT, iptablesListFORWARD
	t.Cleanup(func() {
		ipsetRun, iptablesRun, iptablesListNAT, iptablesListFORWARD = origIpset, origIptables, origList, origFwd
	})

	iptablesListNAT = func(context.Context) (string, error) {
		return "-A PREROUTING -i br0 -p tcp -m set --match-set keenetic_xray_adaptive dst " +
			"-m comment --comment " + redirectComment + " -j REDIRECT --to-ports 12080\n", nil
	}
	// The QUIC REJECT references the set too -- it has to go before the
	// destroy as well, or "in use by a kernel component" comes back.
	iptablesListFORWARD = func(context.Context) (string, error) {
		return "-A FORWARD -i br0 -p udp -m set --match-set keenetic_xray_adaptive dst -m udp --dport 443 " +
			"-m comment --comment " + redirectComment + " -j REJECT --reject-with icmp-port-unreachable\n", nil
	}
	var iptablesCalls, ipsetCalls []string
	iptablesRun = func(_ context.Context, args ...string) error {
		iptablesCalls = append(iptablesCalls, strings.Join(args, " "))
		return nil
	}
	firstCreateFailed := false
	ipsetRun = func(_ context.Context, args ...string) error {
		joined := strings.Join(args, " ")
		ipsetCalls = append(ipsetCalls, joined)
		if args[0] == "create" && !firstCreateFailed {
			firstCreateFailed = true
			return fmt.Errorf("Set cannot be created: set with the same name already exists")
		}
		return nil
	}

	if err := EnsureIPSet(context.Background(), "keenetic_xray_adaptive"); err != nil {
		t.Fatalf("EnsureIPSet should recover from a stale wrong-type set, got: %v", err)
	}

	wantIpset := []string{
		"create keenetic_xray_adaptive hash:net timeout 0 -exist", // fails: wrong-type collision
		"destroy keenetic_xray_adaptive",
		"create keenetic_xray_adaptive hash:net timeout 0 -exist", // succeeds
	}
	if len(ipsetCalls) != len(wantIpset) {
		t.Fatalf("ipset calls = %v, want %v", ipsetCalls, wantIpset)
	}
	for i, w := range wantIpset {
		if ipsetCalls[i] != w {
			t.Errorf("ipset call %d = %q, want %q", i, ipsetCalls[i], w)
		}
	}
	if len(iptablesCalls) != 2 ||
		!strings.HasPrefix(iptablesCalls[0], "-t nat -D PREROUTING ") ||
		!strings.HasPrefix(iptablesCalls[1], "-D FORWARD ") {
		t.Errorf("iptables calls = %v, want the stale REDIRECT and the stale QUIC REJECT cleared before destroy", iptablesCalls)
	}
}

func TestEnsureIPSet_GenuineFailureSurfacesAfterRetry(t *testing.T) {
	origIpset, origList, origFwd := ipsetRun, iptablesListNAT, iptablesListFORWARD
	t.Cleanup(func() { ipsetRun, iptablesListNAT, iptablesListFORWARD = origIpset, origList, origFwd })

	iptablesListNAT = func(context.Context) (string, error) { return "", nil }
	iptablesListFORWARD = func(context.Context) (string, error) { return "", nil }
	ipsetRun = func(_ context.Context, args ...string) error {
		if args[0] == "create" {
			return fmt.Errorf("Kernel error received: Unknown error -524")
		}
		return nil
	}

	err := EnsureIPSet(context.Background(), "keenetic_xray_adaptive")
	if err == nil {
		t.Fatal("want an error when create keeps failing even after the recovery attempt")
	}
	if !strings.Contains(err.Error(), "Unknown error -524") {
		t.Errorf("error = %v, want the underlying ipset message preserved", err)
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

// natDumpFor renders the nat/PREROUTING lines EnsureRedirect would leave
// behind for opts, in `iptables -S` form.
func natDumpFor(setName string, port int, iface string) string {
	dump := "-P PREROUTING ACCEPT\n"
	for _, p := range redirectPorts {
		dump += "-A PREROUTING -i " + iface + " -p " + p.proto + " -m set --match-set " + setName +
			" dst -m " + p.proto + " --dport " + strconv.Itoa(p.port) +
			" -m comment --comment " + redirectComment + " -j REDIRECT --to-ports " + strconv.Itoa(port) + "\n"
	}
	return dump
}

// forwardRejectLine is the filter/FORWARD line EnsureRedirect would leave
// behind for the QUIC reject, in `iptables -S` form.
func forwardRejectLine(setName, iface string) string {
	return "-A FORWARD -i " + iface + " -p udp -m set --match-set " + setName + " dst -m udp --dport 443" +
		" -m comment --comment " + redirectComment + " -j REJECT --reject-with icmp-port-unreachable\n"
}

func TestEnsureRedirect_AddsOneRulePerInterfaceProtocolAndPort(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	// One nat -A per redirectPorts entry, then the one filter -I for QUIC.
	if len(*sent) != len(redirectPorts)+1 {
		t.Fatalf("calls = %v, want one per redirectPorts entry (%d) plus the QUIC reject", *sent, len(redirectPorts))
	}
	for i, p := range redirectPorts {
		got := (*sent)[i]
		if !strings.HasPrefix(got, "-t nat -A PREROUTING -i br0 -p "+p.proto+" ") {
			t.Errorf("call %d = %q, wrong lead-in for %s", i, got, p.proto)
		}
		for _, want := range []string{
			"--match-set susanin_ok dst", "--dport " + strconv.Itoa(p.port),
			"--comment " + redirectComment, "-j REDIRECT --to-ports 12345",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("call %d = %q, missing %q", i, got, want)
			}
		}
	}
}

// TestEnsureRedirect_RedirectsOnlyTCPWebPorts pins the actual policy, not
// just the rule count: anything outside TCP web traffic must not be
// redirected at all. Port-blind, because a wrongly-promoted address used to
// have its entire non-web traffic (a torrent transfer, in the incident that
// prompted this) pulled through the tunnel; and never UDP, because a UDP
// REDIRECT into xray's dokodemo-door loses the datagram's destination -- the
// QUIC black hole this package now turns into an instant reject instead.
// See redirectPorts' doc comment.
func TestEnsureRedirect_RedirectsOnlyTCPWebPorts(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	var nat []string
	for _, c := range *sent {
		if strings.HasPrefix(c, "-t nat ") {
			nat = append(nat, c)
		}
	}
	joined := strings.Join(nat, "\n")
	for _, want := range []string{"-p tcp", "--dport 80", "--dport 443"} {
		if !strings.Contains(joined, want) {
			t.Errorf("nat rules = %q, missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "-p udp") {
		t.Errorf("nat rules = %q, must not redirect UDP", joined)
	}
	// Every rule must carry a --dport; a port-blind one is the bug.
	for i, got := range *sent {
		if !strings.Contains(got, "--dport ") {
			t.Errorf("call %d = %q, has no --dport -- would match every port", i, got)
		}
	}
}

// TestEnsureRedirect_InstallsQUICRejectAtTopOfForward pins the exact QUIC
// rule: inserted at position 1 (so no earlier ACCEPT lets a flow through),
// scoped to the LAN interface and to the set, UDP 443 only, answered with an
// ICMP port-unreachable.
func TestEnsureRedirect_InstallsQUICRejectAtTopOfForward(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	want := "-I FORWARD 1 -i br0 -p udp -m set --match-set susanin_ok dst --dport 443 " +
		"-m comment --comment " + redirectComment + " -j REJECT --reject-with icmp-port-unreachable"
	if last := (*sent)[len(*sent)-1]; last != want {
		t.Errorf("last call = %q\nwant        %q", last, want)
	}
	if got := QUICRejectProblem(); got != "" {
		t.Errorf("QUICRejectProblem = %q, want empty after a clean install", got)
	}
}

func TestEnsureRedirect_MultipleInterfaces(t *testing.T) {
	sent, _ := fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0", "br1"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	n := len(redirectPorts)
	if len(*sent) != 2*n+2 {
		t.Fatalf("calls = %v, want 2 interfaces x %d REDIRECT rules + 2 QUIC rejects", *sent, n)
	}
	if !strings.Contains((*sent)[0], "-i br0 ") || !strings.Contains((*sent)[n], "-i br1 ") {
		t.Errorf("calls = %v, want br0's REDIRECT rules before br1's", *sent)
	}
	if !strings.HasPrefix((*sent)[2*n], "-I FORWARD 1 -i br0 ") || !strings.HasPrefix((*sent)[2*n+1], "-I FORWARD 1 -i br1 ") {
		t.Errorf("calls = %v, want one QUIC reject per interface after the REDIRECT rules", *sent)
	}
}

func TestEnsureRedirect_ReplacesStaleRule(t *testing.T) {
	// A previous run left a REDIRECT for port 9999 and a QUIC reject on a
	// different interface; asking for 12345 on br0 must delete both (matched
	// by their live spec) before adding the new rules.
	nat := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 9999\n"
	fwd := "-P FORWARD ACCEPT\n" + forwardRejectLine("susanin_ok", "br9")
	sent, _ := fakeSystemWithForward(t, nat, fwd, true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2+len(redirectPorts)+1 {
		t.Fatalf("calls = %v, want -D of the stale REDIRECT, -D of the stale reject, %d -A, one -I", *sent, len(redirectPorts))
	}
	if !strings.HasPrefix((*sent)[0], "-t nat -D PREROUTING ") || !strings.Contains((*sent)[0], "--to-ports 9999") {
		t.Errorf("first call = %q, want -D of the stale 9999 rule", (*sent)[0])
	}
	if !strings.HasPrefix((*sent)[1], "-D FORWARD ") || !strings.Contains((*sent)[1], "-i br9 ") {
		t.Errorf("second call = %q, want -D of the stale br9 reject", (*sent)[1])
	}
	if !strings.HasPrefix((*sent)[2], "-t nat -A PREROUTING ") || !strings.Contains((*sent)[2], "--to-ports 12345") {
		t.Errorf("third call = %q, want -A of the new 12345 rule", (*sent)[2])
	}
}

// TestEnsureRedirect_RemovesLegacyUDPRedirect is the upgrade path off every
// version before 2026-10-25: those installed a UDP 443 REDIRECT next to the
// two TCP ones, and the next EnsureRedirect must delete it -- not leave the
// QUIC black hole running alongside the new reject -- and not add it again.
func TestEnsureRedirect_RemovesLegacyUDPRedirect(t *testing.T) {
	nat := "-P PREROUTING ACCEPT\n"
	for _, p := range []struct {
		proto string
		port  int
	}{{"tcp", 80}, {"tcp", 443}, {"udp", 443}} {
		nat += "-A PREROUTING -i br0 -p " + p.proto + " -m set --match-set susanin_ok dst -m " + p.proto +
			" --dport " + strconv.Itoa(p.port) + " -m comment --comment " + redirectComment +
			" -j REDIRECT --to-ports 12345\n"
	}
	sent, _ := fakeSystemWithForward(t, nat, "-P FORWARD ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	deletedUDP, addedUDP := false, false
	for _, c := range *sent {
		if strings.HasPrefix(c, "-t nat -D PREROUTING ") && strings.Contains(c, "-p udp") {
			deletedUDP = true
		}
		if strings.HasPrefix(c, "-t nat -A ") && strings.Contains(c, "-p udp") {
			addedUDP = true
		}
	}
	if !deletedUDP {
		t.Errorf("calls = %v, want the legacy UDP REDIRECT deleted", *sent)
	}
	if addedUDP {
		t.Errorf("calls = %v, must not add a UDP REDIRECT again", *sent)
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
	// REDIRECT: one commented -A that fails immediately, no further rule
	// attempted (add() returns on first error), then one plain -A per
	// redirectPorts entry. QUIC reject: a commented -I that fails, then a
	// plain one that succeeds.
	if len(sent) != 1+len(redirectPorts)+2 {
		t.Fatalf("calls = %v, want [failed commented -A, %d plain -A, failed commented -I, plain -I]", sent, len(redirectPorts))
	}
	if !strings.Contains(sent[0], "-m comment") {
		t.Errorf("first call = %q, want the commented attempt", sent[0])
	}
	for _, c := range sent[1 : 1+len(redirectPorts)] {
		if strings.Contains(c, "-m comment") {
			t.Errorf("retry call = %q, should not carry -m comment", c)
		}
	}
	rejectTry, rejectRetry := sent[1+len(redirectPorts)], sent[2+len(redirectPorts)]
	if !strings.HasPrefix(rejectTry, "-I FORWARD 1 ") || !strings.Contains(rejectTry, "-m comment") {
		t.Errorf("reject first attempt = %q, want the commented -I", rejectTry)
	}
	if !strings.HasPrefix(rejectRetry, "-I FORWARD 1 ") || strings.Contains(rejectRetry, "-m comment") {
		t.Errorf("reject retry = %q, want the plain -I", rejectRetry)
	}
	if got := QUICRejectProblem(); got != "" {
		t.Errorf("QUICRejectProblem = %q, want empty: the retry installed it", got)
	}
}

// TestEnsureRedirect_RejectFailureIsNotFatal: a router whose iptables has no
// REJECT target still gets its TCP REDIRECT -- QUIC to promoted addresses
// then behaves as it did before the reject existed, nothing worse -- and the
// reason is kept for the status lines.
func TestEnsureRedirect_RejectFailureIsNotFatal(t *testing.T) {
	nat := natDumpFor("susanin_ok", 12345, "br0")
	fakeSystemWithForward(t, nat, "-P FORWARD ACCEPT\n", true, nil)
	var sent []string
	iptablesRun = func(_ context.Context, args ...string) error {
		joined := strings.Join(args, " ")
		sent = append(sent, joined)
		if strings.Contains(joined, "-j REJECT") {
			return fmt.Errorf("exit status 2: iptables: No chain/target/match by that name.")
		}
		return nil
	}
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatalf("EnsureRedirect = %v, want nil: only the optional QUIC reject failed", err)
	}
	if got := QUICRejectProblem(); !strings.Contains(got, "No chain/target/match") {
		t.Errorf("QUICRejectProblem = %q, want the iptables complaint", got)
	}
	natAdds := 0
	for _, c := range sent {
		if strings.HasPrefix(c, "-t nat -A ") {
			natAdds++
		}
	}
	if natAdds != len(redirectPorts) {
		t.Errorf("nat -A calls = %d, want %d: the REDIRECT must be in place regardless", natAdds, len(redirectPorts))
	}
	// And that is not drift: the reconcile loop must not rebuild a working
	// REDIRECT every two minutes chasing a rule this router cannot hold.
	if !RedirectInPlace(context.Background(), opts) {
		t.Error("RedirectInPlace = false, want true while the reject is known to be unavailable")
	}
}

func TestEnsureRedirect_SuccessForgetsEarlierRejectProblem(t *testing.T) {
	fakeSystem(t, "-P PREROUTING ACCEPT\n", true, nil)
	setRejectProblem("an earlier failure")
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if err := EnsureRedirect(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if got := QUICRejectProblem(); got != "" {
		t.Errorf("QUICRejectProblem = %q, want it cleared by a successful install", got)
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
	fakeSystemWithForward(t, natDumpFor("susanin_ok", 12345, "br0"), "-P FORWARD ACCEPT\n"+forwardRejectLine("susanin_ok", "br0"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if !RedirectInPlace(context.Background(), opts) {
		t.Error("want true: every rule is live")
	}
	if !QUICRejectInPlace(context.Background(), opts) {
		t.Error("QUICRejectInPlace = false, want true: the reject is live")
	}
}

// TestRedirectInPlace_PortBlindRuleIsDrift covers the upgrade path off a
// pre-2026-09-16 install: a surviving rule with no --dport at all
// redirects every port and must be treated as drift so reconcile
// replaces it, not accepted as "close enough".
func TestRedirectInPlace_PortBlindRuleIsDrift(t *testing.T) {
	dump := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -j REDIRECT --to-ports 12345\n"
	fakeSystemWithForward(t, dump, forwardRejectLine("susanin_ok", "br0"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: the old port-blind rules are not what we want now")
	}
}

func TestRedirectInPlace_MissingRuleIsDrift(t *testing.T) {
	// Only tcp/80 survived (firmware flushed the rest, or it was never
	// added) -- must report drift, not a partial pass.
	dump := "-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst --dport 80 -j REDIRECT --to-ports 12345\n"
	fakeSystemWithForward(t, dump, forwardRejectLine("susanin_ok", "br0"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: the tcp/443 rule is missing")
	}
}

func TestRedirectInPlace_WrongPortIsDrift(t *testing.T) {
	fakeSystemWithForward(t, natDumpFor("susanin_ok", 1, "br0"), forwardRejectLine("susanin_ok", "br0"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: live rules redirect to a different port")
	}
}

// TestRedirectInPlace_MissingQUICRejectIsDrift: the firmware rebuilt the
// filter table (ndm does, on many events) and took our reject with it while
// the nat REDIRECT survived -- the reconcile loop has to notice.
func TestRedirectInPlace_MissingQUICRejectIsDrift(t *testing.T) {
	fakeSystemWithForward(t, natDumpFor("susanin_ok", 12345, "br0"), "-P FORWARD ACCEPT\n", true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: the QUIC reject is gone")
	}
}

func TestRedirectInPlace_QUICRejectOnWrongInterfaceIsDrift(t *testing.T) {
	fakeSystemWithForward(t, natDumpFor("susanin_ok", 12345, "br0"), forwardRejectLine("susanin_ok", "br1"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: the reject is on another interface")
	}
}

func TestRedirectInPlace_QUICRejectUnavailableIsNotDrift(t *testing.T) {
	fakeSystemWithForward(t, natDumpFor("susanin_ok", 12345, "br0"), "-P FORWARD ACCEPT\n", true, nil)
	setRejectProblem("iptables: No chain/target/match by that name.")
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if !RedirectInPlace(context.Background(), opts) {
		t.Error("want true: this router was found unable to hold the reject, demanding it is a rebuild loop")
	}
}

// TestRedirectInPlace_LegacyUDPRedirectIsDrift: a UDP REDIRECT of ours
// surviving next to the right rules (an older process re-adding it, or a
// daemon that was not restarted after the upgrade) is the QUIC black hole
// itself; reconcile has to get rid of it.
func TestRedirectInPlace_LegacyUDPRedirectIsDrift(t *testing.T) {
	nat := natDumpFor("susanin_ok", 12345, "br0") +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -m udp --dport 443 -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 12345\n"
	fakeSystemWithForward(t, nat, forwardRejectLine("susanin_ok", "br0"), true, nil)
	opts := RedirectOptions{SetName: "susanin_ok", Port: 12345, LANInterfaces: []string{"br0"}}
	if RedirectInPlace(context.Background(), opts) {
		t.Error("want false: a leftover UDP 443 REDIRECT must be cleared")
	}
}

func TestRedirectInPlace_InvalidOptions(t *testing.T) {
	fakeSystem(t, "", true, nil)
	if RedirectInPlace(context.Background(), RedirectOptions{}) {
		t.Error("want false for empty/invalid options")
	}
	if QUICRejectInPlace(context.Background(), RedirectOptions{}) {
		t.Error("QUICRejectInPlace: want false for empty/invalid options")
	}
}

func TestClearRedirect(t *testing.T) {
	nat := "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -i br0 -p tcp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -i br0 -p udp -m set --match-set susanin_ok dst -m comment --comment " +
		redirectComment + " -j REDIRECT --to-ports 12345\n" +
		"-A PREROUTING -j DNAT --to-destination 10.0.0.1\n" // not ours -- must survive
	fwd := "-P FORWARD ACCEPT\n" +
		forwardRejectLine("susanin_ok", "br0") +
		// l7sni's NFLOG rule and somebody else's REJECT live in the same chain:
		"-A FORWARD -o eth2.4 -p tcp -m tcp --dport 443 -m comment --comment keenetic-xray-l7sni -j NFLOG --nflog-group 4210\n" +
		"-A FORWARD -i br0 -p tcp -j REJECT --reject-with tcp-reset\n"
	sent, _ := fakeSystemWithForward(t, nat, fwd, true, nil)
	if err := ClearRedirect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 3 {
		t.Fatalf("calls = %v, want exactly our 2 nat rules and our 1 reject deleted", *sent)
	}
	for _, c := range (*sent)[:2] {
		if !strings.HasPrefix(c, "-t nat -D PREROUTING ") {
			t.Errorf("call = %q, want a nat -D", c)
		}
	}
	last := (*sent)[2]
	if !strings.HasPrefix(last, "-D FORWARD ") || !strings.Contains(last, "-j REJECT --reject-with icmp-port-unreachable") {
		t.Errorf("call = %q, want a -D of our QUIC reject", last)
	}
	if strings.Contains(last, "NFLOG") || strings.Contains(last, "tcp-reset") {
		t.Errorf("call = %q, deleted somebody else's rule", last)
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

// TestClearRedirect_UnquotesTheComment: `iptables -S` wraps a string value
// in double quotes whenever it holds more than letters, digits and a few
// punctuation marks, and a -D built from the listed fields as they stand
// would carry those quotes into a value iptables never stored -- the delete
// silently matches nothing. (The bug internal/keenetic's MSS clamp had.)
func TestClearRedirect_UnquotesTheComment(t *testing.T) {
	fwd := "-A FORWARD -i br0 -p udp -m set --match-set susanin_ok dst -m udp --dport 443 " +
		"-m comment --comment \"" + redirectComment + "\" -j REJECT --reject-with icmp-port-unreachable\n"
	sent, _ := fakeSystemWithForward(t, "", fwd, true, nil)
	if err := ClearRedirect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 {
		t.Fatalf("calls = %v, want one -D", *sent)
	}
	if strings.Contains((*sent)[0], "\"") {
		t.Errorf("call = %q, the comment must reach iptables without its quotes", (*sent)[0])
	}
}

func TestRejectSpecs_OnePerInterface(t *testing.T) {
	specs := rejectSpecs(RedirectOptions{SetName: "s", Port: 1, LANInterfaces: []string{"br0", "br1"}}, true)
	if len(specs) != 2 {
		t.Fatalf("specs = %v, want one per interface", specs)
	}
	for i, iface := range []string{"br0", "br1"} {
		got := strings.Join(specs[i], " ")
		for _, want := range []string{"-i " + iface + " ", "-p udp", "--match-set s dst", "--dport 443", "-j REJECT", "--reject-with icmp-port-unreachable"} {
			if !strings.Contains(got, want) {
				t.Errorf("spec %d = %q, missing %q", i, got, want)
			}
		}
	}
	if plain := strings.Join(rejectSpecs(RedirectOptions{SetName: "s", Port: 1, LANInterfaces: []string{"br0"}}, false)[0], " "); strings.Contains(plain, "comment") {
		t.Errorf("spec without comment = %q, still names the comment match", plain)
	}
}

func TestIsOurRejectRule(t *testing.T) {
	ours := []string{
		"-A FORWARD -i br0 -p udp -m set --match-set x dst -m udp --dport 443 -m comment --comment keenetic-xray-adaptive -j REJECT --reject-with icmp-port-unreachable",
		// a build without the comment match: the signature alone
		"-A FORWARD -i br0 -p udp -m set --match-set x dst -m udp --dport 443 -j REJECT --reject-with icmp-port-unreachable",
	}
	for _, l := range ours {
		if !isOurRejectRule(l) {
			t.Errorf("isOurRejectRule(%q) = false, want true", l)
		}
	}
	notOurs := []string{
		"-A FORWARD -o eth2.4 -p tcp -m tcp --dport 443 -m comment --comment keenetic-xray-l7sni -j NFLOG --nflog-group 4210",
		"-A FORWARD -i br0 -p tcp -j REJECT --reject-with tcp-reset",
		"-A FORWARD -i br0 -p udp --dport 53 -j REJECT",
		"-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
	}
	for _, l := range notOurs {
		if isOurRejectRule(l) {
			t.Errorf("isOurRejectRule(%q) = true, want false", l)
		}
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
