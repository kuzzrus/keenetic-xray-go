package keenetic

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fakeIptables stubs the four iptables/opkg hooks for one test. present
// is what iptablesPresent reports; forward is the text iptablesListForward
// returns (an `iptables -t mangle -S FORWARD` dump). Every iptablesRun
// call is recorded joined by spaces. opkg install flips present to true
// unless opkgErr is set.
func fakeIptables(t *testing.T, present bool, forward string, opkgErr error) *[]string {
	t.Helper()
	var sent []string
	oRun, oList, oPresent, oOpkg := iptablesRun, iptablesListForward, iptablesPresent, opkgInstallIptables
	iptablesRun = func(_ context.Context, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}
	iptablesListForward = func(_ context.Context) (string, error) { return forward, nil }
	iptablesPresent = func() bool { return present }
	opkgInstallIptables = func(_ context.Context) error {
		if opkgErr != nil {
			return opkgErr
		}
		present = true
		return nil
	}
	t.Cleanup(func() {
		iptablesRun, iptablesListForward, iptablesPresent, opkgInstallIptables = oRun, oList, oPresent, oOpkg
	})
	return &sent
}

func TestSetMSSClamp_AddsOurRule(t *testing.T) {
	sent := fakeIptables(t, true, "-P FORWARD ACCEPT\n", nil)
	if err := SetMSSClamp(context.Background(), 1360); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 {
		t.Fatalf("iptables calls = %v, want one -A", *sent)
	}
	got := (*sent)[0]
	for _, want := range []string{"-A -t mangle FORWARD", "-p tcp --tcp-flags SYN,RST SYN",
		"--comment " + mssComment, "-j TCPMSS --set-mss 1360"} {
		if !strings.Contains(got, want) {
			t.Errorf("rule %q missing %q", got, want)
		}
	}
}

func TestSetMSSClamp_ReplacesStaleValue(t *testing.T) {
	// A previous run left a 1400 rule; asking for 1360 must delete the
	// old one (matched by its live spec) before adding the new.
	dump := "-P FORWARD ACCEPT\n" +
		"-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment " + mssComment +
		" -j TCPMSS --set-mss 1400\n"
	sent := fakeIptables(t, true, dump, nil)
	if err := SetMSSClamp(context.Background(), 1360); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 2 {
		t.Fatalf("calls = %v, want a -D then a -A", *sent)
	}
	if !strings.HasPrefix((*sent)[0], "-t mangle -D FORWARD ") || !strings.Contains((*sent)[0], "--set-mss 1400") {
		t.Errorf("first call = %q, want -D of the stale 1400 rule", (*sent)[0])
	}
	if !strings.Contains((*sent)[1], "-A -t mangle FORWARD") || !strings.Contains((*sent)[1], "--set-mss 1360") {
		t.Errorf("second call = %q, want -A of the 1360 rule", (*sent)[1])
	}
}

func TestSetMSSClamp_ZeroClears(t *testing.T) {
	dump := "-A FORWARD -p tcp -m comment --comment " + mssComment + " -j TCPMSS --set-mss 1360\n"
	sent := fakeIptables(t, true, dump, nil)
	if err := SetMSSClamp(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 1 || !strings.HasPrefix((*sent)[0], "-t mangle -D FORWARD ") {
		t.Fatalf("calls = %v, want a single -D and no -A", *sent)
	}
}

func TestClearMSSClamp_NoIptablesIsNoop(t *testing.T) {
	sent := fakeIptables(t, false, "", nil)
	if err := ClearMSSClamp(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(*sent) != 0 {
		t.Fatalf("calls = %v, want none when iptables is absent", *sent)
	}
}

func TestClearOurRules_LeavesForeignRules(t *testing.T) {
	dump := "-P FORWARD ACCEPT\n" +
		"-A FORWARD -p tcp -j TCPMSS --clamp-mss-to-pmtu\n" + // someone else's
		"-A FORWARD -p tcp -m comment --comment " + mssComment + " -j TCPMSS --set-mss 1360\n"
	sent := fakeIptables(t, true, dump, nil)
	clearOurRules(context.Background())
	if len(*sent) != 1 {
		t.Fatalf("calls = %v, want exactly one -D (ours only)", *sent)
	}
	if !strings.Contains((*sent)[0], mssComment) || !strings.Contains((*sent)[0], "--set-mss 1360") {
		t.Errorf("deleted %q, want only our tagged rule", (*sent)[0])
	}
}

func TestMSSClampInPlace(t *testing.T) {
	dump := "-A FORWARD -p tcp -m comment --comment " + mssComment + " -j TCPMSS --set-mss 1360\n"
	fakeIptables(t, true, dump, nil)
	if !MSSClampInPlace(context.Background(), 1360) {
		t.Error("MSSClampInPlace(1360) = false, want true")
	}
	if MSSClampInPlace(context.Background(), 1400) {
		t.Error("MSSClampInPlace(1400) = true, want false (different value)")
	}
}

func TestEnsureIptables_InstallsWhenMissing(t *testing.T) {
	fakeIptables(t, false, "", nil) // opkg flips present -> true
	if err := EnsureIptables(context.Background()); err != nil {
		t.Fatalf("EnsureIptables = %v, want nil after a successful opkg install", err)
	}
}

func TestEnsureIptables_ReportsInstallFailure(t *testing.T) {
	fakeIptables(t, false, "", fmt.Errorf("opkg: no feed"))
	if err := EnsureIptables(context.Background()); err == nil {
		t.Fatal("EnsureIptables = nil, want an error when opkg install fails")
	}
}
