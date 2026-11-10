package l7capture

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// --- the table the rules live in -------------------------------------------

// TestEnsureRules_GoesIntoMangleAtTheHeadOfTheChain pins the fix for a capture
// that never saw a packet: on a Keenetic filter/FORWARD has policy DROP and the
// firmware accepts what it allows inside the chain, so a rule appended there is
// only reached by traffic nothing accepted. The rules belong in mangle/FORWARD
// (traversed before filter), ahead of whatever else that chain holds.
func TestEnsureRules_GoesIntoMangleAtTheHeadOfTheChain(t *testing.T) {
	f := installFakeIptables(t)
	foreign := "-A FORWARD -o eth1 -p tcp -m tcp --tcp-flags SYN,SYN SYN -m comment --comment keenetic-xray-mss -j TCPMSS --set-mss 1360"
	f.lines = []string{foreign}
	f.legacy = []string{"-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}

	if err := EnsureRules(context.Background(), quicOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}

	if len(f.lines) != 4 || f.lines[3] != foreign {
		t.Fatalf("mangle/FORWARD = %v, want our 3 rules in front of the rule that was already there", f.lines)
	}
	for i, l := range f.lines[:3] {
		if !strings.Contains(l, "-j NFLOG --nflog-group 4210") {
			t.Errorf("rule %d of mangle/FORWARD is not ours: %s", i+1, l)
		}
	}
	for _, c := range f.sent {
		if !strings.HasPrefix(c, "-t mangle -I FORWARD ") {
			t.Errorf("command %q: want every rule inserted with `-t mangle -I FORWARD <n>`", c)
		}
	}
	if len(f.legacy) != 1 || strings.Contains(f.legacy[0], "NFLOG") {
		t.Errorf("filter/FORWARD = %v, want it untouched", f.legacy)
	}
}

// TestEnsureRules_RemovesWhatAnOlderBuildLeftInFilter: a router updated in place
// has the rules in filter/FORWARD, where they match nothing and would double the
// packets the moment they did. Installing the new ones takes them away -- and
// only them.
func TestEnsureRules_RemovesWhatAnOlderBuildLeftInFilter(t *testing.T) {
	f := installFakeIptables(t)
	accept := "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
	f.legacy = append([]string{accept}, realForwardLines("eth1", "41:65535")...)

	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	if len(f.legacy) != 1 || f.legacy[0] != accept {
		t.Errorf("filter/FORWARD = %v, want only the firmware's own rule left", f.legacy)
	}
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Errorf("rules not in place after the migration: mangle=%v filter=%v", f.lines, f.legacy)
	}
}

// TestRulesInPlace_LeftoverInFilterIsDrift: the right rules in mangle are not
// enough while an older build's copy still sits in filter -- reconcile has to
// run EnsureRules to clean it up.
func TestRulesInPlace_LeftoverInFilterIsDrift(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = realForwardLines("eth1", "41:65535")
	f.legacy = realForwardLines("eth1", "41:65535")
	if RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace = true with our rules still in filter/FORWARD, want false")
	}
	f.legacy = nil
	if !RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace = false with the leftovers gone, want true")
	}
}

// TestRulesInPlace_RulesOnlyInFilterAreNotInPlace: the state of every router
// that has not been migrated yet.
func TestRulesInPlace_RulesOnlyInFilterAreNotInPlace(t *testing.T) {
	f := installFakeIptables(t)
	f.legacy = realForwardLines("eth1", "41:65535")
	if RulesInPlace(context.Background(), testOpts()) {
		t.Error("RulesInPlace = true with the rules only in filter/FORWARD, want false")
	}
}

func TestClearRules_ClearsBothTables(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = realForwardLines("eth1", "41:65535")
	f.legacy = realForwardLines("eth1", "60:65535")
	if err := ClearRules(context.Background()); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	if len(f.lines) != 0 || len(f.legacy) != 0 {
		t.Errorf("rules left behind: mangle=%v filter=%v", f.lines, f.legacy)
	}
}

// TestClearRules_LeavesAForeignNFLOGRuleAlone: the same chain now holds
// HydraRoute's L7 rules (its own group, the same connbytes shape), which an
// earlier, looser definition of "ours" would have deleted.
func TestClearRules_LeavesAForeignNFLOGRuleAlone(t *testing.T) {
	f := installFakeIptables(t)
	hydra := "-A FORWARD -o eth1 -p tcp -m tcp --dport 443 --tcp-flags SYN,ACK ACK -m connbytes --connbytes 2:8 --connbytes-dir original --connbytes-mode packets -m length --length 41:65535 -j NFLOG --nflog-group 210"
	f.lines = append([]string{hydra}, realForwardLines("eth1", "41:65535")...)

	if err := EnsureRules(context.Background(), testOpts()); err != nil {
		t.Fatalf("EnsureRules: %v", err)
	}
	if err := ClearRules(context.Background()); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	if len(f.lines) != 1 || f.lines[0] != hydra {
		t.Errorf("mangle/FORWARD = %v, want only the foreign NFLOG rule left", f.lines)
	}
}

// TestClearRules_FindsOurRuleWithoutTheCommentByItsGroup: an iptables build
// without the comment match installs the rules bare; they are still ours.
func TestClearRules_FindsOurRuleWithoutTheCommentByItsGroup(t *testing.T) {
	f := installFakeIptables(t)
	f.lines = []string{
		"-A FORWARD -o eth1 -p tcp -m tcp --dport 443 -m connbytes --connbytes 2:8 --connbytes-dir original --connbytes-mode packets -j NFLOG --nflog-group 4210",
		"-A FORWARD -o eth1 -p tcp -m tcp --dport 443 -m connbytes --connbytes 2:8 --connbytes-dir original --connbytes-mode packets -j NFLOG --nflog-group 42100",
	}
	if err := ClearRules(context.Background()); err != nil {
		t.Fatalf("ClearRules: %v", err)
	}
	if len(f.lines) != 1 || !strings.Contains(f.lines[0], "--nflog-group 42100") {
		t.Errorf("mangle/FORWARD = %v, want only the rule of group 42100 (not ours) left", f.lines)
	}
}

// --- the kernel's own counters ---------------------------------------------

const countersNFT = `Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts      bytes target     prot opt in     out     source               destination
      12     3600 NFLOG      6    --  *      lte_br0  0.0.0.0/0            0.0.0.0/0            tcp dpt:443 flags:0x12/0x10 connbytes 2:8 connbytes mode packets connbytes direction original length 41:65535 /* keenetic-xray-l7sni */ nflog-group 4210
       0        0 NFLOG      6    --  *      lte_br0  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 flags:0x12/0x10 connbytes 2:4 connbytes mode packets connbytes direction original length 41:65535 /* keenetic-xray-l7sni */ nflog-group 4210
       3     3900 NFLOG      17   --  *      lte_br0  0.0.0.0/0            0.0.0.0/0            udp dpt:443 connbytes 0:3 connbytes mode packets connbytes direction original length 1200:65535 /* keenetic-xray-l7sni */ nflog-group 4210
     500    30000 NFLOG      6    --  *      lte_br0  0.0.0.0/0            0.0.0.0/0            tcp dpt:443 nflog-group 210
     800    52000 TCPMSS     tcp  --  *      lte_br0  0.0.0.0/0            0.0.0.0/0            tcp flags:0x06/0x02 TCPMSS set 1360
`

func TestRuleCounters_ReadsOurRulesOnly(t *testing.T) {
	orig := iptablesListCounters
	defer func() { iptablesListCounters = orig }()
	iptablesListCounters = func(_ context.Context, table string) (string, error) {
		if table != ruleTable {
			return "Chain FORWARD (policy DROP 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination\n", nil
		}
		return countersNFT, nil
	}

	got, err := RuleCounters(context.Background(), 4210)
	if err != nil {
		t.Fatalf("RuleCounters: %v", err)
	}
	want := []RuleStat{
		{Table: "mangle", Iface: "lte_br0", Proto: "tcp", DPort: 443, Packets: 12, Bytes: 3600},
		{Table: "mangle", Iface: "lte_br0", Proto: "tcp", DPort: 80, Packets: 0, Bytes: 0},
		{Table: "mangle", Iface: "lte_br0", Proto: "udp", DPort: 443, Packets: 3, Bytes: 3900},
	}
	if len(got) != len(want) {
		t.Fatalf("RuleCounters = %+v, want %+v (the foreign NFLOG group and the TCPMSS rule are not ours)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Some iptables builds print the protocol column as a name, some as a number.
func TestParseCounterLine_ProtocolAsNameOrNumber(t *testing.T) {
	for _, proto := range []string{"tcp", "6"} {
		line := "  7  420 NFLOG " + proto + " -- * eth1 0.0.0.0/0 0.0.0.0/0 tcp dpt:443 /* keenetic-xray-l7sni */ nflog-group 4210"
		st, ok := parseCounterLine(line, 4210)
		if !ok || st.Proto != "tcp" || st.DPort != 443 || st.Packets != 7 || st.Bytes != 420 || st.Iface != "eth1" {
			t.Errorf("protocol %q: parseCounterLine = %+v, %v", proto, st, ok)
		}
	}
	if _, ok := parseCounterLine("  7  420 NFLOG 1 -- * eth1 0.0.0.0/0 0.0.0.0/0 nflog-group 4210", 4210); ok {
		t.Error("an ICMP rule was read as one of ours")
	}
}

func TestParseCounterLine_GroupNumberIsMatchedWhole(t *testing.T) {
	line := "  7  420 NFLOG tcp -- * eth1 0.0.0.0/0 0.0.0.0/0 tcp dpt:443 nflog-group 42100"
	if _, ok := parseCounterLine(line, 4210); ok {
		t.Error("group 42100 was read as group 4210")
	}
}

func TestRuleCounters_ReportsAnUnlistableCurrentTable(t *testing.T) {
	orig := iptablesListCounters
	defer func() { iptablesListCounters = orig }()
	iptablesListCounters = func(context.Context, string) (string, error) { return "", fmt.Errorf("exit status 4") }
	if _, err := RuleCounters(context.Background(), 4210); err == nil {
		t.Error("RuleCounters = nil error with mangle/FORWARD unreadable, want it reported")
	}
}

// A leftover of an older build still counts packets (none, in practice); it is
// reported with its table so a caller can say what it is.
func TestRuleCounters_LabelsLeftoversWithTheirTable(t *testing.T) {
	orig := iptablesListCounters
	defer func() { iptablesListCounters = orig }()
	iptablesListCounters = func(_ context.Context, table string) (string, error) {
		if table == legacyRuleTable {
			return "    pkts bytes target prot opt in out source destination\n   0  0 NFLOG tcp -- * eth1 0.0.0.0/0 0.0.0.0/0 tcp dpt:443 /* keenetic-xray-l7sni */ nflog-group 4210\n", nil
		}
		return "", nil
	}
	got, err := RuleCounters(context.Background(), 4210)
	if err != nil || len(got) != 1 || got[0].Table != "filter" {
		t.Errorf("RuleCounters = %+v, %v, want one rule labelled filter", got, err)
	}
}
