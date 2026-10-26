package classifier

import (
	"sort"
	"testing"
	"time"
)

// --- tier and reason on every Action ---

func TestActionReasons_FastDetectors(t *testing.T) {
	cases := []struct {
		name   string
		flow   Flow
		reason string
	}{
		{"silent SYN", tcpFlow("SYN_SENT", 2, 0, 0, 0), ReasonSilentSYN},
		{"closed without a reply", tcpFlow("CLOSE", 1, 0, 2, 255), ReasonClosedNoReply},
		{"QUIC without a reply", udpFlow(443, 3, 0, 0, 0), ReasonQUICNoReply},
	}
	for _, c := range cases {
		cfg, state, now := testConfig(), NewState(), time.Now()
		got := ClrFast(cfg, state, []Flow{c.flow}, now)
		if len(got) != 2 {
			t.Fatalf("%s: actions = %+v, want a promotion", c.name, got)
		}
		add := got[0]
		if add.Kind != ActionAddIP || add.Tier != TierProbation || add.Reason != c.reason {
			t.Errorf("%s: AddIP = %+v, want a %s probation with reason %q", c.name, add, TierProbation, c.reason)
		}
		// The probation names the flow that tripped it -- that is how the
		// list screen can say which LAN client it was.
		if add.Flow.Src != lanSrc || add.Flow.DPort != c.flow.DPort || add.Flow.Proto != c.flow.Proto {
			t.Errorf("%s: AddIP.Flow = %+v, want the triggering flow", c.name, add.Flow)
		}
	}
}

func TestActionReasons_SoftDetectors(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	got := ClrSoft(cfg, state, NewRateCache(), []Flow{tcpFlow("ESTABLISHED", 5, 1000, 2, 255)}, now)
	if len(got) != 2 || got[0].Tier != TierProbation || got[0].Reason != ReasonTCPStall {
		t.Fatalf("stall: actions = %+v, want a probation with reason %q", got, ReasonTCPStall)
	}

	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 8, 0, 1, 0)}, t0)
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 12, 0, 1, 0)}, t0.Add(2*time.Second))
	got = ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 16, 0, 1, 0)}, t0.Add(7*time.Second))
	if len(got) != 2 || got[0].Tier != TierProbation || got[0].Reason != ReasonLateStall {
		t.Fatalf("late stall: actions = %+v, want a probation with reason %q", got, ReasonLateStall)
	}
}

func TestActionReasons_Judgements(t *testing.T) {
	cfg, now := testConfig(), time.Now()

	// probation judged good -> confirmed
	state := NewState()
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL)
	got := ClrJudge(cfg, state, []Flow{tcpFlow("ESTABLISHED", 1, 0, 2, 0)}, now)
	if len(got) != 1 || got[0].Tier != TierConfirmed || got[0].Reason != ReasonJudgedGood {
		t.Errorf("good probation: actions = %+v, want a confirmed AddIP, reason %q", got, ReasonJudgedGood)
	}

	// probation judged failed
	state = NewState()
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL)
	got = ClrJudge(cfg, state, []Flow{tcpFlow("SYN_SENT", 3, 0, 0, 0)}, now)
	if len(got) != 2 || got[0].Kind != ActionRemoveIP || got[0].Reason != ReasonJudgedFailed {
		t.Errorf("failed probation: actions = %+v, want a RemoveIP with reason %q", got, ReasonJudgedFailed)
	}

	// confirmed address stops working
	state = NewState()
	state.OK[0].add(blockedDst, now, cfg.OKTTL)
	got = ClrJudge(cfg, state, []Flow{tcpFlow("SYN_SENT", 4, 0, 0, 0)}, now)
	if len(got) != 2 || got[0].Kind != ActionRemoveIP || got[0].Reason != ReasonOKFailed {
		t.Errorf("failed confirmed: actions = %+v, want a RemoveIP with reason %q", got, ReasonOKFailed)
	}

	// healthy confirmed address near expiry -> refreshed
	state = NewState()
	state.OK[0].add(blockedDst, now, cfg.OKRefreshBelow-time.Minute)
	got = ClrJudge(cfg, state, []Flow{tcpFlow("ESTABLISHED", 5, 0, 5, 500)}, now)
	if len(got) != 1 || got[0].Tier != TierConfirmed || got[0].Reason != ReasonOKRefresh {
		t.Errorf("refresh: actions = %+v, want a confirmed AddIP, reason %q", got, ReasonOKRefresh)
	}
}

func TestActionReasons_BlockPromote(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	got := ClrBlockPromote(cfg, state, now)
	if len(got) != 1 || got[0].Tier != TierBlock || got[0].Reason != ReasonBlockWiden {
		t.Fatalf("actions = %+v, want one block AddIP, reason %q", got, ReasonBlockWiden)
	}
}

// --- the operator's exclusion list gates classification ---

func userExcludeAddrs(addrs ...string) func(string) bool {
	set := map[string]bool{}
	for _, a := range addrs {
		set[a] = true
	}
	return func(ip string) bool { return set[ip] }
}

func TestUserExcluded_NeverClassified(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	cfg.UserExcluded = userExcludeAddrs(blockedDst)

	if got := ClrFast(cfg, NewState(), []Flow{tcpFlow("SYN_SENT", 5, 0, 0, 0)}, now); len(got) != 0 {
		t.Errorf("ClrFast: actions = %+v, want none -- the operator excluded this address", got)
	}
	if got := ClrSoft(cfg, NewState(), NewRateCache(), []Flow{tcpFlow("ESTABLISHED", 5, 1000, 2, 255)}, now); len(got) != 0 {
		t.Errorf("ClrSoft: actions = %+v, want none -- the operator excluded this address", got)
	}

	// An address that is not on the list is unaffected.
	cfg.UserExcluded = userExcludeAddrs("9.9.9.9")
	if got := ClrFast(cfg, NewState(), []Flow{tcpFlow("SYN_SENT", 5, 0, 0, 0)}, now); len(got) != 2 {
		t.Errorf("unrelated exclusion: actions = %+v, want the promotion to go through", got)
	}
}

func TestUserExcluded_BlockWideningRefused(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.UserExcludedOverlap = excludeCIDRs("1.2.3.200/32") // one address inside the /24
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- the /24 would redirect the excluded address too", got)
	}
}

func TestUserExcluded_KnownRangeNarrowsAroundIt(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.KnownRangeLookup = func(string) (string, bool) { return "1.2.0.0/18", true }
	cfg.UserExcludedOverlap = excludeCIDRs("1.2.60.0/24") // inside the /18, outside the /24
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")

	got := ClrBlockPromote(cfg, state, now)
	if len(got) != 1 || got[0].IP != "1.2.3.0/24" {
		t.Fatalf("actions = %+v, want the naive 1.2.3.0/24 -- the known range touches an excluded one", got)
	}
}

func TestUserExcluded_NilKeepsOldBehaviour(t *testing.T) {
	cfg := testConfig()
	if cfg.UserExcluded != nil || cfg.UserExcludedOverlap != nil {
		t.Fatal("DefaultConfig must leave the operator's exclusion hooks unset")
	}
	if got := ClrPurgeExcluded(cfg, NewState(), time.Now()); got != nil {
		t.Errorf("ClrPurgeExcluded with no list = %+v, want nil", got)
	}
}

// --- ClrPurgeExcluded ---

func sortedIPs(actions []Action, kind ActionKind) []string {
	var ips []string
	for _, a := range actions {
		if a.Kind == kind {
			ips = append(ips, a.IP)
		}
	}
	sort.Strings(ips)
	return ips
}

func TestClrPurgeExcluded_TakesBackEveryTier(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.UserExcluded = userExcludeAddrs("1.2.3.4", "5.6.7.8", "9.9.9.9", "8.8.4.4")
	cfg.UserExcludedOverlap = excludeCIDRs("31.13.72.0/24")

	state.Test[0].add("1.2.3.4", now, cfg.TestTTL)   // on probation
	state.OK[0].add("5.6.7.8", now, cfg.OKTTL)       // confirmed
	state.OKSince[0]["5.6.7.8"] = now                // ... with its lifetime clock
	state.Watch[0].add("9.9.9.9", now, cfg.WatchTTL) // only being watched: never in the ipset
	state.Cooldown[0].add("8.8.4.4", now, time.Hour) // cooling down: never in the ipset
	state.Blocks[0].add("31.13.72.0/24", now, time.Hour)
	state.OK[0].add("7.7.7.7", now, cfg.OKTTL) // unrelated, must survive

	got := ClrPurgeExcluded(cfg, state, now)

	wantRemoved := []string{"1.2.3.4", "31.13.72.0/24", "5.6.7.8"}
	if r := sortedIPs(got, ActionRemoveIP); !equalStrings(r, wantRemoved) {
		t.Errorf("RemoveIP = %v, want %v (only what was live in the redirect set)", r, wantRemoved)
	}
	if c := sortedIPs(got, ActionDeleteConntrackDst); !equalStrings(c, wantRemoved) {
		t.Errorf("DeleteConntrackDst = %v, want %v (stuck connections must be torn down too)", c, wantRemoved)
	}
	for _, a := range got {
		if a.Reason != ReasonExcluded {
			t.Errorf("action %+v: reason = %q, want %q", a, a.Reason, ReasonExcluded)
		}
	}

	for name, set := range map[string]ttlSet{
		"Test": state.Test[0], "Watch": state.Watch[0], "Cooldown": state.Cooldown[0], "Blocks": state.Blocks[0],
	} {
		if len(set) != 0 {
			t.Errorf("%s still holds %v after the purge", name, set)
		}
	}
	if state.OK[0].has("5.6.7.8", now) {
		t.Error("5.6.7.8 is still confirmed after the purge")
	}
	if _, ok := state.OKSince[0]["5.6.7.8"]; ok {
		t.Error("OKSince kept the clock of a purged entry")
	}
	if !state.OK[0].has("7.7.7.7", now) {
		t.Error("an unrelated confirmed address was purged")
	}
}

func TestClrPurgeExcluded_BlockOverlappingAnExcludedAddress(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.UserExcluded = userExcludeAddrs("31.13.72.9")
	cfg.UserExcludedOverlap = excludeCIDRs("31.13.72.9/32")
	state.Blocks[0].add("31.13.72.0/24", now, time.Hour)
	state.Blocks[0].add("157.240.0.0/24", now, time.Hour)

	got := ClrPurgeExcluded(cfg, state, now)
	if r := sortedIPs(got, ActionRemoveIP); !equalStrings(r, []string{"31.13.72.0/24"}) {
		t.Errorf("RemoveIP = %v, want only the block that holds the excluded address", r)
	}
	if !state.Blocks[0].has("157.240.0.0/24", now) {
		t.Error("an unrelated block was purged")
	}
}

func TestClrPurgeExcluded_BothProtocolsOneRemoval(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.UserExcluded = userExcludeAddrs("1.2.3.4")
	state.Test[0].add("1.2.3.4", now, cfg.TestTTL)
	state.OK[1].add("1.2.3.4", now, cfg.OKTTL)

	got := ClrPurgeExcluded(cfg, state, now)
	if r := sortedIPs(got, ActionRemoveIP); len(r) != 1 {
		t.Errorf("RemoveIP = %v, want a single removal for an address present in both protocols", r)
	}
	if state.Test[0].has("1.2.3.4", now) || state.OK[1].has("1.2.3.4", now) {
		t.Error("the address is still in the state of one of the protocols")
	}
}

func TestClrPurgeExcluded_ExpiredEntryNeedsNoRemoval(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.UserExcluded = userExcludeAddrs("1.2.3.4")
	state.Test[0].add("1.2.3.4", now.Add(-time.Hour), cfg.TestTTL) // lapsed, not yet pruned

	if got := ClrPurgeExcluded(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- it is no longer in the ipset", got)
	}
	if len(state.Test[0]) != 0 {
		t.Error("the stale entry should still be dropped from the state")
	}
}

func TestClrPurgeExcluded_LeavesRussianRangeVetoAlone(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.ExcludedRangeLookup = func(string) (string, bool) { return "1.2.3.0/24", true }
	cfg.ExcludedRangeOverlap = excludeCIDRs("1.2.3.0/24")
	cfg.UserExcluded = userExcludeAddrs("9.9.9.9") // a list exists, but holds nothing relevant
	state.OK[0].add("1.2.3.4", now, cfg.OKTTL)

	if got := ClrPurgeExcluded(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- the purge is for the operator's list only", got)
	}
	if !state.OK[0].has("1.2.3.4", now) {
		t.Error("the Russian-range veto must not start taking entries back")
	}
}

// --- State.Expire reports what lapsed ---

func TestStateExpire_ReportsLapsedEntriesByTier(t *testing.T) {
	state := NewState()
	t0 := time.Now()
	state.Test[0].add("1.1.1.1", t0, time.Minute)
	state.OK[1].add("2.2.2.2", t0, time.Hour)
	state.Blocks[0].add("3.3.3.0/24", t0, 30*time.Minute)
	state.Watch[0].add("4.4.4.4", t0, 8*time.Second)    // bookkeeping: pruned, not reported
	state.Cooldown[0].add("5.5.5.5", t0, 5*time.Minute) // bookkeeping: pruned, not reported
	state.Test[0].add("6.6.6.6", t0, 3*time.Hour)       // still alive
	state.OKSince[1]["2.2.2.2"] = t0

	if got := state.Expire(t0.Add(time.Second)); len(got) != 0 {
		t.Fatalf("early Expire = %+v, want nothing lapsed yet", got)
	}

	got := state.Expire(t0.Add(2 * time.Hour))
	byAddr := map[string]Lapsed{}
	for _, l := range got {
		byAddr[l.Addr] = l
	}
	want := map[string]Lapsed{
		"1.1.1.1":    {Addr: "1.1.1.1", UDP: false, Tier: TierProbation},
		"2.2.2.2":    {Addr: "2.2.2.2", UDP: true, Tier: TierConfirmed},
		"3.3.3.0/24": {Addr: "3.3.3.0/24", UDP: false, Tier: TierBlock},
	}
	if len(got) != len(want) {
		t.Fatalf("Expire = %+v, want exactly %v", got, want)
	}
	for addr, w := range want {
		if byAddr[addr] != w {
			t.Errorf("Expire reported %+v for %s, want %+v", byAddr[addr], addr, w)
		}
	}
	if !state.Test[0].has("6.6.6.6", t0.Add(2*time.Hour)) {
		t.Error("a live entry was dropped")
	}
	if len(state.Watch[0]) != 0 || len(state.Cooldown[0]) != 0 || len(state.OKSince[1]) != 0 {
		t.Error("Watch, Cooldown and OKSince should still be pruned")
	}
	if again := state.Expire(t0.Add(2 * time.Hour)); len(again) != 0 {
		t.Errorf("second Expire = %+v, want nothing -- each lapse is reported once", again)
	}
}

// A probation that gets judged is removed from Test by the judge, so it never
// shows up as lapsed -- only a probation with no verdict does.
func TestStateExpire_JudgedProbationIsNotLapsed(t *testing.T) {
	cfg, state, t0 := testConfig(), NewState(), time.Now()
	acts := ClrFast(cfg, state, []Flow{tcpFlow("SYN_SENT", 2, 0, 0, 0)}, t0)
	if len(acts) == 0 {
		t.Fatal("setup: no promotion")
	}
	ClrJudge(cfg, state, []Flow{tcpFlow("ESTABLISHED", 4, 0, 4, 400)}, t0.Add(10*time.Second)) // confirmed
	for _, l := range state.Expire(t0.Add(2 * time.Minute)) {
		if l.Tier == TierProbation {
			t.Errorf("Expire reported %+v as a lapsed probation, but it was judged", l)
		}
	}

	state = NewState()
	ClrFast(cfg, state, []Flow{tcpFlow("SYN_SENT", 2, 0, 0, 0)}, t0)
	lapsed := state.Expire(t0.Add(2 * time.Minute)) // nothing ever judged it
	if len(lapsed) != 1 || lapsed[0].Tier != TierProbation || lapsed[0].Addr != blockedDst {
		t.Errorf("Expire = %+v, want the unjudged probation reported as lapsed", lapsed)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
