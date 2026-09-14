package classifier

import (
	"net"
	"testing"
	"time"
)

func testConfig() *Config {
	cfg := DefaultConfig()
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	cfg.LANSubnets = []*net.IPNet{n}
	return &cfg
}

const (
	lanSrc     = "192.168.1.5"
	blockedDst = "1.2.3.4"
)

func tcpFlow(state string, op, ob, rp, rb uint64) Flow {
	return Flow{L4Proto: 6, Proto: "tcp", Src: lanSrc, Dst: blockedDst,
		SPort: 40000, DPort: 443, TCPState: state, OP: op, OB: ob, RP: rp, RB: rb, HasReply: rp > 0}
}

func udpFlow(dport uint, op, ob, rp, rb uint64) Flow {
	return Flow{L4Proto: 17, Proto: "udp", Src: lanSrc, Dst: blockedDst,
		SPort: 40000, DPort: dport, OP: op, OB: ob, RP: rp, RB: rb, HasReply: rp > 0}
}

// --- ClrFast ---

func TestClrFast_TCPSyn(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrFast(cfg, state, []Flow{tcpFlow("SYN_SENT", 2, 0, 0, 0)}, now)
	if len(actions) != 2 || actions[0].Kind != ActionAddIP || actions[0].IP != blockedDst {
		t.Fatalf("actions = %+v, want [AddIP, DeleteConntrack]", actions)
	}
	if !state.Test[0].has(blockedDst, now) {
		t.Error("dst should be in the tcp test state")
	}
}

func TestClrFast_TCPSyn_NotEnoughPackets(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrFast(cfg, state, []Flow{tcpFlow("SYN_SENT", 1, 0, 0, 0)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none (op below FastSynMinOp)", actions)
	}
}

func TestClrFast_TCPClose(t *testing.T) {
	// v0.3.8's loosened threshold: rp<=2 && rb<256 (was rp==0 && rb==0).
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrFast(cfg, state, []Flow{tcpFlow("CLOSE", 1, 0, 2, 255)}, now)
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want a promotion (rp=2,rb=255 is within the loosened threshold)", actions)
	}
}

func TestClrFast_TCPClose_TooMuchReply(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrFast(cfg, state, []Flow{tcpFlow("CLOSE", 1, 0, 3, 0)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none (rp=3 exceeds the threshold)", actions)
	}
}

func TestClrFast_QUIC(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrFast(cfg, state, []Flow{udpFlow(443, 3, 0, 0, 0)}, now)
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want a promotion", actions)
	}
}

func TestClrFast_SkipsNonLANAndPrivateDst(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	nonLAN := tcpFlow("SYN_SENT", 5, 0, 0, 0)
	nonLAN.Src = "203.0.113.9"
	privateDst := tcpFlow("SYN_SENT", 5, 0, 0, 0)
	privateDst.Dst = "10.1.1.1"

	if got := ClrFast(cfg, NewState(), []Flow{nonLAN}, now); len(got) != 0 {
		t.Errorf("non-LAN src: actions = %+v, want none", got)
	}
	if got := ClrFast(cfg, NewState(), []Flow{privateDst}, now); len(got) != 0 {
		t.Errorf("private dst: actions = %+v, want none", got)
	}
}

func TestClrFast_SkipsExistingCandidate(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.OK[0].add(blockedDst, now, time.Hour) // already confirmed
	actions := ClrFast(cfg, state, []Flow{tcpFlow("SYN_SENT", 5, 0, 0, 0)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none -- already in ok state", actions)
	}
}

// --- ClrSoft ---

func TestClrSoft_TCPStall(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	// v0.3.8's loosened threshold: rp<=2 && rb<256 (was rp==0 && rb==0).
	actions := ClrSoft(cfg, state, NewRateCache(), []Flow{tcpFlow("ESTABLISHED", 5, 1000, 2, 255)}, now)
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want an immediate promotion", actions)
	}
}

func TestClrSoft_TCPStall_NotEnoughData(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrSoft(cfg, state, NewRateCache(), []Flow{tcpFlow("ESTABLISHED", 5, 999, 0, 0)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none (ob below threshold)", actions)
	}
}

func TestClrSoft_TCPLateStall_NeedsThreePasses(t *testing.T) {
	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()

	// Pass 1: no prior sample -- just records it.
	if got := ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 8, 0, 1, 0)}, t0); len(got) != 0 {
		t.Fatalf("pass 1 actions = %+v, want none (no prior sample yet)", got)
	}

	// Pass 2 (+2s): op increased (active), rp unchanged (silent) ->
	// starts watching, does not promote yet.
	got := ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 12, 0, 1, 0)}, t0.Add(2*time.Second))
	if len(got) != 0 {
		t.Fatalf("pass 2 actions = %+v, want none (just started watching)", got)
	}
	if !state.Watch[0].has(blockedDst, t0.Add(2*time.Second)) {
		t.Fatal("pass 2 should have started a watch entry")
	}

	// Pass 3 (+7s from t0, i.e. 5s after the watch started -- within
	// WatchTTL(8s)-WatchRetryBelow(4s) of expiring): still active,
	// still silent -> confirmed late-stall, promote.
	got = ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 16, 0, 1, 0)}, t0.Add(7*time.Second))
	if len(got) != 2 {
		t.Fatalf("pass 3 actions = %+v, want a promotion (confirmed late-stall)", got)
	}
	if state.Watch[0].has(blockedDst, t0.Add(7*time.Second)) {
		t.Error("watch entry should be cleared once promoted")
	}
	if !state.Test[0].has(blockedDst, t0.Add(7*time.Second)) {
		t.Error("dst should now be in the test state")
	}
}

func TestClrSoft_TCPLateStall_RepliesResumingCancelsIt(t *testing.T) {
	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 8, 0, 1, 0)}, t0)
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 12, 0, 1, 0)}, t0.Add(2*time.Second))
	if !state.Watch[0].has(blockedDst, t0.Add(2*time.Second)) {
		t.Fatal("expected watching to have started")
	}
	// Reply side becomes active again (rp increased) -- replSilent is now
	// false, so the watch is neither confirmed nor re-armed by this pass.
	got := ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 16, 0, 5, 0)}, t0.Add(4*time.Second))
	if len(got) != 0 {
		t.Errorf("actions = %+v, want none once replies resumed", got)
	}
}

func TestClrSoft_UDPSilent(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	actions := ClrSoft(cfg, state, NewRateCache(), []Flow{udpFlow(80, 12, 0, 0, 0)}, now)
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want a promotion", actions)
	}
}

func TestClrSoft_UDPSilent_ExcludedPortsNeverPromote(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	for _, dport := range []uint{53, 67, 68, 123} {
		state := NewState()
		got := ClrSoft(cfg, state, NewRateCache(), []Flow{udpFlow(dport, 100, 0, 0, 0)}, now)
		if len(got) != 0 {
			t.Errorf("dport %d: actions = %+v, want none (excluded port)", dport, got)
		}
	}
}

func TestClrSoft_QUICLateStall_ThreePasses(t *testing.T) {
	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()
	flow := func(op uint64) Flow { return udpFlow(443, op, 0, 1, 0) }

	ClrSoft(cfg, state, cache, []Flow{flow(8)}, t0)
	ClrSoft(cfg, state, cache, []Flow{flow(12)}, t0.Add(2*time.Second))
	got := ClrSoft(cfg, state, cache, []Flow{flow(16)}, t0.Add(7*time.Second))
	if len(got) != 2 {
		t.Fatalf("actions = %+v, want a confirmed QUIC-LATE-STALL promotion", got)
	}
	if !state.Test[1].has(blockedDst, t0.Add(7*time.Second)) {
		t.Error("dst should be in the udp test state")
	}
}

func TestRateCache_PruneDropsUnseenFlows(t *testing.T) {
	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()
	f := tcpFlow("ESTABLISHED", 8, 0, 1, 0)
	ClrSoft(cfg, state, cache, []Flow{f}, t0) // records a sample

	// The flow vanishes from conntrack for one pass (closed, or just not
	// in this scan) -- its sample must be pruned, not carried forward
	// indefinitely.
	ClrSoft(cfg, state, cache, nil, t0.Add(2*time.Second))
	if _, ok := cache.samples[flowKey(f)]; ok {
		t.Error("a flow absent from a whole pass should have its sample pruned")
	}
}

// --- ClrJudge ---

func TestClrJudge_TestToOK(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.Test[0].add(blockedDst, now, cfg.TestTTL)
	f := tcpFlow("ESTABLISHED", 1, 0, 2, 0) // rp>=2 -> good

	actions := ClrJudge(cfg, state, []Flow{f}, now)
	if len(actions) != 1 || actions[0].Kind != ActionAddIP {
		t.Fatalf("actions = %+v, want [AddIP] into the ok tier", actions)
	}
	if state.Test[0].has(blockedDst, now) {
		t.Error("should have left the test tier")
	}
	if !state.OK[0].has(blockedDst, now) {
		t.Error("should have entered the ok tier")
	}
}

func TestClrJudge_TestToCooldown(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.Test[0].add(blockedDst, now, cfg.TestTTL)
	f := tcpFlow("SYN_SENT", 3, 0, 0, 0) // even via the tunnel, no reply -> failed

	actions := ClrJudge(cfg, state, []Flow{f}, now)
	if len(actions) != 2 || actions[0].Kind != ActionRemoveIP || actions[1].Kind != ActionDeleteConntrack {
		t.Fatalf("actions = %+v, want [RemoveIP, DeleteConntrack]", actions)
	}
	if state.Test[0].has(blockedDst, now) {
		t.Error("should have left the test tier")
	}
	if !state.Cooldown[0].has(blockedDst, now) {
		t.Error("should have entered cooldown")
	}
}

func TestClrJudge_TestUndecided(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.Test[0].add(blockedDst, now, cfg.TestTTL)
	f := tcpFlow("ESTABLISHED", 2, 0, 0, 0) // neither threshold met yet

	actions := ClrJudge(cfg, state, []Flow{f}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none while still undecided", actions)
	}
	if !state.Test[0].has(blockedDst, now) {
		t.Error("should remain in the test tier until judged one way or the other")
	}
}

func TestClrJudge_OKChurn(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.OK[0].add(blockedDst, now, cfg.OKTTL)
	f := tcpFlow("SYN_SENT", 4, 0, 0, 0) // even the tunnel path stopped working

	actions := ClrJudge(cfg, state, []Flow{f}, now)
	if len(actions) != 2 || actions[0].Kind != ActionRemoveIP {
		t.Fatalf("actions = %+v, want [RemoveIP, DeleteConntrack]", actions)
	}
	if state.OK[0].has(blockedDst, now) {
		t.Error("should have left the ok tier")
	}
	if !state.Cooldown[0].has(blockedDst, now) {
		t.Error("should have entered its own (shorter) cooldown")
	}
}

func TestClrJudge_OKRefreshedNearExpiry(t *testing.T) {
	cfg, state := testConfig(), NewState()
	t0 := time.Now()
	// Add with a TTL just inside OKRefreshBelow(3h) of expiring.
	almostExpired := cfg.OKRefreshBelow - time.Minute
	state.OK[0].add(blockedDst, t0, almostExpired)
	f := tcpFlow("ESTABLISHED", 5, 0, 5, 500) // healthy

	actions := ClrJudge(cfg, state, []Flow{f}, t0)
	if len(actions) != 1 || actions[0].Kind != ActionAddIP {
		t.Fatalf("actions = %+v, want a refresh", actions)
	}
	if got := state.OK[0].at(blockedDst, t0); got.Sub(t0) < cfg.OKTTL-time.Second {
		t.Errorf("expiry = %v from now, want it pushed back out to ~OKTTL", got.Sub(t0))
	}
}

func TestClrJudge_OKNotYetDueForRefresh(t *testing.T) {
	cfg, state := testConfig(), NewState()
	t0 := time.Now()
	state.OK[0].add(blockedDst, t0, cfg.OKTTL) // fresh, nowhere near expiring
	f := tcpFlow("ESTABLISHED", 5, 0, 5, 500)  // healthy

	actions := ClrJudge(cfg, state, []Flow{f}, t0)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none -- not due for a refresh yet", actions)
	}
}

func TestClrJudge_IgnoresUntrackedDestination(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	f := tcpFlow("ESTABLISHED", 5, 0, 5, 500) // not in test or ok state at all
	if got := ClrJudge(cfg, state, []Flow{f}, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none for a flow JUDGE isn't tracking", got)
	}
}
