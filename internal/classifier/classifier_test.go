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

func TestClrFast_SkipsExcludedRangeDst(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	cfg.ExcludedRangeLookup = func(ip string) (string, bool) {
		if ip == blockedDst {
			return "1.2.3.0/24", true
		}
		return "", false
	}
	actions := ClrFast(cfg, NewState(), []Flow{tcpFlow("SYN_SENT", 5, 0, 0, 0)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none -- dst matches ExcludedRangeLookup", actions)
	}
}

func TestExcludedRangeLookup_NotConsultedWhenNil(t *testing.T) {
	cfg := testConfig()
	if cfg.ExcludedRangeLookup != nil {
		t.Fatal("testConfig()/DefaultConfig() should leave ExcludedRangeLookup nil")
	}
	actions := ClrFast(cfg, NewState(), []Flow{tcpFlow("SYN_SENT", 5, 0, 0, 0)}, time.Now())
	if len(actions) == 0 {
		t.Fatal("actions = none, want a promotion -- ExcludedRangeLookup unset should never veto")
	}
}

// TestClrFast_SilentSYNOnNonWebPortNeverPromotes is the torrent case,
// confirmed live 2026-09-16: a dead BitTorrent peer looks exactly like
// ClrFast's silent-SYN signature, and a swarm has dozens at a time. The
// same flow shape must still promote on 80/443 -- the point is the port,
// not the signal.
func TestClrFast_SilentSYNOnNonWebPortNeverPromotes(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	for _, dport := range []uint{6881, 51413, 25, 22, 3478} {
		f := tcpFlow("SYN_SENT", 5, 0, 0, 0)
		f.DPort = dport
		if got := ClrFast(cfg, NewState(), []Flow{f}, now); len(got) != 0 {
			t.Errorf("dport %d: actions = %+v, want none", dport, got)
		}
	}
	for _, dport := range []uint{80, 443} {
		f := tcpFlow("SYN_SENT", 5, 0, 0, 0)
		f.DPort = dport
		if got := ClrFast(cfg, NewState(), []Flow{f}, now); len(got) == 0 {
			t.Errorf("dport %d: want a promotion, web traffic is the whole point", dport)
		}
	}
}

// TestClrJudge_NonWebFlowCannotRefreshOK covers the other half: a
// torrent flow to an address promoted earlier must not keep renewing its
// TTL, or an old mistake would never expire.
func TestClrJudge_NonWebFlowCannotRefreshOK(t *testing.T) {
	cfg, state, t0 := testConfig(), NewState(), time.Now()
	state.OK[0].add(blockedDst, t0, cfg.OKRefreshBelow-time.Minute) // due for refresh
	f := tcpFlow("ESTABLISHED", 5, 0, 5, 500)                       // healthy
	f.DPort = 6881

	if got := ClrJudge(cfg, state, []Flow{f}, t0); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- a non-web flow must not refresh", got)
	}
	if at := state.OK[0].at(blockedDst, t0); at.Sub(t0) >= cfg.OKTTL-time.Second {
		t.Error("TTL was pushed back out by a non-web flow")
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

func TestClrSoft_SkipsExcludedRangeDst(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	cfg.ExcludedRangeLookup = func(ip string) (string, bool) {
		if ip == blockedDst {
			return "1.2.3.0/24", true
		}
		return "", false
	}
	actions := ClrSoft(cfg, NewState(), NewRateCache(), []Flow{tcpFlow("ESTABLISHED", 5, 1000, 2, 255)}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none -- dst matches ExcludedRangeLookup", actions)
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
	// AR-04: this used to be the entire test -- it only checked that
	// nothing was promoted, not that the watch entry itself was cleared.
	// See TestAR04_ResumedRepliesDontLeaveAStaleWatchForALaterStall for
	// why leaving it stale until its own WatchTTL is a real bug.
	if state.Watch[0].has(blockedDst, t0.Add(4*time.Second)) {
		t.Error("watch entry should have been cleared once replies resumed, not left to expire on its own")
	}
}

// TestAR04_ResumedRepliesDontLeaveAStaleWatchForALaterStall is the full
// regression scenario for AR-04: without clearing the watch entry when
// replies resume, a later and genuinely unrelated stall to the same dst
// -- arriving before the stale entry's own WatchTTL expires -- would be
// mistaken by watchOrConfirmLateStall for the second half of a
// two-observation confirmation and promoted off a single fresh sample.
func TestAR04_ResumedRepliesDontLeaveAStaleWatchForALaterStall(t *testing.T) {
	cfg, state, cache := testConfig(), NewState(), NewRateCache()
	t0 := time.Now()

	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 8, 0, 1, 0)}, t0)
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 12, 0, 1, 0)}, t0.Add(2*time.Second))
	if !state.Watch[0].has(blockedDst, t0.Add(2*time.Second)) {
		t.Fatal("expected watching to have started")
	}

	// Replies resume (rp: 1 -> 5) -- the stall is over.
	ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 16, 0, 5, 0)}, t0.Add(4*time.Second))
	if state.Watch[0].has(blockedDst, t0.Add(4*time.Second)) {
		t.Fatal("watch entry should have been cleared once replies resumed")
	}

	// +6s from t0: a new, unrelated stall (rp unchanged from the last
	// sample) starts. Without AR-04, the stale watch entry from +2s
	// (otherwise only cleared at +10s) would still be within
	// WatchRetryBelow(4s) of expiring here, and this single fresh sample
	// would be mistaken for the confirming second observation.
	got := ClrSoft(cfg, state, cache, []Flow{tcpFlow("ESTABLISHED", 20, 0, 5, 0)}, t0.Add(6*time.Second))
	if len(got) != 0 {
		t.Fatalf("actions = %+v, want none -- this is only the first observation of the new stall", got)
	}
	if state.Test[0].has(blockedDst, t0.Add(6*time.Second)) {
		t.Error("dst must not be promoted off a single fresh sample")
	}
	if !state.Watch[0].has(blockedDst, t0.Add(6*time.Second)) {
		t.Error("the new stall should have started its own fresh watch")
	}
}

// TestClrSoft_SilentNonQUICUDPNeverPromotes pins the 2026-09-16 policy
// change: upstream promoted silent UDP on any port outside
// 443/53/67/68/123, which in practice meant BitTorrent DHT and uTP. Only
// QUIC (443) is eligible now -- see promotableDst.
func TestClrSoft_SilentNonQUICUDPNeverPromotes(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	for _, dport := range []uint{80, 53, 67, 68, 123, 6881, 51413} {
		state := NewState()
		got := ClrSoft(cfg, state, NewRateCache(), []Flow{udpFlow(dport, 100, 0, 0, 0)}, now)
		if len(got) != 0 {
			t.Errorf("dport %d: actions = %+v, want none", dport, got)
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
	// AR-01: promoted on an earlier tick, not this one -- ClrJudge skips
	// judging a Test entry created with exactly this same now (see
	// skipFreshTestPromotion), so seeding it with `now` here would make
	// this test assert on a case the fix no longer reaches.
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL)
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
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL) // AR-01: earlier tick, see TestClrJudge_TestToOK
	f := tcpFlow("SYN_SENT", 3, 0, 0, 0)                              // even via the tunnel, no reply -> failed

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
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL) // AR-01: earlier tick, see TestClrJudge_TestToOK
	f := tcpFlow("ESTABLISHED", 2, 0, 0, 0)                           // neither threshold met yet

	actions := ClrJudge(cfg, state, []Flow{f}, now)
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none while still undecided", actions)
	}
	if !state.Test[0].has(blockedDst, now) {
		t.Error("should remain in the test tier until judged one way or the other")
	}
}

// TestAR01_SameTickPromotionNotImmediatelyJudged is the regression test
// for the audit's own numerical example: adaptiveRouteClassifyLoop runs
// ClrSoft then ClrJudge back to back, on the same flows slice and the
// same now, applying the resulting Actions to the real ipset only
// afterward. This flow satisfies both ClrSoft's TCP-STALL immediate-
// promotion condition (OP>=5, OB>=1000, RP<=2, RB<256) and judgeTest's
// own "good" signal (RP>=2) simultaneously -- without the fix, ClrJudge
// would confirm it OK for cfg.OKTTL (hours) in the very same call that
// promoted it, before REDIRECT/ipset for it has been applied to the
// kernel at all, off a conntrack read that predates the promotion
// decision.
func TestAR01_SameTickPromotionNotImmediatelyJudged(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	f := tcpFlow("ESTABLISHED", 5, 1000, 2, 0)

	promoted := ClrSoft(cfg, state, NewRateCache(), []Flow{f}, now)
	if len(promoted) != 2 || promoted[0].Kind != ActionAddIP {
		t.Fatalf("ClrSoft actions = %+v, want a TCP-STALL promotion", promoted)
	}
	if !state.Test[0].has(blockedDst, now) {
		t.Fatal("precondition: dst should now be in the test tier")
	}

	judged := ClrJudge(cfg, state, []Flow{f}, now)
	if len(judged) != 0 {
		t.Errorf("ClrJudge actions = %+v, want none -- a same-tick promotion must not be judged before its own REDIRECT is even applied (AR-01)", judged)
	}
	if !state.Test[0].has(blockedDst, now) {
		t.Error("dst should remain in the test tier until a later tick judges it")
	}
	if state.OK[0].has(blockedDst, now) {
		t.Error("dst must not be confirmed OK on the same tick it was only just promoted")
	}
}

// TestAR01_JudgedNormallyOnALaterTick confirms the fix only defers
// judging by (at least) one tick, rather than making a promoted entry
// unjudgeable altogether.
func TestAR01_JudgedNormallyOnALaterTick(t *testing.T) {
	cfg, state, promotedAt := testConfig(), NewState(), time.Now()
	f := tcpFlow("ESTABLISHED", 5, 1000, 2, 0)
	if promoted := ClrSoft(cfg, state, NewRateCache(), []Flow{f}, promotedAt); len(promoted) != 2 {
		t.Fatalf("ClrSoft actions = %+v, want a TCP-STALL promotion", promoted)
	}

	laterNow := promotedAt.Add(classifyIntervalForTest)
	judged := ClrJudge(cfg, state, []Flow{f}, laterNow)
	if len(judged) != 1 || judged[0].Kind != ActionAddIP {
		t.Fatalf("actions = %+v, want [AddIP] -- a later tick must still judge normally", judged)
	}
	if !state.OK[0].has(blockedDst, laterNow) {
		t.Error("dst should have been confirmed OK on the later tick")
	}
}

// classifyIntervalForTest mirrors cmd/keenetic-xray's own classifyInterval
// (500ms) -- this package doesn't import that constant (leaf package, no
// dependency on cmd/keenetic-xray), just needs *some* realistic gap
// between two ticks for TestAR01_JudgedNormallyOnALaterTick.
const classifyIntervalForTest = 500 * time.Millisecond

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

// TestAR02_GoodFlowProtectsSharedIPFromFailedSiblingFlow is the
// regression test for the audit's AR-02: State.OK is keyed by
// destination IP alone, not IP+port (see ClrJudge's own doc comment), so
// a healthy flow to blockedDst:443 and a failed flow to blockedDst:80
// share one ok-tier entry. Before this fix, ClrJudge judged and mutated
// on each flow independently and immediately, so whichever flow happened
// to come last in the conntrack scan -- not the actual evidence --
// decided the outcome; a working :443 connection could be dropped from
// the ipset because an unrelated, merely-stalled :80 connection to the
// same IP was judged failed in the very same pass. Run with both
// orderings to confirm the fix doesn't just get lucky with scan order.
func TestAR02_GoodFlowProtectsSharedIPFromFailedSiblingFlow(t *testing.T) {
	cfg, now := testConfig(), time.Now()
	healthy := tcpFlow("ESTABLISHED", 5, 0, 5, 500) // :443, RP=5 -> healthy
	failedFlow := Flow{L4Proto: 6, Proto: "tcp", Src: lanSrc, Dst: blockedDst,
		SPort: 40001, DPort: 80, TCPState: "SYN_SENT", OP: 4, RP: 0} // :80, stalled -> failed

	for _, flows := range [][]Flow{{failedFlow, healthy}, {healthy, failedFlow}} {
		state := NewState()
		state.OK[0].add(blockedDst, now, cfg.OKTTL)

		actions := ClrJudge(cfg, state, flows, now)

		if !state.OK[0].has(blockedDst, now) {
			t.Errorf("flows=%+v: dst left the ok tier -- a same-tick healthy :443 flow must protect it from a failed :80 sibling", flows)
		}
		for _, a := range actions {
			if a.Kind == ActionRemoveIP {
				t.Errorf("flows=%+v: actions = %+v, want no RemoveIP", flows, actions)
			}
		}
	}
}

// TestAR02_GoodFlowProtectsTestTierFromFailedSiblingFlow is the Test-tier
// counterpart: a promotion in progress for blockedDst must still reach
// the ok tier off a healthy :443 flow even when a failed :80 flow to the
// same IP is judged in the same pass.
func TestAR02_GoodFlowProtectsTestTierFromFailedSiblingFlow(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	state.Test[0].add(blockedDst, now.Add(-time.Second), cfg.TestTTL) // AR-01: earlier tick, see TestClrJudge_TestToOK

	healthy := tcpFlow("ESTABLISHED", 1, 0, 2, 0) // :443, RP=2 -> good
	failedFlow := Flow{L4Proto: 6, Proto: "tcp", Src: lanSrc, Dst: blockedDst,
		SPort: 40001, DPort: 80, TCPState: "SYN_SENT", OP: 3, RP: 0} // :80, stalled -> failed

	actions := ClrJudge(cfg, state, []Flow{failedFlow, healthy}, now)
	if !state.OK[0].has(blockedDst, now) {
		t.Errorf("dst should have reached the ok tier via the healthy :443 flow, actions = %+v", actions)
	}
	if state.Cooldown[0].has(blockedDst, now) {
		t.Error("dst must not have been sent to cooldown by the failed :80 sibling")
	}
	for _, a := range actions {
		if a.Kind == ActionRemoveIP {
			t.Errorf("actions = %+v, want no RemoveIP", actions)
		}
	}
}

func TestClrJudge_IgnoresUntrackedDestination(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	f := tcpFlow("ESTABLISHED", 5, 0, 5, 500) // not in test or ok state at all
	if got := ClrJudge(cfg, state, []Flow{f}, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none for a flow JUDGE isn't tracking", got)
	}
}

// --- ClrBlockPromote ---

func addOK(state *State, i int, now time.Time, ttl time.Duration, addrs ...string) {
	for _, a := range addrs {
		state.OK[i].add(a, now, ttl)
	}
}

func TestClrBlockPromote_ThresholdMet(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 {
		t.Fatalf("actions = %+v, want exactly one block promotion", actions)
	}
	a := actions[0]
	if a.Kind != ActionAddIP || a.IP != "1.2.3.0/24" || a.TTL != cfg.BlockTTL {
		t.Errorf("action = %+v, want AddIP 1.2.3.0/24 ttl=%v", a, cfg.BlockTTL)
	}
	if !state.Blocks[0].has("1.2.3.0/24", now) {
		t.Error("promoted block should be recorded in state.Blocks")
	}
}

func TestClrBlockPromote_ThresholdNotMet(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3") // one short of the default threshold (4)

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none below BlockThreshold", got)
	}
}

func TestClrBlockPromote_AlreadyPromotedNotReEmitted(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	state.Blocks[0].add("1.2.3.0/24", now, cfg.BlockTTL) // already promoted this pass

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- block already current, no repeat Action/log line", got)
	}
}

func TestClrBlockPromote_ReJustifiedAfterExpiry(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	state.Blocks[0]["1.2.3.0/24"] = now.Add(-time.Second) // expired as of now (ttlSet.add(...,ttl<=0) means never-expires, not this)

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.2.3.0/24" {
		t.Fatalf("actions = %+v, want the block re-promoted since its own entry has expired", actions)
	}
}

func TestClrBlockPromote_TestTierAloneDoesNotCount(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	for _, a := range []string{"1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4"} {
		state.Test[0].add(a, now, cfg.TestTTL) // provisional only, never confirmed
	}

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- block promotion must only count confirmed (OK) addresses", got)
	}
}

func TestClrBlockPromote_IgnoresExpiredOKEntries(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3")
	state.OK[0]["1.2.3.4"] = now.Add(-time.Second) // stale map entry, already expired (ttlSet.add(...,ttl<=0) means never-expires, not this)

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- the 4th address is expired and shouldn't count", got)
	}
}

func TestClrBlockPromote_DisabledWhenThresholdZero(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.BlockThreshold = 0
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4", "1.2.3.5")

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- BlockThreshold<=0 disables the pass", got)
	}
}

func TestClrBlockPromote_TCPAndUDPTrackedSeparately(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2") // tcp: 2
	addOK(state, 1, now, cfg.OKTTL, "1.2.3.3", "1.2.3.4") // udp: 2 -- 4 total, but split, neither alone meets threshold=4

	if got := ClrBlockPromote(cfg, state, now); len(got) != 0 {
		t.Errorf("actions = %+v, want none -- tcp and udp OK entries don't combine toward one block's threshold", got)
	}
}

func TestClrBlockPromote_KnownRangeLookupWidensPromotedBlock(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) {
		if ip == "1.2.3.4" { // one of the sample addrs -- exact address doesn't matter, any in the group works
			return "1.2.0.0/20", true
		}
		return "1.2.0.0/20", true
	}

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 {
		t.Fatalf("actions = %+v, want exactly one block promotion", actions)
	}
	if a := actions[0]; a.IP != "1.2.0.0/20" {
		t.Errorf("action IP = %q, want the known range 1.2.0.0/20, not the naive /24", a.IP)
	}
	if state.Blocks[0].has("1.2.3.0/24", now) {
		t.Error("naive /24 should not be recorded in state.Blocks once a known range matched")
	}
	if !state.Blocks[0].has("1.2.0.0/20", now) {
		t.Error("the known range should be recorded in state.Blocks")
	}
}

func TestClrBlockPromote_KnownRangeLookupNoMatchFallsBackToNaiveBlock(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) { return "", false }

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.2.3.0/24" {
		t.Fatalf("actions = %+v, want the naive /24 -- lookup found no known range", actions)
	}
}

func TestClrBlockPromote_KnownRangeLookupNotConsultedWhenNil(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	if cfg.KnownRangeLookup != nil {
		t.Fatal("testConfig()/DefaultConfig() should leave KnownRangeLookup nil")
	}
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.2.3.0/24" {
		t.Fatalf("actions = %+v, want the naive /24 -- nil lookup means the original behavior", actions)
	}
}

func TestClrBlockPromote_TwoNaiveBlocksConvergeOnSameKnownRange(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	addOK(state, 0, now, cfg.OKTTL, "1.2.4.1", "1.2.4.2", "1.2.4.3", "1.2.4.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) { return "1.2.0.0/20", true }

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 {
		t.Fatalf("actions = %+v, want exactly one promotion -- both naive blocks resolve to the same known range", actions)
	}
	if actions[0].IP != "1.2.0.0/20" {
		t.Errorf("action IP = %q, want 1.2.0.0/20", actions[0].IP)
	}
}

func TestClrBlockPromote_KnownRangeTooWideIsRejected(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) { return "1.0.0.0/15", true } // way wider than KnownRangeMinPrefixBits

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.2.3.0/24" {
		t.Fatalf("actions = %+v, want the naive /24 -- known match is too wide, treated as no match", actions)
	}
	if state.Blocks[0].has("1.0.0.0/15", now) {
		t.Error("the too-wide known range should never be recorded")
	}
}

func TestClrBlockPromote_KnownRangeExactlyAtMinPrefixBitsIsAccepted(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.KnownRangeMinPrefixBits = 18
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) { return "1.2.0.0/18", true } // exactly at the floor

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.2.0.0/18" {
		t.Fatalf("actions = %+v, want the known /18 -- exactly at the floor, should be accepted", actions)
	}
}

func TestClrBlockPromote_KnownRangeMinPrefixBitsZeroDisablesCap(t *testing.T) {
	cfg, state, now := testConfig(), NewState(), time.Now()
	cfg.KnownRangeMinPrefixBits = 0
	addOK(state, 0, now, cfg.OKTTL, "1.2.3.1", "1.2.3.2", "1.2.3.3", "1.2.3.4")
	cfg.KnownRangeLookup = func(ip string) (string, bool) { return "1.0.0.0/8", true } // absurdly wide, cap disabled so still accepted

	actions := ClrBlockPromote(cfg, state, now)
	if len(actions) != 1 || actions[0].IP != "1.0.0.0/8" {
		t.Fatalf("actions = %+v, want the known /8 -- cap disabled (MinPrefixBits<=0)", actions)
	}
}

func TestKnownRangeAcceptable(t *testing.T) {
	cases := []struct {
		cidr    string
		minBits int
		want    bool
	}{
		{"1.2.0.0/20", 18, true},
		{"1.2.0.0/18", 18, true},  // exactly at the floor
		{"1.2.0.0/17", 18, false}, // one bit too wide
		{"1.0.0.0/8", 18, false},
		{"1.0.0.0/8", 0, true},    // cap disabled
		{"not-a-cidr", 18, false}, // defensive: unparseable input is rejected, not accepted
	}
	for _, c := range cases {
		if got := knownRangeAcceptable(c.cidr, c.minBits); got != c.want {
			t.Errorf("knownRangeAcceptable(%q, %d) = %v, want %v", c.cidr, c.minBits, got, c.want)
		}
	}
}

func TestContainingBlock(t *testing.T) {
	if b, ok := containingBlock("31.13.72.5", 24); !ok || b != "31.13.72.0/24" {
		t.Errorf("containingBlock(...,24) = %q,%v, want 31.13.72.0/24,true", b, ok)
	}
	if b, ok := containingBlock("31.13.72.5", 16); !ok || b != "31.13.0.0/16" {
		t.Errorf("containingBlock(...,16) = %q,%v, want 31.13.0.0/16,true", b, ok)
	}
	if _, ok := containingBlock("not-an-ip", 24); ok {
		t.Error("containingBlock on garbage input should report ok=false")
	}
	if _, ok := containingBlock("2001:db8::1", 24); ok {
		t.Error("containingBlock on an IPv6 address should report ok=false")
	}
}
