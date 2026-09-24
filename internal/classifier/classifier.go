package classifier

import (
	"net"
	"strconv"
	"time"
)

// ActionKind is what one Action asks an external caller to do.
type ActionKind int

const (
	// ActionAddIP: add IP to the redirect ipset (internal/adaptiveroute),
	// with the given TTL (0 = no per-entry expiry).
	ActionAddIP ActionKind = iota
	// ActionRemoveIP: remove IP from the redirect ipset.
	ActionRemoveIP
	// ActionDeleteConntrack: delete Flow's own conntrack entry (internal/
	// keenetic) so a fresh connection attempt goes through the just-
	// changed routing decision -- an already-established flow doesn't
	// retroactively move when the ipset changes underneath it.
	ActionDeleteConntrack
)

// Action is one external effect a classification pass wants applied.
// The classifier itself is pure -- it only decides, mutating State in
// memory; internal/adaptiveroute (ipset) and internal/keenetic
// (conntrack -D) are what actually carry an Action out. Kept out of
// this package on purpose so ClrFast/ClrSoft/ClrJudge are testable with
// nothing but constructed Flows, no fake exec layer needed at all.
type Action struct {
	Kind ActionKind
	IP   string        // ActionAddIP / ActionRemoveIP
	TTL  time.Duration // ActionAddIP only
	Flow Flow          // ActionDeleteConntrack only -- identifies exactly which conntrack entry to tear down
}

// promoteTest is upstream's promote_test (src/classifier.c): move dst
// into the "test" tier (provisionally routed; ClrJudge decides later
// whether it actually helped) and tear down the triggering flow's own
// conntrack entry so a fresh connection goes through the now-redirected
// path.
func promoteTest(cfg *Config, state *State, f Flow, now time.Time) []Action {
	i := protoIndex(f.L4Proto == 17)
	state.Test[i].add(f.Dst, now, cfg.TestTTL)
	state.Watch[i].remove(f.Dst)
	return []Action{
		{Kind: ActionAddIP, IP: f.Dst, TTL: cfg.TestTTL},
		{Kind: ActionDeleteConntrack, Flow: f},
	}
}

// ClrFast mirrors upstream's clr_fast (src/classifier.c): a completely
// silent SYN retry, or a TCP close with next to no reply, is suspicious
// enough on its own to try routing through the tunnel immediately -- no
// second opinion needed the way ClrSoft's late-stall detection wants
// one.
func ClrFast(cfg *Config, state *State, flows []Flow, now time.Time) []Action {
	var actions []Action
	for _, f := range flows {
		if f.L4Proto != 6 && f.L4Proto != 17 {
			continue
		}
		if !fromLAN(cfg, f.Src) || isPrivateDst(f.Dst) || isExcludedDst(cfg, f.Dst) ||
			!promotableDst(f.L4Proto == 17, f.DPort) {
			continue
		}
		if !candidateOK(state, f.L4Proto == 17, f.Dst, now) {
			continue
		}

		switch {
		case f.L4Proto == 6 && f.TCPState == "SYN_SENT" &&
			f.OP >= uint64(cfg.FastSynMinOp) && f.RP == 0:
			actions = append(actions, promoteTest(cfg, state, f, now)...)
		case f.L4Proto == 6 && f.TCPState == "CLOSE" &&
			f.OP >= 1 && f.RP <= 2 && f.RB < 256:
			actions = append(actions, promoteTest(cfg, state, f, now)...)
		case f.L4Proto == 17 && f.DPort == 443 && f.OP >= 3 && f.RP == 0:
			actions = append(actions, promoteTest(cfg, state, f, now)...)
		}
	}
	return actions
}

// rateSample is one flow's most recently observed (OP,RP) pair.
type rateSample struct{ op, rp uint64 }

// RateCache is ClrSoft's own per-pass bookkeeping: has this flow's
// original side sent more since the last SOFT pass, while its reply
// side stayed exactly as silent? That combination is what flags a
// "still active, but the reply just went quiet" late-stall candidate.
// Mirrors upstream's rc_* cache (src/classifier.c) -- a map instead of
// a fixed linear-scan array, otherwise the same begin/sample/end shape.
// Owned by the caller and reused across calls (SOFT-pass-scoped
// bookkeeping, not classification state, so it doesn't live on State).
type RateCache struct {
	samples map[string]rateSample
	seen    map[string]bool
}

// NewRateCache returns an empty, ready-to-use RateCache.
func NewRateCache() *RateCache {
	return &RateCache{samples: map[string]rateSample{}, seen: map[string]bool{}}
}

func flowKey(f Flow) string {
	return f.Proto + "|" + f.Src + "|" + strconv.FormatUint(uint64(f.SPort), 10) +
		"|" + f.Dst + "|" + strconv.FormatUint(uint64(f.DPort), 10)
}

// beginPass resets seen-this-pass tracking -- call once before scanning.
func (c *RateCache) beginPass() { c.seen = map[string]bool{} }

// endPass drops every sample not touched in the pass just finished --
// call once after scanning. A flow that vanished from conntrack (closed,
// or timed out) stops being sampled, exactly like upstream's rc_end.
func (c *RateCache) endPass() {
	for key := range c.samples {
		if !c.seen[key] {
			delete(c.samples, key)
		}
	}
}

// delta reports whether f has a prior sample from an earlier pass
// (hadPrev), and if so whether its orig side is active (more packets
// than last time) and its reply side is silent (same packet count as
// last time) -- then records f's current counters as the new sample.
func (c *RateCache) delta(f Flow) (origActive, replSilent, hadPrev bool) {
	key := flowKey(f)
	c.seen[key] = true
	prev, ok := c.samples[key]
	c.samples[key] = rateSample{op: f.OP, rp: f.RP}
	if !ok {
		return false, false, false
	}
	return f.OP > prev.op, f.RP == prev.rp, true
}

// ClrSoft mirrors upstream's clr_soft (src/classifier.c). Two distinct
// signals: an established TCP flow that sent real data and got
// essentially nothing back is promoted immediately (TCP-STALL); one
// that's still actively sending AND has gotten *some* reply, but whose
// reply side suddenly goes quiet for roughly a full watch window, gets
// the two-observation late-stall treatment (the DPI-throttle-after-
// initial-response pattern -- see the classifier's package doc comment
// and docs/HANDOFF-susanin.md for why this matters for YouTube/
// Instagram specifically). UDP mirrors both cases for non-QUIC and QUIC
// respectively.
func ClrSoft(cfg *Config, state *State, cache *RateCache, flows []Flow, now time.Time) []Action {
	var actions []Action
	cache.beginPass()
	for _, f := range flows {
		if f.L4Proto != 6 && f.L4Proto != 17 {
			continue
		}
		if !fromLAN(cfg, f.Src) || isPrivateDst(f.Dst) || isExcludedDst(cfg, f.Dst) ||
			!promotableDst(f.L4Proto == 17, f.DPort) {
			continue
		}
		udp := f.L4Proto == 17

		switch {
		case f.L4Proto == 6 && f.TCPState == "ESTABLISHED":
			if f.OP >= 5 && f.OB >= 1000 && f.RP <= 2 && f.RB < 256 {
				if candidateOK(state, udp, f.Dst, now) {
					actions = append(actions, promoteTest(cfg, state, f, now)...)
				}
				continue
			}
			if f.OP >= 8 && f.RP > 0 {
				if origActive, replSilent, hadPrev := cache.delta(f); hadPrev {
					switch {
					case origActive && replSilent:
						actions = append(actions, watchOrConfirmLateStall(cfg, state, udp, f, now)...)
					case !replSilent:
						// AR-04: replies resumed -- drop any pending
						// watch entry now, on direct evidence, instead
						// of leaving it to expire on its own WatchTTL.
						// Otherwise a later, unrelated stall to the same
						// dst arriving inside that window would find
						// state.Watch already populated and
						// watchOrConfirmLateStall could mistake it for
						// the second half of a two-observation
						// confirmation -- promoting off one fresh
						// sample instead of the two genuinely
						// independent ones the watch mechanism exists
						// to require.
						state.Watch[protoIndex(udp)].remove(f.Dst)
					}
				}
			}
		case f.L4Proto == 17:
			// QUIC late-stall only. Upstream also promoted *silent*
			// non-QUIC UDP here (12+ packets, no reply, excluding
			// 53/67/68/123) -- deliberately dropped: promotableDst above
			// now admits only UDP 443, which made that branch
			// unreachable, and it was precisely what caught BitTorrent
			// DHT/uTP traffic. See promotableDst's own doc comment for
			// the incident.
			if f.HasReply && f.OP >= 8 {
				if origActive, replSilent, hadPrev := cache.delta(f); hadPrev {
					switch {
					case origActive && replSilent:
						actions = append(actions, watchOrConfirmLateStall(cfg, state, udp, f, now)...)
					case !replSilent:
						// AR-04: see the TCP branch's own comment above.
						state.Watch[protoIndex(udp)].remove(f.Dst)
					}
				}
			}
		}
	}
	cache.endPass()
	return actions
}

// watchOrConfirmLateStall is the watch-then-confirm block ClrSoft shares
// between TCP and QUIC: first sighting of "active but reply gone quiet"
// starts a short watch window; if it's *still* in that state close to
// the window's end (seen again, roughly WatchTTL-WatchRetryBelow later,
// since ClrSoft only runs every soft_interval), that's a confirmed
// late-stall, not one noisy sample -- promote it.
func watchOrConfirmLateStall(cfg *Config, state *State, udp bool, f Flow, now time.Time) []Action {
	i := protoIndex(udp)
	if !state.Watch[i].has(f.Dst, now) {
		if candidateOK(state, udp, f.Dst, now) {
			state.Watch[i].add(f.Dst, now, cfg.WatchTTL)
		}
		return nil
	}
	at := state.Watch[i].at(f.Dst, now)
	if at.IsZero() || at.Sub(now) > cfg.WatchRetryBelow {
		return nil
	}
	if !candidateOK(state, udp, f.Dst, now) {
		return nil
	}
	state.Watch[i].remove(f.Dst)
	return promoteTest(cfg, state, f, now)
}

// ClrJudge mirrors upstream's clr_judge (src/classifier.c): for a
// destination currently in the test tier, decide whether routing it
// through the tunnel actually fixed it (promote to ok) or didn't (drop
// to cooldown); for one already in the ok tier, decide whether it's
// still healthy or has stopped working (drop to a shorter cooldown) --
// and opportunistically refresh a healthy ok entry's TTL before it
// expires. See the package doc comment for why this checks State
// directly instead of a conntrack mark the way upstream does.
//
// AR-01: the caller (adaptiveRouteClassifyLoop) runs ClrFast, ClrSoft,
// then ClrJudge back to back on one call with one shared flows slice and
// one shared now, and only applies the whole batch of Actions to the
// real ipset afterward. A destination ClrFast/ClrSoft just promoted to
// Test earlier in that same call has its own REDIRECT Action still only
// queued, not yet applied -- and f itself is still the pre-promotion
// conntrack snapshot that triggered the promotion, not evidence of
// anything that happened through the tunnel. Judging it right here would
// score a connection that (as far as the kernel is concerned) never
// actually went through the tunnel at all, on data that predates the
// promotion decision -- confirmed reachable exactly as the audit
// describes: a single ESTABLISHED flow with a couple of reply packets
// already on it (RP>=2) satisfies both ClrSoft's TCP-STALL promotion and
// judgeTest's "good" signal simultaneously, so the same flow that
// triggers the promotion can also immediately confirm it, in one pass,
// before REDIRECT exists. skipFreshTestPromotion below identifies that
// case without any new state: a Test entry always expires at exactly
// now+cfg.TestTTL at the moment promoteTest creates it, so an entry
// whose expiry is still exactly that far out was necessarily created
// with *this* now -- i.e. earlier in this very call, not on a previous
// tick.
//
// AR-02: State.Test/State.OK are keyed by destination IP alone (see the
// package doc comment), matching the REDIRECT ipset's own IP-only
// membership -- port-scoping for blast radius lives in the iptables rule
// itself (internal/adaptiveroute's redirectPorts), not in this state. One
// consequence: two different conntrack flows to the same IP on different
// eligible ports (e.g. :80 and :443, both promotableDst) share one
// judgment. flows' own order is whatever ScanConntrack happened to
// enumerate that tick -- not meaningful, and not something a caller
// should have to reason about -- so without the pre-pass below, a flow
// that confirmed a destination healthy could have that confirmation
// immediately discarded by a *different*, unrelated flow to the same
// destination judged failed right after it, in the very same call.
// goodThisTick runs a first, read-only pass over every qualifying flow to
// collect each (protocol, dst) that had at least one good/healthy flow
// this tick, so the second, mutating pass can refuse to let a
// failed-only flow undo it.
func ClrJudge(cfg *Config, state *State, flows []Flow, now time.Time) []Action {
	type judgeKey struct {
		i   int
		dst string
	}
	goodThisTick := map[judgeKey]bool{}
	for _, f := range flows {
		if f.L4Proto != 6 && f.L4Proto != 17 {
			continue
		}
		if !fromLAN(cfg, f.Src) || !promotableDst(f.L4Proto == 17, f.DPort) {
			continue
		}
		i := protoIndex(f.L4Proto == 17)
		var good bool
		switch {
		case state.Test[i].has(f.Dst, now) && !skipFreshTestPromotion(cfg, state, i, f.Dst, now):
			good, _ = testVerdict(f)
		case state.OK[i].has(f.Dst, now):
			good, _ = okVerdict(f)
		default:
			continue
		}
		if good {
			goodThisTick[judgeKey{i, f.Dst}] = true
		}
	}

	var actions []Action
	for _, f := range flows {
		if f.L4Proto != 6 && f.L4Proto != 17 {
			continue
		}
		// Same port gate as ClrFast/ClrSoft (see promotableDst): a
		// non-web flow must not keep an entry alive either, or a
		// torrent swarm's own traffic to an address promoted earlier
		// would refresh its TTL indefinitely and the mistake would
		// never expire. Symmetric by design -- such a flow can no
		// longer justify a drop either, matching the fact that it can
		// no longer justify a promotion.
		if !fromLAN(cfg, f.Src) || !promotableDst(f.L4Proto == 17, f.DPort) {
			continue
		}
		udp := f.L4Proto == 17
		i := protoIndex(udp)

		switch {
		case state.Test[i].has(f.Dst, now):
			if skipFreshTestPromotion(cfg, state, i, f.Dst, now) {
				continue
			}
			if good, failed := testVerdict(f); failed && !good && goodThisTick[judgeKey{i, f.Dst}] {
				continue // a sibling flow to the same dst confirmed it good this tick
			}
			actions = append(actions, judgeTest(cfg, state, udp, f, now)...)
		case state.OK[i].has(f.Dst, now):
			if healthy, failed := okVerdict(f); failed && !healthy && goodThisTick[judgeKey{i, f.Dst}] {
				continue // a sibling flow to the same dst confirmed it healthy this tick
			}
			actions = append(actions, judgeOK(cfg, state, udp, f, now)...)
		}
	}
	return actions
}

// skipFreshTestPromotion reports whether dst's Test-tier entry was
// created with exactly this now -- see ClrJudge's own doc comment for
// why that means "earlier in this same call," not "on a previous tick,"
// and must not be judged yet.
func skipFreshTestPromotion(cfg *Config, state *State, i int, dst string, now time.Time) bool {
	return state.Test[i].at(dst, now).Sub(now) == cfg.TestTTL
}

// testVerdict computes judgeTest's own good/failed thresholds without
// mutating anything -- extracted so ClrJudge's first pass (see its own
// doc comment, AR-02) can consult the same numbers judgeTest itself
// applies, rather than keeping two copies that could drift.
func testVerdict(f Flow) (good, failed bool) {
	if f.L4Proto == 6 {
		if f.RP >= 2 || f.RB >= 128 {
			good = true
		}
		if (f.TCPState == "SYN_SENT" && f.OP >= 3 && f.RP == 0) ||
			(f.TCPState == "ESTABLISHED" && f.OP >= 10 && f.OB >= 3000 && f.RP <= 1 && f.RB < 128) {
			failed = true
		}
		return good, failed
	}
	if f.RP >= 1 {
		good = true
	}
	if (f.DPort == 443 && f.OP >= 10 && f.RP == 0) || (f.DPort != 443 && f.OP >= 20 && f.RP == 0) {
		failed = true
	}
	return good, failed
}

func judgeTest(cfg *Config, state *State, udp bool, f Flow, now time.Time) []Action {
	i := protoIndex(udp)
	good, failed := testVerdict(f)

	switch {
	case good:
		state.OK[i].add(f.Dst, now, cfg.OKTTL)
		state.OKSince[i][f.Dst] = now // AR-05: see judgeOK's own doc comment
		state.Test[i].remove(f.Dst)
		state.Watch[i].remove(f.Dst)
		state.Cooldown[i].remove(f.Dst)
		return []Action{{Kind: ActionAddIP, IP: f.Dst, TTL: cfg.OKTTL}}
	case failed:
		state.Test[i].remove(f.Dst)
		state.Watch[i].remove(f.Dst)
		state.Cooldown[i].add(f.Dst, now, cfg.CooldownTTL)
		return []Action{
			{Kind: ActionRemoveIP, IP: f.Dst},
			{Kind: ActionDeleteConntrack, Flow: f},
		}
	}
	return nil
}

// okVerdict is judgeOK's own testVerdict counterpart -- see that
// function's doc comment.
func okVerdict(f Flow) (healthy, failed bool) {
	if f.L4Proto == 6 {
		if f.RP >= 2 || f.RB >= 128 {
			healthy = true
		}
		if (f.TCPState == "SYN_SENT" && f.OP >= 4 && f.RP == 0) ||
			(f.TCPState == "ESTABLISHED" && f.OP >= 15 && f.OB >= 5000 && f.RP <= 1 && f.RB < 128) {
			failed = true
		}
		return healthy, failed
	}
	if f.RP >= 1 {
		healthy = true
	}
	if f.DPort == 443 && f.OP >= 16 && f.RP == 0 {
		failed = true
	}
	return healthy, failed
}

// judgeOK's healthy-refresh branch below is capped by maxOKLifetime
// (AR-05): without it, a destination whose block was later lifted -- or
// that was never really blocked, just caught a transient false positive
// -- would stay routed through the tunnel forever. OKRefreshBelow's own
// window means any healthy flow within the last stretch of an entry's
// TTL extends it straight back out to a full new one, so a destination
// with even occasional regular use in practice never reaches its own
// expiry to get a chance at being tried DIRECT again -- there is no
// separate, dedicated check for that recovery at all. Once the cap
// trips, judgeOK simply stops refreshing and lets the entry lapse on its
// existing (already-granted) TTL on schedule: no early eviction, no
// synthetic DIRECT probe traffic, nothing an operator would notice under
// normal use. If it's genuinely still blocked, ClrFast/ClrSoft detect
// and re-promote it the same way they did the first time, typically
// within one soft_interval of the next real connection attempt.
func judgeOK(cfg *Config, state *State, udp bool, f Flow, now time.Time) []Action {
	i := protoIndex(udp)
	healthy, failed := okVerdict(f)

	switch {
	case failed && !healthy:
		state.OK[i].remove(f.Dst)
		delete(state.OKSince[i], f.Dst)
		state.Test[i].remove(f.Dst)
		state.Watch[i].remove(f.Dst)
		state.Cooldown[i].add(f.Dst, now, cfg.CooldownOKTTL)
		return []Action{
			{Kind: ActionRemoveIP, IP: f.Dst},
			{Kind: ActionDeleteConntrack, Flow: f},
		}
	case healthy && !failed:
		at := state.OK[i].at(f.Dst, now)
		if !at.IsZero() && at.Sub(now) <= cfg.OKRefreshBelow {
			since, tracked := state.OKSince[i][f.Dst]
			if !tracked {
				// Entry predates this fix, or was loaded from disk
				// (OKSince isn't persisted) -- start its clock now
				// rather than treating it as already-expired.
				since = now
				state.OKSince[i][f.Dst] = since
			}
			if now.Sub(since) >= maxOKLifetime(cfg) {
				return nil
			}
			state.OK[i].add(f.Dst, now, cfg.OKTTL)
			return []Action{{Kind: ActionAddIP, IP: f.Dst, TTL: cfg.OKTTL}}
		}
	}
	return nil
}

// maxOKLifetimeMultiple sets how many OKTTL cycles a single OK-tier
// entry may be refreshed through before judgeOK stops extending it (see
// its own doc comment, AR-05). Tied to cfg.OKTTL rather than a fixed
// duration so the cap still respects the operator's own chosen trust
// window: the bot's own OKTTL buttons run 6/12/18/24h, so the default
// multiplier below caps total lifetime at 1-4 days depending on that
// choice, comfortably longer than any single normal refresh cycle.
const maxOKLifetimeMultiple = 4

func maxOKLifetime(cfg *Config) time.Duration {
	return maxOKLifetimeMultiple * cfg.OKTTL
}

// ClrBlockPromote has no upstream equivalent. A large CDN (Facebook/
// Instagram, Netflix, ...) serves one logical service from dozens of
// addresses that rotate faster than per-flow FAST/SOFT/JUDGE can
// individually confirm each of them -- confirmed live on hardware: by
// the time one address earns its own OK promotion, a retry has often
// already moved on to a sibling address nothing has flagged yet. This
// pass looks only at state.OK (individually *confirmed*, not merely
// provisional state.Test -- promoting a whole subnet off unverified
// signals would risk pulling unrelated same-subnet traffic through the
// tunnel for nothing) grouped by their containing cfg.BlockCIDRBits-bit
// network, and once cfg.BlockThreshold distinct confirmed addresses
// share one network, redirects that network wholesale instead of
// waiting for every remaining address in it to each earn its own.
//
// A promoted block is deliberately much simpler than a single address:
// no JUDGE-style verify/fail path of its own, just a flat cfg.BlockTTL
// that this same pass re-justifies from scratch on every call (still
// >= threshold confirmed addresses inside it -> refreshed for another
// BlockTTL; otherwise left alone to expire, both in state.Blocks and,
// via the matching kernel-level ipset timeout, in the dataplane too --
// see internal/adaptiveroute.AddIP). state.Blocks[i].has is what keeps
// an already-current block from producing a new Action (and a new log
// line) on every single tick.
//
// cfg.BlockCIDRBits is a blind guess -- a fixed width applied everywhere
// with no idea whether a given provider's real allocation is wider or
// narrower. Before finalizing a threshold-crossing block, this pass
// gives cfg.KnownRangeLookup (if set) one confirmed address from it: a
// match there is a real, known boundary rather than a guess, and that
// wider range is what actually gets promoted and recorded -- one large
// provider's whole allocation redirected from a single /24's worth of
// confirmed evidence, instead of leaving its other /24s to each cross
// the threshold on their own later. Two independently-crossing naive
// blocks that resolve to the same known range simply converge on one
// promotion: the second one's state.Blocks[i].has check (keyed by the
// resolved range, not the naive block) finds it already current. A
// match wider than cfg.KnownRangeMinPrefixBits is treated as no match
// at all -- see that field's own doc comment for why a "known" range
// isn't automatically a safe one to redirect wholesale.
//
// cfg.BlockThreshold <= 0 disables this pass outright -- the zero Config
// would otherwise "promote" every OK address into its own /24 block
// immediately, which is never what an unconfigured Config should do.
func ClrBlockPromote(cfg *Config, state *State, now time.Time) []Action {
	if cfg.BlockThreshold <= 0 || cfg.BlockCIDRBits <= 0 {
		return nil
	}
	var actions []Action
	for i := 0; i < 2; i++ {
		counts := map[string]int{}
		sample := map[string]string{} // naive block -> one confirmed address inside it, for KnownRangeLookup
		for addr, exp := range state.OK[i] {
			if !exp.After(now) {
				continue
			}
			block, ok := containingBlock(addr, cfg.BlockCIDRBits)
			if !ok {
				continue
			}
			counts[block]++
			if _, seen := sample[block]; !seen {
				sample[block] = addr
			}
		}
		for block, n := range counts {
			if n < cfg.BlockThreshold {
				continue
			}
			promoted := block
			if cfg.KnownRangeLookup != nil {
				if known, ok := cfg.KnownRangeLookup(sample[block]); ok && knownRangeAcceptable(known, cfg.KnownRangeMinPrefixBits) {
					promoted = known
				}
			}
			// A promoted block is a single ipset entry covering every
			// address inside it, and the REDIRECT rule matches all of
			// them -- so an excluded range anywhere in it rides along,
			// with the per-flow veto never consulted. See
			// ExcludedRangeOverlap. Narrow back to the naive block
			// first: a KnownRangeLookup match is far wider and much
			// likelier to straddle a boundary, and the naive block is
			// often clean when the wide one is not. Give up on widening
			// only when that is tainted too. Either way the confirmed
			// addresses that drove the count keep the individual
			// promotions they already earned -- only the widening is
			// lost, which is the correct trade: widening is an
			// optimization, redirecting Russian traffic is a defect.
			if promoted != block && isExcludedBlock(cfg, promoted) {
				promoted = block
			}
			if isExcludedBlock(cfg, promoted) {
				continue
			}
			if state.Blocks[i].has(promoted, now) {
				continue
			}
			state.Blocks[i].add(promoted, now, cfg.BlockTTL)
			actions = append(actions, Action{Kind: ActionAddIP, IP: promoted, TTL: cfg.BlockTTL})
		}
	}
	return actions
}

// knownRangeAcceptable reports whether cidr (a KnownRangeLookup match)
// is narrow enough for ClrBlockPromote to actually use: its prefix must
// be at least minBits long (i.e. the network no wider than a /minBits),
// or minBits <= 0 (the cap disabled). See KnownRangeMinPrefixBits' own
// doc comment for why this cap exists at all. An unparseable cidr is
// rejected outright -- shouldn't happen for a well-formed
// KnownRangeLookup, but this package treats external input defensively
// throughout (see containingBlock).
func knownRangeAcceptable(cidr string, minBits int) bool {
	if minBits <= 0 {
		return true
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := n.Mask.Size()
	return ones >= minBits
}

// containingBlock returns addr's containing IPv4 network at bits prefix
// length, in CIDR string form (e.g. "31.13.72.0/24"). ok is false for an
// unparseable or non-IPv4 addr -- shouldn't happen, Flow.Dst always comes
// from the kernel's own conntrack table, but this package treats that
// the same way isPrivateDst does rather than risk a panic on it.
func containingBlock(addr string, bits int) (block string, ok bool) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", false
	}
	v4 := ip.To4()
	if v4 == nil {
		return "", false
	}
	mask := net.CIDRMask(bits, 32)
	return (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String(), true
}
