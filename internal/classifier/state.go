package classifier

import "time"

// neverExpires is the "ttl 0 = never expire" sentinel -- upstream uses
// 0x7fffffff as a time_t; this just needs to be further out than any
// real TTL this package uses, not an exact analog.
var neverExpires = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// ttlSet is a set of addresses with per-entry expiry -- the Go
// equivalent of upstream's state_set (src/state.c), a map instead of a
// growable C array since Go has one built in.
type ttlSet map[string]time.Time

func (s ttlSet) has(addr string, now time.Time) bool {
	exp, ok := s[addr]
	return ok && exp.After(now)
}

// at returns the entry's expiry, or the zero Time if absent or expired.
func (s ttlSet) at(addr string, now time.Time) time.Time {
	if exp, ok := s[addr]; ok && exp.After(now) {
		return exp
	}
	return time.Time{}
}

// add upserts addr with a fresh expiry ttl out from now (ttl<=0 = never
// expires). This is upstream's state_add with refresh=0 -- its only
// other mode, refresh=1 ("touch an existing entry's TTL, do nothing if
// absent"), has no caller this port needs.
func (s ttlSet) add(addr string, now time.Time, ttl time.Duration) {
	if ttl <= 0 {
		s[addr] = neverExpires
		return
	}
	s[addr] = now.Add(ttl)
}

func (s ttlSet) remove(addr string) { delete(s, addr) }

// expire drops every entry whose TTL has passed. Reads (has/at) already
// treat an expired entry as absent on their own, so this is only about
// not letting idle sets grow forever between real hits -- call it
// periodically, not on every read.
func (s ttlSet) expire(now time.Time) {
	for addr, exp := range s {
		if !exp.After(now) {
			delete(s, addr)
		}
	}
}

// State holds the two-tier (test/ok) classification state plus the
// watch/cooldown supporting sets, per protocol -- mirrors upstream's
// susanin_state (src/state.h) one-for-one. Index 0 = tcp, 1 = udp, same
// as upstream's st_test(st,udp)-style macros; use protoIndex to compute
// it from a Flow.
//
// Blocks has no upstream equivalent: CIDR blocks (string form, e.g.
// "31.13.72.0/24") that ClrBlockPromote has redirected wholesale, kept
// separately from Test/OK/Watch/Cooldown (which are always single
// addresses) purely so a block already promoted and not yet due for
// re-justification isn't re-emitted as a new Action on every tick.
type State struct {
	Test, OK, Watch, Cooldown [2]ttlSet
	Blocks                    [2]ttlSet

	// OKSince tracks when each OK-tier entry first arrived there (AR-05),
	// separately from ttlSet's own per-entry expiry -- see judgeOK's own
	// doc comment for what this backs. Not persisted across a restart,
	// for the same "not worth the complexity" reason persist.go already
	// gives for Watch/Blocks: the cap this supports is measured in days,
	// so losing a few hours of it to an occasional restart doesn't
	// matter in practice, and an entry loaded from disk with no OKSince
	// yet just lazily backfills its own the first time judgeOK's refresh
	// path touches it.
	OKSince [2]map[string]time.Time
}

// NewState returns an empty, ready-to-use State.
func NewState() *State {
	s := &State{}
	for i := 0; i < 2; i++ {
		s.Test[i] = ttlSet{}
		s.OK[i] = ttlSet{}
		s.Watch[i] = ttlSet{}
		s.Cooldown[i] = ttlSet{}
		s.Blocks[i] = ttlSet{}
		s.OKSince[i] = map[string]time.Time{}
	}
	return s
}

func protoIndex(udp bool) int {
	if udp {
		return 1
	}
	return 0
}

// Expire prunes every expired entry across all 10 sets. Cheap to call
// periodically (e.g. once per JUDGE pass, which already runs on a
// short interval) -- reads are always correct without it, this is only
// about bounding memory for state nothing has touched in a while.
func (s *State) Expire(now time.Time) {
	for i := 0; i < 2; i++ {
		s.Test[i].expire(now)
		s.OK[i].expire(now)
		s.Watch[i].expire(now)
		s.Cooldown[i].expire(now)
		s.Blocks[i].expire(now)
		for addr := range s.OKSince[i] {
			if !s.OK[i].has(addr, now) {
				delete(s.OKSince[i], addr)
			}
		}
	}
}
