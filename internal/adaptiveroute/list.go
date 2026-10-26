package adaptiveroute

import (
	"context"
	"sort"
	"time"
)

// Entry is one line of the "what is redirected" list: an ipset member and
// whatever the daemon remembers about how it got there.
type Entry struct {
	Member
	Note  Note
	Known bool // false: no note -- it predates this daemon run, or came from outside
}

// Tier is the entry's tier (one of the Tier* constants), "" when unknown.
func (e Entry) Tier() string {
	if !e.Known {
		return ""
	}
	return e.Note.Tier
}

// ListEntries joins the redirect set with the daemon's in-memory notes,
// ordered for display. Meant for the process that runs the classify loop
// (the bot handler); a CLI in another process has no notes of its own and
// joins the published snapshot instead (JoinEntries).
func ListEntries(ctx context.Context, setName string) ([]Entry, error) {
	members, err := MembersDetailed(ctx, setName)
	if err != nil {
		return nil, err
	}
	return JoinEntries(members, LookupNote), nil
}

// JoinEntries pairs each member with its note (lookup may be any source of
// notes) and sorts the result with SortEntries.
func JoinEntries(members []Member, lookup func(addr string) (Note, bool)) []Entry {
	out := make([]Entry, 0, len(members))
	for _, m := range members {
		e := Entry{Member: m}
		if lookup != nil {
			e.Note, e.Known = lookup(m.Addr)
		}
		out = append(out, e)
	}
	SortEntries(out)
	return out
}

// tierRank orders tiers for display: what has proved itself first, the
// provisional and the unknown last.
func tierRank(tier string) int {
	switch tier {
	case TierConfirmed:
		return 0
	case TierL7SNI:
		return 1
	case TierBlock:
		return 2
	case TierProbation:
		return 3
	}
	return 4
}

// SortEntries orders by tier, then the longest time left first (within one
// tier that is the most recently added), then address.
func SortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if ra, rb := tierRank(a.Tier()), tierRank(b.Tier()); ra != rb {
			return ra < rb
		}
		la, lb := left(a.Member), left(b.Member)
		if la != lb {
			return la > lb
		}
		return a.Addr < b.Addr
	})
}

// left is the sort key for time-to-live: an entry that never expires counts
// as longer than any that does.
func left(m Member) time.Duration {
	if !m.HasTimeout {
		return 1<<63 - 1
	}
	return m.Left
}

// Tally counts a list by tier.
type Tally struct {
	Total, Probation, Confirmed, Block, L7SNI, Unknown int
}

// TallyEntries counts es by tier.
func TallyEntries(es []Entry) Tally {
	var t Tally
	for _, e := range es {
		t.Total++
		switch e.Tier() {
		case TierProbation:
			t.Probation++
		case TierConfirmed:
			t.Confirmed++
		case TierBlock:
			t.Block++
		case TierL7SNI:
			t.L7SNI++
		default:
			t.Unknown++
		}
	}
	return t
}
