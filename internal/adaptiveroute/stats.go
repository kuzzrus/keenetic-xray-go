package adaptiveroute

import (
	"sort"
	"sync"
	"time"
)

// What the daemon remembers about adaptive routing's own activity, in
// memory only. The classify loop writes it, the bot handler (same process)
// reads it for the status screen and the "что перенаправлено" list; neither
// needs it to survive a restart, and nothing here touches the flash.
//
// Exists because the log alone could not answer the one question that
// decides whether the detector needs tuning: of the addresses it puts on
// probation, how many are ever confirmed? (On the first real router dump,
// 36 "redirecting" lines for 29 addresses were 9 confirmed and 20 that
// lapsed without a verdict -- invisible without this.)

// Event is one kind of thing worth counting.
type Event int

const (
	// EventProbation: an address entered the provisional (test) tier.
	EventProbation Event = iota
	// EventConfirmed: a probation address was judged good and promoted.
	EventConfirmed
	// EventLapsed: a probation ended without a verdict -- nothing to judge.
	EventLapsed
	// EventFailed: a probation, or a confirmed address, was judged failed.
	EventFailed
	// EventBlock: a whole network was widened into the redirect.
	EventBlock
	// EventExcluded: an entry was dropped because the operator excluded it.
	EventExcluded
	numEvents
)

// Counts holds one count per Event.
type Counts [numEvents]int

// Of returns the count for ev.
func (c Counts) Of(ev Event) int {
	if ev < 0 || ev >= numEvents {
		return 0
	}
	return c[ev]
}

const (
	statsBucket  = 10 * time.Minute
	statsKeep    = 25 * time.Hour
	hourBuckets  = 6   // 60 minutes
	dayBuckets   = 144 // 24 hours
	maxNotes     = 512
	noteStaleAge = 7 * 24 * time.Hour
)

var stats struct {
	mu      sync.Mutex
	since   time.Time
	total   Counts
	buckets map[int64]*Counts // keyed by unix/600
	notes   map[string]Note

	// dirty: something changed since the last SnapshotIfDirty wrote the
	// snapshot file; lastWrite: when that was.
	dirty     bool
	lastWrite time.Time
}

func init() { resetStats() }

func resetStats() {
	stats.mu.Lock()
	stats.since = time.Time{}
	stats.total = Counts{}
	stats.buckets = map[int64]*Counts{}
	stats.notes = map[string]Note{}
	stats.dirty = false
	stats.lastWrite = time.Time{}
	stats.mu.Unlock()
}

func bucketKey(t time.Time) int64 { return t.Unix() / int64(statsBucket/time.Second) }

// RecordEvent counts ev at time at.
func RecordEvent(ev Event, at time.Time) {
	if ev < 0 || ev >= numEvents {
		return
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if stats.since.IsZero() {
		stats.since = at
	}
	stats.dirty = true
	stats.total[ev]++
	k := bucketKey(at)
	b := stats.buckets[k]
	if b == nil {
		b = &Counts{}
		stats.buckets[k] = b
	}
	b[ev]++
	if len(stats.buckets) > int(statsKeep/statsBucket)+8 {
		old := bucketKey(at.Add(-statsKeep))
		for key := range stats.buckets {
			if key < old {
				delete(stats.buckets, key)
			}
		}
	}
}

// StatsSnapshot is the counters as of one moment. Hour and Day cover the
// last 60 minutes and 24 hours at ten-minute granularity; Total counts
// everything since the first event this process recorded (Since).
type StatsSnapshot struct {
	Since            time.Time
	Total, Hour, Day Counts
}

// Stats returns the current counters.
func Stats(now time.Time) StatsSnapshot {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	s := StatsSnapshot{Since: stats.since, Total: stats.total}
	cur := bucketKey(now)
	for k, b := range stats.buckets {
		age := cur - k
		if age < 0 || age >= dayBuckets {
			continue
		}
		for i := Event(0); i < numEvents; i++ {
			s.Day[i] += b[i]
			if age < hourBuckets {
				s.Hour[i] += b[i]
			}
		}
	}
	return s
}

// The tiers a Note can carry. The first three are the classifier's own
// (classifier.Tier); l7sni is the other way into the redirect set: an address
// the SNI/Host capture matched against the operator's routes lists.
const (
	TierProbation = "probation"
	TierConfirmed = "confirmed"
	TierBlock     = "block"
	TierL7SNI     = "l7sni"
)

// Reasons that do not come from the classifier.
const (
	// ReasonRestored: the entry was in the classifier state loaded at startup,
	// so nothing is known about what tripped it.
	ReasonRestored = "restored"
	// ReasonL7SNI: the hostname matched one of the operator's routes lists.
	ReasonL7SNI = "l7sni"
)

// Note is what the daemon knows about why one address is in the redirect
// set: the tier it entered, the classifier's reason, and which LAN client's
// flow tripped it (probation entries carry the triggering flow).
type Note struct {
	Addr   string
	Tier   string // one of the Tier* constants
	Reason string
	Client string // LAN source of the triggering flow, "" when unknown
	Proto  string // "tcp" | "udp", "" when unknown
	DPort  uint
	Host   string // the hostname the address was matched by (l7sni only)
	At     time.Time
}

// NoteAdded remembers n for the list screen. A later note for the same
// address replaces the earlier one, except that a promotion or a refresh does
// not erase what originally tripped it: a note that names no client keeps the
// earlier client, port and hostname, and one without a reason keeps the
// earlier reason.
func NoteAdded(n Note) {
	if n.Addr == "" {
		return
	}
	stats.mu.Lock()
	defer stats.mu.Unlock()
	if prev, ok := stats.notes[n.Addr]; ok {
		if n.Client == "" {
			n.Client, n.Proto, n.DPort = prev.Client, prev.Proto, prev.DPort
			if n.Host == "" {
				n.Host = prev.Host
			}
		}
		if n.Reason == "" {
			n.Reason = prev.Reason
		}
	}
	stats.dirty = true
	stats.notes[n.Addr] = n
	if len(stats.notes) > maxNotes {
		type kv struct {
			k string
			t time.Time
		}
		all := make([]kv, 0, len(stats.notes))
		for k, v := range stats.notes {
			all = append(all, kv{k, v.At})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
		for _, e := range all[:len(all)-maxNotes+maxNotes/8] {
			delete(stats.notes, e.k)
		}
	}
}

// LookupNote returns what is remembered about addr.
func LookupNote(addr string) (Note, bool) {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	n, ok := stats.notes[addr]
	if ok && time.Since(n.At) > noteStaleAge {
		return Note{}, false
	}
	return n, ok
}

// NoteIfAbsent remembers n only when nothing is known about n.Addr yet --
// for entries restored from the classifier's saved state at startup, which
// must not overwrite what a live event already recorded.
func NoteIfAbsent(n Note) {
	if n.Addr == "" {
		return
	}
	stats.mu.Lock()
	_, have := stats.notes[n.Addr]
	stats.mu.Unlock()
	if !have {
		NoteAdded(n)
	}
}

// ForgetNote drops the remembered note for addr (an entry that was removed).
func ForgetNote(addr string) {
	stats.mu.Lock()
	if _, ok := stats.notes[addr]; ok {
		delete(stats.notes, addr)
		stats.dirty = true
	}
	stats.mu.Unlock()
}

// allNotes returns a copy of every remembered note, oldest first.
func allNotes() []Note {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	out := make([]Note, 0, len(stats.notes))
	for _, n := range stats.notes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.Before(out[j].At)
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
