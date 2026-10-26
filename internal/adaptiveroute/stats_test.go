package adaptiveroute

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestStats_WindowsAndTotals(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	now := time.Date(2026, 10, 25, 20, 30, 0, 0, time.UTC)

	RecordEvent(EventProbation, now.Add(-5*time.Minute)) // inside the hour
	RecordEvent(EventProbation, now.Add(-5*time.Minute))
	RecordEvent(EventConfirmed, now.Add(-5*time.Minute))
	RecordEvent(EventLapsed, now.Add(-3*time.Hour))     // inside the day, outside the hour
	RecordEvent(EventProbation, now.Add(-30*time.Hour)) // older than the day
	RecordEvent(Event(-1), now)                         // junk is ignored
	RecordEvent(numEvents, now)

	s := Stats(now)
	if s.Total.Of(EventProbation) != 3 || s.Total.Of(EventConfirmed) != 1 || s.Total.Of(EventLapsed) != 1 {
		t.Errorf("Total = %+v", s.Total)
	}
	if s.Hour.Of(EventProbation) != 2 || s.Hour.Of(EventConfirmed) != 1 || s.Hour.Of(EventLapsed) != 0 {
		t.Errorf("Hour = %+v, want 2 probations + 1 confirmed and no lapse", s.Hour)
	}
	if s.Day.Of(EventProbation) != 2 || s.Day.Of(EventLapsed) != 1 {
		t.Errorf("Day = %+v, want the 30-hour-old probation out and the 3-hour-old lapse in", s.Day)
	}
	if s.Since.IsZero() || !s.Since.Equal(now.Add(-5*time.Minute)) && !s.Since.Equal(now.Add(-3*time.Hour)) && !s.Since.Equal(now.Add(-30*time.Hour)) {
		t.Errorf("Since = %v, want the time of the first recorded event", s.Since)
	}
	if got := (Counts{}).Of(Event(99)); got != 0 {
		t.Errorf("Counts.Of(out of range) = %d, want 0", got)
	}
}

func TestStats_PrunesOldBuckets(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 400; i++ { // ~66 hours of ten-minute buckets
		RecordEvent(EventProbation, base.Add(time.Duration(i)*statsBucket))
	}
	stats.mu.Lock()
	n := len(stats.buckets)
	stats.mu.Unlock()
	if limit := int(statsKeep/statsBucket) + 8; n > limit {
		t.Errorf("kept %d buckets, want at most %d", n, limit)
	}
	if got := Stats(base.Add(399 * statsBucket)).Total.Of(EventProbation); got != 400 {
		t.Errorf("Total = %d, want every event counted even after pruning", got)
	}
}

func TestNotes_RefreshKeepsTheOriginalClient(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	at := time.Now()
	NoteAdded(Note{Addr: "1.2.3.4", Tier: "probation", Reason: "silent-syn", Client: "192.168.1.50", Proto: "tcp", DPort: 443, At: at})
	NoteAdded(Note{Addr: "1.2.3.4", Tier: "confirmed", Reason: "judged-good", At: at.Add(time.Second)})

	n, ok := LookupNote("1.2.3.4")
	if !ok || n.Tier != "confirmed" || n.Reason != "judged-good" {
		t.Fatalf("note = %+v, %v", n, ok)
	}
	if n.Client != "192.168.1.50" || n.Proto != "tcp" || n.DPort != 443 {
		t.Errorf("note = %+v, want the client that tripped it kept across the promotion", n)
	}
	ForgetNote("1.2.3.4")
	if _, ok := LookupNote("1.2.3.4"); ok {
		t.Error("ForgetNote left the note behind")
	}
	NoteAdded(Note{}) // no address: ignored
}

func TestNotes_AreBounded(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	base := time.Now()
	for i := 0; i < maxNotes*2; i++ {
		NoteAdded(Note{Addr: fmt.Sprintf("10.%d.%d.1", i/256, i%256), At: base.Add(time.Duration(i) * time.Second)})
	}
	stats.mu.Lock()
	n := len(stats.notes)
	stats.mu.Unlock()
	if n > maxNotes {
		t.Errorf("kept %d notes, want at most %d", n, maxNotes)
	}
	if _, ok := LookupNote(fmt.Sprintf("10.%d.%d.1", (maxNotes*2-1)/256, (maxNotes*2-1)%256)); !ok {
		t.Error("the newest note was evicted")
	}
}

func TestMembersDetailed(t *testing.T) {
	oOut := ipsetOutput
	t.Cleanup(func() { ipsetOutput = oOut })
	ipsetOutput = func(_ context.Context, args ...string) (string, error) {
		return "create keenetic_xray_adaptive hash:net family inet hashsize 1024 maxelem 65536 timeout 0\n" +
			"add keenetic_xray_adaptive 149.154.167.41 timeout 21246\n" +
			"add keenetic_xray_adaptive 31.13.72.0/24 timeout 1799\n" +
			"add keenetic_xray_adaptive 1.2.3.4\n" +
			"add other_set 9.9.9.9 timeout 5\n" +
			"add keenetic_xray_adaptive 5.6.7.8 timeout abc\n" +
			"add keenetic_xray_adaptive 203.0.113.5 timeout 0\n", nil // how a real kernel prints an element that never expires
	}
	got, err := MembersDetailed(context.Background(), "keenetic_xray_adaptive")
	if err != nil {
		t.Fatal(err)
	}
	want := []Member{
		{Addr: "149.154.167.41", Left: 21246 * time.Second, HasTimeout: true},
		{Addr: "31.13.72.0/24", Left: 1799 * time.Second, HasTimeout: true},
		{Addr: "1.2.3.4"},
		{Addr: "5.6.7.8"},
		{Addr: "203.0.113.5"},
	}
	if len(got) != len(want) {
		t.Fatalf("members = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("member %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	addrs, err := Members(context.Background(), "keenetic_xray_adaptive")
	if err != nil || len(addrs) != 5 || addrs[0] != "149.154.167.41" {
		t.Errorf("Members = %v, %v; want the bare elements (no timeout text)", addrs, err)
	}
}
