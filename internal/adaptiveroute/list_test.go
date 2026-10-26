package adaptiveroute

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stubIPSet makes ipset list print listing and records every ipset change.
func stubIPSet(t *testing.T, listing string) *[]string {
	t.Helper()
	oOut, oRun := ipsetOutput, ipsetRun
	t.Cleanup(func() { ipsetOutput, ipsetRun = oOut, oRun })
	ipsetOutput = func(_ context.Context, _ ...string) (string, error) { return listing, nil }
	var ran []string
	ipsetRun = func(_ context.Context, args ...string) error {
		ran = append(ran, strings.Join(args, " "))
		return nil
	}
	return &ran
}

const sampleListing = "create keenetic_xray_adaptive hash:net family inet hashsize 1024 maxelem 65536 timeout 0\n" +
	"add keenetic_xray_adaptive 1.1.1.1 timeout 40\n" + // probation
	"add keenetic_xray_adaptive 2.2.2.2 timeout 21000\n" + // confirmed
	"add keenetic_xray_adaptive 3.3.3.3 timeout 20000\n" + // confirmed, older
	"add keenetic_xray_adaptive 31.13.72.0/24 timeout 1500\n" + // block
	"add keenetic_xray_adaptive 4.4.4.4 timeout 3000\n" + // l7sni
	"add keenetic_xray_adaptive 5.5.5.5 timeout 900\n" + // no note
	"add keenetic_xray_adaptive 6.6.6.6\n" // no note, never expires

func seedSampleNotes(t *testing.T) {
	t.Helper()
	resetStats()
	t.Cleanup(resetStats)
	now := time.Now()
	NoteAdded(Note{Addr: "1.1.1.1", Tier: TierProbation, Reason: "silent-syn", Client: "192.168.1.50", Proto: "tcp", DPort: 443, At: now})
	NoteAdded(Note{Addr: "2.2.2.2", Tier: TierConfirmed, Reason: "judged-good", Client: "192.168.1.51", Proto: "tcp", DPort: 443, At: now})
	NoteAdded(Note{Addr: "3.3.3.3", Tier: TierConfirmed, Reason: "judged-good", At: now})
	NoteAdded(Note{Addr: "31.13.72.0/24", Tier: TierBlock, Reason: "block-widen", At: now})
	NoteAdded(Note{Addr: "4.4.4.4", Tier: TierL7SNI, Reason: ReasonL7SNI, Host: "youtube.com", At: now})
}

func TestListEntries_JoinsNotesAndOrdersForDisplay(t *testing.T) {
	seedSampleNotes(t)
	stubIPSet(t, sampleListing)

	got, err := ListEntries(context.Background(), "keenetic_xray_adaptive")
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, e := range got {
		order = append(order, e.Addr)
	}
	// confirmed (longest left first), l7sni, block, probation, then the unknown ones
	// (the entry that never expires sorts ahead of the one that does).
	want := "2.2.2.2,3.3.3.3,4.4.4.4,31.13.72.0/24,1.1.1.1,6.6.6.6,5.5.5.5"
	if strings.Join(order, ",") != want {
		t.Errorf("order = %v\nwant    %s", order, want)
	}

	byAddr := map[string]Entry{}
	for _, e := range got {
		byAddr[e.Addr] = e
	}
	if e := byAddr["1.1.1.1"]; !e.Known || e.Tier() != TierProbation || e.Note.Client != "192.168.1.50" || e.Left != 40*time.Second {
		t.Errorf("1.1.1.1 = %+v", e)
	}
	if e := byAddr["4.4.4.4"]; e.Note.Host != "youtube.com" {
		t.Errorf("4.4.4.4 host = %q, want youtube.com", e.Note.Host)
	}
	if e := byAddr["5.5.5.5"]; e.Known || e.Tier() != "" {
		t.Errorf("5.5.5.5 = %+v, want unknown (no note)", e)
	}
	if e := byAddr["6.6.6.6"]; e.HasTimeout {
		t.Errorf("6.6.6.6 = %+v, want no timeout", e)
	}

	tally := TallyEntries(got)
	if tally != (Tally{Total: 7, Probation: 1, Confirmed: 2, Block: 1, L7SNI: 1, Unknown: 2}) {
		t.Errorf("tally = %+v", tally)
	}
}

func TestListEntries_IPSetError(t *testing.T) {
	oOut := ipsetOutput
	t.Cleanup(func() { ipsetOutput = oOut })
	ipsetOutput = func(context.Context, ...string) (string, error) { return "", os.ErrNotExist }
	if _, err := ListEntries(context.Background(), "x"); err == nil {
		t.Error("want the ipset error passed up")
	}
}

func TestJoinEntries_FromASnapshot(t *testing.T) {
	snap := &Snapshot{Notes: []Note{{Addr: "1.1.1.1", Tier: TierConfirmed}}}
	got := JoinEntries([]Member{{Addr: "1.1.1.1"}, {Addr: "2.2.2.2"}}, snap.Lookup)
	if len(got) != 2 || got[0].Addr != "1.1.1.1" || !got[0].Known || got[1].Known {
		t.Errorf("entries = %+v", got)
	}
	var nilSnap *Snapshot
	if _, ok := nilSnap.Lookup("1.1.1.1"); ok {
		t.Error("a nil snapshot knows nothing")
	}
	if e := JoinEntries([]Member{{Addr: "9.9.9.9"}}, nil); len(e) != 1 || e[0].Known {
		t.Errorf("no lookup: %+v", e)
	}
}

// --- SweepExcluded ---

func TestSweepExcluded(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	ran := stubIPSet(t, "add keenetic_xray_adaptive 1.1.1.1 timeout 40\n"+
		"add keenetic_xray_adaptive 8.8.8.8 timeout 40\n"+
		"add keenetic_xray_adaptive 31.13.72.0/24 timeout 900\n"+
		"add keenetic_xray_adaptive 77.88.0.0/18 timeout 900\n")
	NoteAdded(Note{Addr: "8.8.8.8", Tier: TierConfirmed, At: time.Now()})

	ex := parseExclusions("8.8.8.0/28\n31.13.72.9\n")
	var cleaned []string
	removed, err := SweepExcluded(context.Background(), "keenetic_xray_adaptive", ex,
		func(_ context.Context, m string) { cleaned = append(cleaned, m) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(removed, ",") != "8.8.8.8,31.13.72.0/24" {
		t.Errorf("removed = %v, want the address inside the excluded /28 and the block holding the excluded address", removed)
	}
	if strings.Join(cleaned, ",") != "8.8.8.8,31.13.72.0/24" {
		t.Errorf("cleanup ran for %v", cleaned)
	}
	wantRan := "del keenetic_xray_adaptive 8.8.8.8 -exist|del keenetic_xray_adaptive 31.13.72.0/24 -exist"
	if strings.Join(*ran, "|") != wantRan {
		t.Errorf("ipset calls = %q", *ran)
	}
	if _, ok := LookupNote("8.8.8.8"); ok {
		t.Error("the note of a swept entry should be gone")
	}
	if got := Stats(time.Now()).Total.Of(EventExcluded); got != 0 {
		t.Errorf("SweepExcluded counted %d exclusions; the classify loop owns that counter", got)
	}
}

func TestSweepExcluded_EmptyListTouchesNothing(t *testing.T) {
	ran := stubIPSet(t, "add keenetic_xray_adaptive 1.1.1.1\n")
	removed, err := SweepExcluded(context.Background(), "keenetic_xray_adaptive", &Exclusions{}, nil)
	if err != nil || len(removed) != 0 || len(*ran) != 0 {
		t.Errorf("removed %v, err %v, ipset calls %q; want nothing", removed, err, *ran)
	}
	if removed, err := SweepExcluded(context.Background(), "x", nil, nil); err != nil || removed != nil {
		t.Errorf("nil list: %v, %v", removed, err)
	}
}

func TestSweepExcluded_ReportsTheFirstFailureButKeepsGoing(t *testing.T) {
	ran := stubIPSet(t, "add s 1.1.1.1\nadd s 1.1.1.2\n")
	calls := 0
	ipsetRun = func(_ context.Context, args ...string) error {
		calls++
		if calls == 1 {
			return os.ErrPermission
		}
		*ran = append(*ran, strings.Join(args, " "))
		return nil
	}
	removed, err := SweepExcluded(context.Background(), "s", parseExclusions("1.1.1.0/24\n"), nil)
	if err == nil {
		t.Error("want the first failure reported")
	}
	if len(removed) != 1 || removed[0] != "1.1.1.2" {
		t.Errorf("removed = %v, want the second member despite the first failing", removed)
	}
}

// --- labels ---

func TestFormatLeft(t *testing.T) {
	cases := map[time.Duration]string{
		-time.Second:                    "0с",
		0:                               "0с",
		42 * time.Second:                "42с",
		time.Minute:                     "1м",
		17*time.Minute + 59*time.Second: "17м",
		time.Hour:                       "1ч",
		5*time.Hour + 54*time.Minute:    "5ч 54м",
		25 * time.Hour:                  "25ч",
	}
	for d, want := range cases {
		if got := FormatLeft(d); got != want {
			t.Errorf("FormatLeft(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestLabelsCoverEveryReasonTheClassifierEmits(t *testing.T) {
	for _, r := range []string{
		"silent-syn", "closed-no-reply", "quic-no-reply", "tcp-stall", "late-stall",
		"judged-good", "judged-failed", "ok-failed", "ok-refresh", "block-widen", "excluded",
		ReasonRestored, ReasonL7SNI,
	} {
		if got := ReasonLabel(r); got == r || got == "" {
			t.Errorf("ReasonLabel(%q) = %q: no Russian wording", r, got)
		}
	}
	if got := ReasonLabel("something-new"); got != "something-new" {
		t.Errorf("an unknown reason should pass through, got %q", got)
	}
	for _, tier := range []string{TierProbation, TierConfirmed, TierBlock, TierL7SNI, ""} {
		if TierLabel(tier) == "" || TierIcon(tier) == "" {
			t.Errorf("tier %q has no label or icon", tier)
		}
	}
}

func TestNoteFlow(t *testing.T) {
	if got := (Note{Client: "192.168.1.50", Proto: "tcp", DPort: 443}).Flow(); got != "192.168.1.50 tcp/443" {
		t.Errorf("Flow = %q", got)
	}
	if got := (Note{Client: "192.168.1.50"}).Flow(); got != "192.168.1.50" {
		t.Errorf("Flow without a port = %q", got)
	}
	if got := (Note{}).Flow(); got != "" {
		t.Errorf("Flow of an unknown client = %q", got)
	}
}

func TestCountsSummaryRU(t *testing.T) {
	var c Counts
	c[EventProbation], c[EventConfirmed], c[EventLapsed], c[EventFailed] = 14, 3, 9, 2
	got := c.SummaryRU()
	want := "проб 14 · подтверждено 3 · истекло без вердикта 9 · не помогло 2"
	if got != want {
		t.Errorf("SummaryRU = %q, want %q", got, want)
	}
	c[EventBlock], c[EventExcluded] = 1, 2
	if got := c.SummaryRU(); !strings.HasSuffix(got, "· подсетей 1 · исключено 2") {
		t.Errorf("SummaryRU with blocks and exclusions = %q", got)
	}
	if (Counts{}).Quiet() != true || c.Quiet() {
		t.Error("Quiet misreports")
	}
}

// --- snapshot ---

func TestSnapshot_RoundTrip(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	now := time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC)
	RecordEvent(EventProbation, now.Add(-time.Minute))
	RecordEvent(EventConfirmed, now.Add(-time.Minute))
	NoteAdded(Note{Addr: "1.2.3.4", Tier: TierConfirmed, Reason: "judged-good", Client: "192.168.1.50", Proto: "tcp", DPort: 443, At: now})

	path := filepath.Join(t.TempDir(), "snap.json")
	if err := WriteSnapshot(path, now); err != nil {
		t.Fatal(err)
	}
	snap, err := ReadSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if !snap.At.Equal(now) || snap.Stats.Hour.Of(EventProbation) != 1 || snap.Stats.Total.Of(EventConfirmed) != 1 {
		t.Errorf("snapshot = %+v", snap)
	}
	if n, ok := snap.Lookup("1.2.3.4"); !ok || n.Client != "192.168.1.50" || n.DPort != 443 {
		t.Errorf("note = %+v, %v", n, ok)
	}
}

func TestReadSnapshot_RejectsOtherVersionsAndJunk(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "v9.json")
	_ = os.WriteFile(other, []byte(`{"version":9,"at":"2026-10-25T20:00:00Z"}`), 0o644)
	if _, err := ReadSnapshot(other); !os.IsNotExist(err) {
		t.Errorf("a snapshot of another version = %v, want it reported as absent", err)
	}
	junk := filepath.Join(dir, "junk.json")
	_ = os.WriteFile(junk, []byte("not json"), 0o644)
	if _, err := ReadSnapshot(junk); err == nil {
		t.Error("junk should fail to parse")
	}
	if _, err := ReadSnapshot(filepath.Join(dir, "missing.json")); !os.IsNotExist(err) {
		t.Errorf("missing file = %v", err)
	}
}

func TestSnapshotIfDirty_WritesOnlyWhenChangedAndDue(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	path := filepath.Join(t.TempDir(), "snap.json")
	t0 := time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC)

	if wrote, err := SnapshotIfDirty(path, t0, 10*time.Second); wrote || err != nil {
		t.Fatalf("clean state wrote=%v err=%v; want nothing to do", wrote, err)
	}
	NoteAdded(Note{Addr: "1.2.3.4", Tier: TierProbation, At: t0})
	if wrote, err := SnapshotIfDirty(path, t0, 10*time.Second); !wrote || err != nil {
		t.Fatalf("first change wrote=%v err=%v; want a write", wrote, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("snapshot file missing after the write")
	}
	NoteAdded(Note{Addr: "5.6.7.8", Tier: TierProbation, At: t0})
	if wrote, _ := SnapshotIfDirty(path, t0.Add(3*time.Second), 10*time.Second); wrote {
		t.Error("wrote again inside the minimum interval")
	}
	if wrote, _ := SnapshotIfDirty(path, t0.Add(11*time.Second), 10*time.Second); !wrote {
		t.Error("did not write once the interval passed and the change was still pending")
	}
	if wrote, _ := SnapshotIfDirty(path, t0.Add(30*time.Second), 10*time.Second); wrote {
		t.Error("wrote with nothing new")
	}
	ForgetNote("5.6.7.8")
	if wrote, _ := SnapshotIfDirty(path, t0.Add(60*time.Second), 10*time.Second); !wrote {
		t.Error("forgetting a note is a change too")
	}
}

func TestSnapshotIfDirty_FailureStaysPending(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	t0 := time.Date(2026, 10, 25, 20, 0, 0, 0, time.UTC)
	NoteAdded(Note{Addr: "1.2.3.4", At: t0})

	bad := filepath.Join(t.TempDir(), "no-such-dir", "snap.json")
	if wrote, err := SnapshotIfDirty(bad, t0, time.Second); wrote || err == nil {
		t.Fatalf("wrote=%v err=%v; want a failure", wrote, err)
	}
	good := filepath.Join(t.TempDir(), "snap.json")
	if wrote, err := SnapshotIfDirty(good, t0.Add(2*time.Second), time.Second); !wrote || err != nil {
		t.Errorf("retry wrote=%v err=%v; the failed write must stay pending", wrote, err)
	}
}

func TestNoteIfAbsent(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	at := time.Now()
	NoteAdded(Note{Addr: "1.2.3.4", Tier: TierConfirmed, Reason: "judged-good", At: at})
	NoteIfAbsent(Note{Addr: "1.2.3.4", Tier: TierProbation, Reason: ReasonRestored, At: at})
	NoteIfAbsent(Note{Addr: "5.6.7.8", Tier: TierProbation, Reason: ReasonRestored, At: at})
	NoteIfAbsent(Note{})
	if n, _ := LookupNote("1.2.3.4"); n.Reason != "judged-good" {
		t.Errorf("NoteIfAbsent overwrote a live note: %+v", n)
	}
	if n, ok := LookupNote("5.6.7.8"); !ok || n.Reason != ReasonRestored {
		t.Errorf("NoteIfAbsent did not add a missing note: %+v, %v", n, ok)
	}
}

func TestNoteAdded_KeepsTheHostAcrossARefresh(t *testing.T) {
	resetStats()
	t.Cleanup(resetStats)
	at := time.Now()
	NoteAdded(Note{Addr: "1.2.3.4", Tier: TierL7SNI, Host: "youtube.com", Client: "192.168.1.50", At: at})
	NoteAdded(Note{Addr: "1.2.3.4", Tier: TierL7SNI, At: at.Add(time.Second)})
	if n, _ := LookupNote("1.2.3.4"); n.Host != "youtube.com" || n.Client != "192.168.1.50" {
		t.Errorf("note after a refresh = %+v", n)
	}
}
