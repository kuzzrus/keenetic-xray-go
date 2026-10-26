package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// The counters and notes live in package adaptiveroute's process-wide state;
// every test here starts from a clean one by driving only its public
// surface: events are read back through Stats, notes through LookupNote.

func hourCounts(now time.Time) adaptiveroute.Counts { return adaptiveroute.Stats(now).Hour }

func probationAction(ip, reason string) classifier.Action {
	return classifier.Action{
		Kind: classifier.ActionAddIP, IP: ip, TTL: 60 * time.Second,
		Tier: classifier.TierProbation, Reason: reason,
		Flow: classifier.Flow{Src: "192.168.1.50", Dst: ip, Proto: "tcp", L4Proto: 6, DPort: 443},
	}
}

func TestNoteAdaptiveAction_ProbationSaysWhoAndWhy(t *testing.T) {
	now := time.Now()
	ip := "198.51.100.10"
	t.Cleanup(func() { adaptiveroute.ForgetNote(ip) })

	line := noteAdaptiveAction(probationAction(ip, classifier.ReasonSilentSYN), now)
	want := "adaptive-route: redirecting 198.51.100.10 [probation 60s: silent-syn, client 192.168.1.50 tcp/443]"
	if line != want {
		t.Errorf("line = %q\nwant   %q", line, want)
	}
	n, ok := adaptiveroute.LookupNote(ip)
	if !ok || n.Tier != adaptiveroute.TierProbation || n.Reason != "silent-syn" || n.Client != "192.168.1.50" || n.Proto != "tcp" || n.DPort != 443 {
		t.Errorf("note = %+v, %v", n, ok)
	}
}

func TestNoteAdaptiveAction_CountsEachOutcome(t *testing.T) {
	now := time.Now()
	base := hourCounts(now)
	ips := []string{"198.51.100.21", "198.51.100.22", "198.51.100.23", "198.51.100.24"}
	t.Cleanup(func() {
		for _, ip := range ips {
			adaptiveroute.ForgetNote(ip)
		}
		adaptiveroute.ForgetNote("203.0.113.0/24")
	})

	noteAdaptiveAction(probationAction(ips[0], classifier.ReasonSilentSYN), now)
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: ips[0], TTL: 6 * time.Hour, Tier: classifier.TierConfirmed, Reason: classifier.ReasonJudgedGood}, now)
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: "203.0.113.0/24", TTL: 30 * time.Minute, Tier: classifier.TierBlock, Reason: classifier.ReasonBlockWiden}, now)
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionRemoveIP, IP: ips[1], Reason: classifier.ReasonJudgedFailed}, now)
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionRemoveIP, IP: ips[2], Reason: classifier.ReasonOKFailed}, now)
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionRemoveIP, IP: ips[3], Reason: classifier.ReasonExcluded}, now)
	// a refresh is not a new confirmation, and conntrack plumbing is not an event at all
	noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: ips[0], TTL: 6 * time.Hour, Tier: classifier.TierConfirmed, Reason: classifier.ReasonOKRefresh}, now)
	if got := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionDeleteConntrack}, now); got != "" {
		t.Errorf("a conntrack delete logged %q", got)
	}
	if got := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionDeleteConntrackDst, IP: ips[0]}, now); got != "" {
		t.Errorf("a conntrack delete logged %q", got)
	}

	got := hourCounts(now)
	diff := func(ev adaptiveroute.Event) int { return got.Of(ev) - base.Of(ev) }
	for ev, want := range map[adaptiveroute.Event]int{
		adaptiveroute.EventProbation: 1, adaptiveroute.EventConfirmed: 1, adaptiveroute.EventBlock: 1,
		adaptiveroute.EventFailed: 2, adaptiveroute.EventExcluded: 1, adaptiveroute.EventLapsed: 0,
	} {
		if d := diff(ev); d != want {
			t.Errorf("event %d moved by %d, want %d", ev, d, want)
		}
	}
}

func TestNoteAdaptiveAction_ConfirmationKeepsWhatTrippedIt(t *testing.T) {
	now := time.Now()
	ip := "198.51.100.30"
	t.Cleanup(func() { adaptiveroute.ForgetNote(ip) })

	noteAdaptiveAction(probationAction(ip, classifier.ReasonTCPStall), now)
	line := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: ip, TTL: 6 * time.Hour, Tier: classifier.TierConfirmed, Reason: classifier.ReasonJudgedGood}, now.Add(time.Second))
	if line != "adaptive-route: redirecting 198.51.100.30 [confirmed 6h: judged-good]" {
		t.Errorf("line = %q", line)
	}
	n, _ := adaptiveroute.LookupNote(ip)
	if n.Tier != adaptiveroute.TierConfirmed || n.Reason != "tcp-stall" || n.Client != "192.168.1.50" {
		t.Errorf("note after confirmation = %+v, want the tier moved up and the original trigger and client kept", n)
	}

	if line := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: ip, TTL: 6 * time.Hour, Tier: classifier.TierConfirmed, Reason: classifier.ReasonOKRefresh}, now); !strings.HasPrefix(line, "adaptive-route: refreshed 198.51.100.30") {
		t.Errorf("refresh line = %q", line)
	}
	if n, _ := adaptiveroute.LookupNote(ip); n.Reason != "tcp-stall" {
		t.Errorf("a refresh overwrote the trigger: %+v", n)
	}
}

func TestNoteAdaptiveAction_RemoveForgetsTheNoteAndNamesTheReason(t *testing.T) {
	now := time.Now()
	ip := "198.51.100.40"
	noteAdaptiveAction(probationAction(ip, classifier.ReasonSilentSYN), now)

	line := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionRemoveIP, IP: ip, Reason: classifier.ReasonJudgedFailed}, now)
	if line != "adaptive-route: no longer redirecting 198.51.100.40 [judged-failed]" {
		t.Errorf("line = %q", line)
	}
	if _, ok := adaptiveroute.LookupNote(ip); ok {
		t.Error("the note of a removed address should be gone")
	}
	if line := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionRemoveIP, IP: "203.0.113.0/24"}, now); line != "adaptive-route: no longer redirecting subnet 203.0.113.0/24" {
		t.Errorf("reasonless subnet removal line = %q", line)
	}
}

func TestNoteAdaptiveAction_UntieredAddIsStillLogged(t *testing.T) {
	// An Action from before tiers existed (or from a test) still logs the old way.
	line := noteAdaptiveAction(classifier.Action{Kind: classifier.ActionAddIP, IP: "198.51.100.50"}, time.Now())
	if line != "adaptive-route: redirecting 198.51.100.50" {
		t.Errorf("line = %q", line)
	}
}

func TestShortTTL(t *testing.T) {
	cases := map[time.Duration]string{
		60 * time.Second:          "60s",
		90 * time.Second:          "90s",
		2 * time.Minute:           "2m",
		30 * time.Minute:          "30m",
		90 * time.Minute:          "90m",
		time.Hour:                 "1h",
		6 * time.Hour:             "6h",
		6*time.Hour + time.Second: "21601s",
		0:                         "0s",
	}
	for d, want := range cases {
		if got := shortTTL(d); got != want {
			t.Errorf("shortTTL(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestRecordLapsed_CountsUnjudgedProbationsOnly(t *testing.T) {
	now := time.Now()
	base := hourCounts(now)
	state := classifier.NewState()
	// 198.51.100.61 lapsed as a TCP probation but is still confirmed over UDP.
	state.OK[1]["198.51.100.61"] = now.Add(time.Hour)
	adaptiveroute.NoteAdded(adaptiveroute.Note{Addr: "198.51.100.60", Tier: adaptiveroute.TierProbation, At: now})
	adaptiveroute.NoteAdded(adaptiveroute.Note{Addr: "198.51.100.61", Tier: adaptiveroute.TierConfirmed, At: now})
	adaptiveroute.NoteAdded(adaptiveroute.Note{Addr: "198.51.100.62", Tier: adaptiveroute.TierConfirmed, At: now})
	t.Cleanup(func() {
		for _, ip := range []string{"198.51.100.60", "198.51.100.61", "198.51.100.62"} {
			adaptiveroute.ForgetNote(ip)
		}
	})

	recordLapsed(state, []classifier.Lapsed{
		{Addr: "198.51.100.60", Tier: classifier.TierProbation},
		{Addr: "198.51.100.61", Tier: classifier.TierProbation},
		{Addr: "198.51.100.62", Tier: classifier.TierConfirmed},
	}, now)

	if d := hourCounts(now).Of(adaptiveroute.EventLapsed) - base.Of(adaptiveroute.EventLapsed); d != 2 {
		t.Errorf("lapsed moved by %d, want 2 (the two probations; an expired confirmed entry is not a lapse)", d)
	}
	if _, ok := adaptiveroute.LookupNote("198.51.100.60"); ok {
		t.Error("a fully gone address should lose its note")
	}
	if _, ok := adaptiveroute.LookupNote("198.51.100.61"); !ok {
		t.Error("an address still confirmed under the other protocol must keep its note")
	}
	if _, ok := adaptiveroute.LookupNote("198.51.100.62"); ok {
		t.Error("an expired confirmed address should lose its note")
	}
}

func TestSeedAdaptiveNotes(t *testing.T) {
	now := time.Now()
	state := classifier.NewState()
	state.Test[0]["198.51.100.71"] = now.Add(30 * time.Second)
	state.OK[0]["198.51.100.72"] = now.Add(3 * time.Hour)
	state.OK[1]["198.51.100.73"] = now.Add(3 * time.Hour)
	state.OK[0]["198.51.100.74"] = now.Add(-time.Minute) // already expired
	t.Cleanup(func() {
		for _, ip := range []string{"198.51.100.71", "198.51.100.72", "198.51.100.73", "198.51.100.74"} {
			adaptiveroute.ForgetNote(ip)
		}
	})
	// A note a live event already recorded must survive the seeding.
	adaptiveroute.NoteAdded(adaptiveroute.Note{Addr: "198.51.100.72", Tier: adaptiveroute.TierConfirmed, Reason: "silent-syn", At: now})

	seedAdaptiveNotes(state, now)

	if n, ok := adaptiveroute.LookupNote("198.51.100.71"); !ok || n.Tier != adaptiveroute.TierProbation || n.Reason != adaptiveroute.ReasonRestored {
		t.Errorf("restored probation note = %+v, %v", n, ok)
	}
	if n, _ := adaptiveroute.LookupNote("198.51.100.72"); n.Reason != "silent-syn" {
		t.Errorf("seeding overwrote a live note: %+v", n)
	}
	if n, ok := adaptiveroute.LookupNote("198.51.100.73"); !ok || n.Tier != adaptiveroute.TierConfirmed {
		t.Errorf("restored confirmed note = %+v, %v", n, ok)
	}
	if _, ok := adaptiveroute.LookupNote("198.51.100.74"); ok {
		t.Error("an expired entry should not get a note")
	}
}

func TestSummaryLineFor(t *testing.T) {
	if line, ok := summaryLineFor(adaptiveroute.Counts{}); ok {
		t.Errorf("a quiet hour produced %q", line)
	}
	var h adaptiveroute.Counts
	h[adaptiveroute.EventProbation], h[adaptiveroute.EventConfirmed], h[adaptiveroute.EventLapsed] = 5, 2, 3
	line, ok := summaryLineFor(h)
	want := "adaptive-route: last hour: 5 probations -> 2 confirmed, 3 lapsed without a verdict, 0 failed; 0 subnets widened, 0 excluded"
	if !ok || line != want {
		t.Errorf("summary = %q, %v\nwant      %q", line, ok, want)
	}
	h[adaptiveroute.EventFailed], h[adaptiveroute.EventBlock], h[adaptiveroute.EventExcluded] = 1, 2, 4
	if line, _ := summaryLineFor(h); !strings.HasSuffix(line, "1 failed; 2 subnets widened, 4 excluded") {
		t.Errorf("summary = %q", line)
	}
}

func TestAdaptiveSummaryLine_ReadsTheLastHour(t *testing.T) {
	// Far from anything else this package records, so only this event falls in the window.
	now := time.Now().Add(1000 * time.Hour)
	if _, ok := adaptiveSummaryLine(now); ok {
		t.Fatal("the window should be quiet")
	}
	adaptiveroute.RecordEvent(adaptiveroute.EventProbation, now.Add(-time.Minute))
	if line, ok := adaptiveSummaryLine(now); !ok || !strings.Contains(line, "1 probations") {
		t.Errorf("summary = %q, %v", line, ok)
	}
}

func TestPrintAdaptiveList(t *testing.T) {
	now := time.Date(2026, 10, 25, 21, 7, 0, 0, time.UTC)
	entries := adaptiveroute.JoinEntries([]adaptiveroute.Member{
		{Addr: "149.154.167.41", Left: 5*time.Hour + 54*time.Minute, HasTimeout: true},
		{Addr: "31.13.72.0/24", Left: 24 * time.Minute, HasTimeout: true},
		{Addr: "198.51.100.9", Left: 41 * time.Second, HasTimeout: true},
		{Addr: "203.0.113.5", Left: time.Hour, HasTimeout: true},
	}, (&adaptiveroute.Snapshot{Notes: []adaptiveroute.Note{
		{Addr: "149.154.167.41", Tier: adaptiveroute.TierConfirmed, Reason: classifier.ReasonSilentSYN, Client: "192.168.1.50", Proto: "tcp", DPort: 443},
		{Addr: "31.13.72.0/24", Tier: adaptiveroute.TierBlock, Reason: classifier.ReasonBlockWiden},
		{Addr: "198.51.100.9", Tier: adaptiveroute.TierL7SNI, Reason: adaptiveroute.ReasonL7SNI, Host: "youtube.com"},
	}}).Lookup)

	var snap adaptiveroute.Snapshot
	snap.At = now
	snap.Stats.Hour[adaptiveroute.EventProbation], snap.Stats.Hour[adaptiveroute.EventConfirmed], snap.Stats.Hour[adaptiveroute.EventLapsed] = 14, 3, 9
	ex, _ := adaptiveroute.LoadExclusions(filepath.Join(t.TempDir(), "none.txt"))

	var buf bytes.Buffer
	printAdaptiveList(&buf, entries, &snap, ex)
	out := buf.String()
	for _, want := range []string{
		"Перенаправляется сейчас: 4 (проба 0 · подтверждено 1 · подсетей 1 · по имени 1 · без пометки 1) · исключений: 0",
		"За последний час: проб 14 · подтверждено 3 · истекло без вердикта 9 · не помогло 0",
		"149.154.167.41",
		"подтверждён",
		"5ч 54м",
		"192.168.1.50 tcp/443",
		"SYN ушёл, ответа нет",
		"имя совпало со списком маршрутов (youtube.com)",
		"без пометки",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// confirmed first, the unknown last
	if strings.Index(out, "149.154.167.41") > strings.Index(out, "203.0.113.5") {
		t.Errorf("order wrong:\n%s", out)
	}

	buf.Reset()
	printAdaptiveList(&buf, nil, nil, nil)
	if !strings.Contains(buf.String(), "Снимка демона нет") || !strings.Contains(buf.String(), "Перенаправляется сейчас: 0") {
		t.Errorf("empty list without a snapshot printed:\n%s", buf.String())
	}
}

// --- CLI: exclude / include / excluded ---

func withExclusionConfig(t *testing.T) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfg)
	return adaptiveroute.ExclusionsPath(cfg)
}

func TestAdaptiveRouteExcludeAndInclude(t *testing.T) {
	path := withExclusionConfig(t)

	out := captureStdout(t, func() {
		if err := adaptiveRouteExclude([]string{"142.251.153.4", " 8.8.8.0/24 ", "142.251.153.4"}); err != nil {
			t.Errorf("exclude: %v", err)
		}
	})
	for _, want := range []string{"исключено: 142.251.153.4", "исключено: 8.8.8.0/24", "уже в списке: 142.251.153.4"} {
		if !strings.Contains(out, want) {
			t.Errorf("exclude output lacks %q:\n%s", want, out)
		}
	}
	ex, _ := adaptiveroute.LoadExclusions(path)
	if ex.Len() != 2 || !ex.Contains("8.8.8.8") || !ex.Contains("142.251.153.4") {
		t.Errorf("list after exclude = %v", ex.Entries())
	}

	out = captureStdout(t, func() {
		if err := adaptiveRouteExcluded(); err != nil {
			t.Errorf("excluded: %v", err)
		}
	})
	if !strings.Contains(out, "исключения (2)") || !strings.Contains(out, "142.251.153.4") || !strings.Contains(out, "8.8.8.0/24") {
		t.Errorf("excluded output:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := adaptiveRouteInclude([]string{"142.251.153.4", "1.1.1.1"}); err != nil {
			t.Errorf("include: %v", err)
		}
	})
	if !strings.Contains(out, "возвращено: 142.251.153.4") || !strings.Contains(out, "не было в списке: 1.1.1.1") {
		t.Errorf("include output:\n%s", out)
	}
	if ex, _ := adaptiveroute.LoadExclusions(path); ex.Len() != 1 || ex.Contains("142.251.153.4") {
		t.Errorf("list after include = %v", ex.Entries())
	}
}

func TestAdaptiveRouteExclude_RejectsBadInputBeforeWritingAnything(t *testing.T) {
	path := withExclusionConfig(t)
	if err := adaptiveRouteExclude([]string{"1.2.3.4", "not-an-ip"}); err == nil {
		t.Error("a bad entry in the batch should fail the whole call")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the valid entry was written although the batch failed (stat err = %v)", err)
	}
	if err := adaptiveRouteExclude(nil); err == nil {
		t.Error("exclude with no arguments should print the usage")
	}
	if err := adaptiveRouteInclude(nil); err == nil {
		t.Error("include with no arguments should print the usage")
	}
	if err := adaptiveRouteExclude([]string{"0.0.0.0/0"}); err == nil {
		t.Error("excluding the whole internet is a typo, not a request")
	}
}

func TestAdaptiveRouteExcluded_EmptyAndMalformed(t *testing.T) {
	path := withExclusionConfig(t)
	out := captureStdout(t, func() { _ = adaptiveRouteExcluded() })
	if !strings.Contains(out, "список исключений пуст") {
		t.Errorf("empty list output:\n%s", out)
	}
	if err := os.WriteFile(path, []byte("1.2.3.4\nthis is not an address\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { _ = adaptiveRouteExcluded() })
	if !strings.Contains(out, "исключения (1)") || !strings.Contains(out, "не распознано и пропущено: 1") {
		t.Errorf("malformed list output:\n%s", out)
	}
}

func TestTransportAdaptive_NewSubcommandsAreDispatched(t *testing.T) {
	path := withExclusionConfig(t)
	cfg := config.Default()
	var err error
	captureStdout(t, func() { err = transportAdaptive(cfg, []string{"exclude", "9.9.9.9"}) })
	if err != nil {
		t.Fatalf("transport adaptive exclude: %v", err)
	}
	if ex, _ := adaptiveroute.LoadExclusions(path); !ex.Contains("9.9.9.9") {
		t.Error("`transport adaptive exclude` did not reach the list")
	}
	captureStdout(t, func() { err = transportAdaptive(cfg, []string{"include", "9.9.9.9"}) })
	if err != nil {
		t.Fatalf("transport adaptive include: %v", err)
	}
	captureStdout(t, func() { err = transportAdaptive(cfg, []string{"excluded"}) })
	if err != nil {
		t.Fatalf("transport adaptive excluded: %v", err)
	}
	if err := transportAdaptive(cfg, []string{"list"}); err == nil || !strings.Contains(err.Error(), "ndmc") {
		t.Errorf("list off the router = %v, want the not-a-Keenetic error", err)
	}
	if err := transportAdaptive(cfg, []string{"bogus"}); err == nil || !strings.Contains(err.Error(), "exclude") {
		t.Errorf("unknown subcommand = %v, want a usage that names the new ones", err)
	}
}
