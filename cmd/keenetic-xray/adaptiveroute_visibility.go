package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// What adaptive routing tells the operator about itself: log lines that say
// why an address was redirected and what became of it, the counters behind
// the bot status, and the operator's never-route list. The decisions are the
// classifier's (internal/classifier); this file only reports them and
// enforces the list.

const (
	// adaptiveSnapshotInterval: the daemon publishes its counters and notes
	// (adaptiveRouteSnapshotPath) at most this often, and only after a change.
	adaptiveSnapshotInterval = 15 * time.Second

	// adaptiveSummaryInterval: how often the classify loop logs a one-line
	// summary of the last hour.
	adaptiveSummaryInterval = time.Hour

	// adaptiveExclusionSweepTimeout bounds applyExclusionChange's ipset and
	// conntrack work. It runs on the classify loop's own goroutine, so like
	// every other external call there it must not be able to hang the loop
	// (see adaptiveRouteOpTimeout).
	adaptiveExclusionSweepTimeout = 30 * time.Second
)

// shortTTL renders a TTL for a log line: "60s", "30m", "6h".
func shortTTL(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", int64(d/time.Hour))
	case d >= 2*time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", int64(d/time.Minute))
	}
	return fmt.Sprintf("%ds", int64(d/time.Second))
}

// flowText names the connection that tripped a probation: "192.168.1.50
// tcp/443", "" when the action carries no flow.
func flowText(f classifier.Flow) string {
	if f.Src == "" {
		return ""
	}
	return fmt.Sprintf("%s %s/%d", f.Src, f.Proto, f.DPort)
}

// noteAdaptiveAction records what one applied Action means -- the counters
// the bot status shows, the per-address note its list shows -- and returns
// the log line for it ("" for plumbing such as a conntrack delete). Call it
// only for an action that actually took effect.
//
// The line keeps its old first words ("adaptive-route: redirecting <addr>")
// so anything already grepping for them still finds it, and adds in brackets
// what the log could not say before: which tier the address entered, for how
// long, what tripped it and which LAN client's connection it was.
func noteAdaptiveAction(a classifier.Action, now time.Time) string {
	what := a.IP
	if strings.Contains(a.IP, "/") {
		what = "subnet " + a.IP
	}
	switch a.Kind {
	case classifier.ActionAddIP:
		note := adaptiveroute.Note{Addr: a.IP, Tier: string(a.Tier), Reason: a.Reason, At: now}
		switch a.Tier {
		case classifier.TierProbation:
			adaptiveroute.RecordEvent(adaptiveroute.EventProbation, now)
			note.Client, note.Proto, note.DPort = a.Flow.Src, a.Flow.Proto, a.Flow.DPort
			adaptiveroute.NoteAdded(note)
			line := fmt.Sprintf("adaptive-route: redirecting %s [probation %s: %s", what, shortTTL(a.TTL), a.Reason)
			if f := flowText(a.Flow); f != "" {
				line += ", client " + f
			}
			return line + "]"
		case classifier.TierConfirmed:
			// The note keeps what originally tripped the address -- that is
			// what the list is for; "it was judged good" is the tier itself.
			note.Reason = ""
			adaptiveroute.NoteAdded(note)
			if a.Reason == classifier.ReasonOKRefresh {
				return fmt.Sprintf("adaptive-route: refreshed %s [confirmed %s]", what, shortTTL(a.TTL))
			}
			adaptiveroute.RecordEvent(adaptiveroute.EventConfirmed, now)
			return fmt.Sprintf("adaptive-route: redirecting %s [confirmed %s: %s]", what, shortTTL(a.TTL), a.Reason)
		case classifier.TierBlock:
			adaptiveroute.RecordEvent(adaptiveroute.EventBlock, now)
			adaptiveroute.NoteAdded(note)
			return fmt.Sprintf("adaptive-route: redirecting %s [block %s: %s]", what, shortTTL(a.TTL), a.Reason)
		}
		return "adaptive-route: redirecting " + what
	case classifier.ActionRemoveIP:
		switch a.Reason {
		case classifier.ReasonJudgedFailed, classifier.ReasonOKFailed:
			adaptiveroute.RecordEvent(adaptiveroute.EventFailed, now)
		case classifier.ReasonExcluded:
			adaptiveroute.RecordEvent(adaptiveroute.EventExcluded, now)
		}
		adaptiveroute.ForgetNote(a.IP)
		if a.Reason == "" {
			return "adaptive-route: no longer redirecting " + what
		}
		return fmt.Sprintf("adaptive-route: no longer redirecting %s [%s]", what, a.Reason)
	}
	return ""
}

// recordLapsed counts the probations State.Expire dropped without a verdict
// and forgets the notes of addresses that left every tier. The count is the
// number the whole visibility work exists for: on the first real router dump,
// 36 "redirecting" lines for 29 addresses turned out to be 9 confirmed and 20
// that simply lapsed -- invisible until something counted them.
func recordLapsed(state *classifier.State, lapsed []classifier.Lapsed, now time.Time) {
	for _, l := range lapsed {
		if l.Tier == classifier.TierProbation {
			adaptiveroute.RecordEvent(adaptiveroute.EventLapsed, now)
		}
		// The same address can still be live under the other protocol or as
		// a promoted entry; its note belongs to that.
		if !liveInState(state, l.Addr, now) {
			adaptiveroute.ForgetNote(l.Addr)
		}
	}
}

func liveInState(state *classifier.State, addr string, now time.Time) bool {
	for i := 0; i < 2; i++ {
		for _, set := range []map[string]time.Time{state.Test[i], state.OK[i], state.Blocks[i]} {
			if exp, ok := set[addr]; ok && exp.After(now) {
				return true
			}
		}
	}
	return false
}

// seedAdaptiveNotes gives the entries the classifier state loaded from disk
// a note, so the list can tell a probation from a confirmed address right
// after a restart instead of calling everything "без пометки" until each one
// is next touched. What tripped them is gone with the old process.
func seedAdaptiveNotes(state *classifier.State, now time.Time) {
	for i := 0; i < 2; i++ {
		for addr, exp := range state.Test[i] {
			if exp.After(now) {
				adaptiveroute.NoteIfAbsent(adaptiveroute.Note{Addr: addr, Tier: adaptiveroute.TierProbation, Reason: adaptiveroute.ReasonRestored, At: now})
			}
		}
		for addr, exp := range state.OK[i] {
			if exp.After(now) {
				adaptiveroute.NoteIfAbsent(adaptiveroute.Note{Addr: addr, Tier: adaptiveroute.TierConfirmed, Reason: adaptiveroute.ReasonRestored, At: now})
			}
		}
	}
}

// adaptiveSummaryLine is the hourly log line: what became of the last hour's
// probations. ok is false for a quiet hour -- no line then, the log has
// enough in it already.
func adaptiveSummaryLine(now time.Time) (line string, ok bool) {
	return summaryLineFor(adaptiveroute.Stats(now).Hour)
}

// summaryLineFor formats one hour's counts; adaptiveSummaryLine's pure half.
func summaryLineFor(h adaptiveroute.Counts) (line string, ok bool) {
	if h.Quiet() {
		return "", false
	}
	return fmt.Sprintf("adaptive-route: last hour: %d probations -> %d confirmed, %d lapsed without a verdict, %d failed; %d subnets widened, %d excluded",
		h.Of(adaptiveroute.EventProbation), h.Of(adaptiveroute.EventConfirmed), h.Of(adaptiveroute.EventLapsed),
		h.Of(adaptiveroute.EventFailed), h.Of(adaptiveroute.EventBlock), h.Of(adaptiveroute.EventExcluded)), true
}

// applyExclusionChange enforces a never-route list the classify loop just saw
// change (or load for the first time): the classifier forgets everything the
// list covers and the redirect set gives it up, including entries the
// classifier never tracked -- l7sni additions and whatever survived a
// restart. cfg must already carry the list (UserExcluded/UserExcludedOverlap).
func applyExclusionChange(ctx context.Context, cfg *classifier.Config, state *classifier.State, ex *adaptiveroute.Exclusions, now time.Time, logf func(string, ...any)) {
	note := ""
	if ex.Skipped > 0 {
		note = fmt.Sprintf(", %d unrecognised lines ignored", ex.Skipped)
	}
	logf("adaptive-route: exclusion list: %d entries%s", ex.Len(), note)

	applyAdaptiveRouteActions(ctx, classifier.ClrPurgeExcluded(cfg, state, now), logf)

	sctx, cancel := context.WithTimeout(ctx, adaptiveExclusionSweepTimeout)
	defer cancel()
	removed, err := adaptiveroute.SweepExcluded(sctx, adaptiveRouteIPSet, ex, keenetic.DeleteConntrackToward)
	for _, m := range removed {
		adaptiveroute.RecordEvent(adaptiveroute.EventExcluded, now)
		logf("adaptive-route: no longer redirecting %s [%s]", m, classifier.ReasonExcluded)
	}
	if err != nil {
		logf("adaptive-route: sweeping excluded entries from the redirect set: %v", err)
	}
}

// --- CLI: transport adaptive list | excluded | exclude | include ---

// adaptiveRouteList prints what is redirected right now and why. The set
// itself is read live from the kernel; the reasons, clients and counters come
// from the snapshot the daemon publishes (adaptiveRouteSnapshotPath), because
// this process cannot see the daemon's memory.
func adaptiveRouteList(cfg *config.Config) error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	members, err := adaptiveroute.MembersDetailed(ctx, adaptiveRouteIPSet)
	if err != nil {
		return fmt.Errorf("чтение ipset %s: %w", adaptiveRouteIPSet, err)
	}
	snap, _ := adaptiveroute.ReadSnapshot(adaptiveRouteSnapshotPath())
	var lookup func(string) (adaptiveroute.Note, bool)
	if snap != nil {
		lookup = snap.Lookup
	}
	ex, _ := adaptiveroute.LoadExclusions(adaptiveroute.ExclusionsPath(configPath()))
	if !cfg.AdaptiveRoute.Enabled {
		fmt.Println("адаптивная маршрутизация выключена (transport adaptive on)")
	}
	printAdaptiveList(os.Stdout, adaptiveroute.JoinEntries(members, lookup), snap, ex)
	return nil
}

// printAdaptiveList renders the list for a terminal.
func printAdaptiveList(w io.Writer, entries []adaptiveroute.Entry, snap *adaptiveroute.Snapshot, ex *adaptiveroute.Exclusions) {
	t := adaptiveroute.TallyEntries(entries)
	fmt.Fprintf(w, "Перенаправляется сейчас: %d", t.Total)
	if t.Total > 0 {
		fmt.Fprintf(w, " (проба %d · подтверждено %d · подсетей %d", t.Probation, t.Confirmed, t.Block)
		if t.L7SNI > 0 {
			fmt.Fprintf(w, " · по имени %d", t.L7SNI)
		}
		if t.Unknown > 0 {
			fmt.Fprintf(w, " · без пометки %d", t.Unknown)
		}
		fmt.Fprint(w, ")")
	}
	fmt.Fprintf(w, " · исключений: %d\n", ex.Len())

	if snap != nil {
		fmt.Fprintf(w, "За последний час: %s\n", snap.Stats.Hour.SummaryRU())
		fmt.Fprintf(w, "За сутки: %s\n", snap.Stats.Day.SummaryRU())
		fmt.Fprintf(w, "(счётчики и пометки — из снимка демона от %s, обнуляются при его перезапуске)\n",
			snap.At.Local().Format("15:04:05"))
	} else {
		fmt.Fprintln(w, "Снимка демона нет — причины и счётчики недоступны (демон не запущен или ещё ничего не ловил).")
	}
	if len(entries) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%-18s %-12s %-9s %-22s %s\n", "АДРЕС", "ЯРУС", "ОСТАЛОСЬ", "КЛИЕНТ", "ПРИЧИНА")
	for _, e := range entries {
		left, client, reason := "—", "—", "—"
		if e.HasTimeout {
			left = adaptiveroute.FormatLeft(e.Left)
		}
		if e.Known {
			reason = adaptiveroute.ReasonLabel(e.Note.Reason)
			if f := e.Note.Flow(); f != "" {
				client = f
			}
			if e.Note.Host != "" {
				reason += " (" + e.Note.Host + ")"
			}
		}
		fmt.Fprintf(w, "%-18s %-12s %-9s %-22s %s\n", e.Addr, adaptiveroute.TierLabel(e.Tier()), left, client, reason)
	}
}

// adaptiveRouteExcluded prints the operator's never-route list.
func adaptiveRouteExcluded() error {
	path := adaptiveroute.ExclusionsPath(configPath())
	ex, err := adaptiveroute.LoadExclusions(path)
	if err != nil {
		return err
	}
	if ex.Len() == 0 {
		fmt.Println("список исключений пуст — добавить: keenetic-xray transport adaptive exclude <ip|a.b.c.d/nn>")
	} else {
		fmt.Printf("исключения (%d) — в адаптивное перенаправление не попадают никогда:\n", ex.Len())
		for _, e := range ex.Entries() {
			fmt.Println("  " + e)
		}
	}
	if ex.Skipped > 0 {
		fmt.Printf("⚠️ строк в %s не распознано и пропущено: %d\n", path, ex.Skipped)
	}
	return nil
}

// adaptiveRouteExclude adds addresses or networks to the never-route list and
// takes whatever they cover out of the redirect set right away, so the effect
// does not depend on the daemon being alive; a running daemon notices the file
// on its next tick and drops the same entries from the classifier's memory.
func adaptiveRouteExclude(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray transport adaptive exclude <ip|a.b.c.d/nn> [<ip|a.b.c.d/nn> ...]")
	}
	canon := make([]string, len(args))
	for i, a := range args {
		c, err := adaptiveroute.NormalizeExclusion(a)
		if err != nil {
			return err
		}
		canon[i] = c
	}
	path := adaptiveroute.ExclusionsPath(configPath())
	for _, c := range canon {
		_, added, err := adaptiveroute.AddExclusion(path, c)
		if err != nil {
			return err
		}
		if added {
			fmt.Printf("исключено: %s\n", c)
		} else {
			fmt.Printf("уже в списке: %s\n", c)
		}
	}
	if !keenetic.Available() {
		return nil
	}
	ex, err := adaptiveroute.LoadExclusions(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), adaptiveExclusionSweepTimeout)
	defer cancel()
	removed, err := adaptiveroute.SweepExcluded(ctx, adaptiveRouteIPSet, ex, keenetic.DeleteConntrackToward)
	if len(removed) > 0 {
		fmt.Printf("убрано из перенаправления: %s — открытые соединения к ним оборваны, переподключатся напрямую\n", strings.Join(removed, ", "))
	}
	if err != nil {
		fmt.Printf("предупреждение: не всё удалось убрать из ipset: %v\n", err)
	}
	return nil
}

// adaptiveRouteInclude takes entries back off the never-route list. Nothing is
// redirected as a result: the classifier simply may catch the address again if
// it looks blocked.
func adaptiveRouteInclude(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray transport adaptive include <ip|a.b.c.d/nn> [<ip|a.b.c.d/nn> ...]")
	}
	path := adaptiveroute.ExclusionsPath(configPath())
	for _, a := range args {
		c, removed, err := adaptiveroute.RemoveExclusion(path, a)
		if err != nil {
			return err
		}
		if removed {
			fmt.Printf("возвращено: %s — классификатор снова может его ловить\n", c)
		} else {
			fmt.Printf("не было в списке: %s\n", c)
		}
	}
	return nil
}
