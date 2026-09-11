package botcontrol

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

// Merge fans several Event channels into one. The output closes once
// every input has closed (or ctx is done); nil inputs are ignored. Used
// to fold a one-off stream (the post-update watcher) in alongside the
// failover events.
func Merge(ctx context.Context, chans ...<-chan Event) <-chan Event {
	out := make(chan Event)
	var wg sync.WaitGroup
	for _, c := range chans {
		if c == nil {
			continue
		}
		wg.Add(1)
		go func(c <-chan Event) {
			defer wg.Done()
			for ev := range c {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}(c)
	}
	go func() { wg.Wait(); close(out) }()
	return out
}

// FailoverEvents adapts a failover.Daemon's event stream into the
// protocol Event values the agent forwards, rendering each to Russian
// text here -- where describeTransition already lives -- so the failover
// package stays free of UX strings. The returned channel is closed when
// ctx is cancelled or the source channel closes.
//
// It also coalesces: one primary-drop-and-recover cycle produces five
// state transitions (leave primary, cooldown, test recovery, switch
// back, confirm, cooldown), but only the two an operator cares about --
// "left primary" and "primary is back" -- are forwarded. The internal
// churn in between is dropped. The goroutine keeps just enough state (the
// time primary was last left) to annotate the recovery with how long the
// backup carried traffic.
func FailoverEvents(ctx context.Context, in <-chan failover.Event) <-chan Event {
	out := make(chan Event, cap(in))
	go func() {
		defer close(out)
		var leftPrimaryAt time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case fe, ok := <-in:
				if !ok {
					return
				}
				ev, forward := renderFailoverEvent(fe, &leftPrimaryAt)
				if !forward {
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

// stuckWatchInterval is how often WatchStuckPrimary re-checks the
// snapshot. Overridden in tests.
var stuckWatchInterval = time.Minute

// WatchStuckPrimary forwards `in` unchanged and, on a 1-minute ticker,
// emits ONE "primary_stuck" advisory when production has been carrying
// traffic on backup for longer than `after` without primary recovering
// -- the operator otherwise only learns this by opening /doctor. Re-armed
// the moment primary is live again. after <= 0 disables the watch (in is
// still forwarded verbatim).
func WatchStuckPrimary(ctx context.Context, snap func(context.Context) (failover.Snapshot, bool), after time.Duration, in <-chan Event) <-chan Event {
	out := make(chan Event, cap(in)+1)
	go func() {
		defer close(out)

		var tick <-chan time.Time
		if after > 0 {
			t := time.NewTicker(stuckWatchInterval)
			defer t.Stop()
			tick = t.C
		}
		warned := false

		send := func(ev Event) bool {
			select {
			case out <- ev:
				return true
			case <-ctx.Done():
				return false
			}
		}

		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-in:
				if !ok {
					return
				}
				if !send(ev) {
					return
				}
			case <-tick:
				s, ok := snap(ctx)
				if !ok {
					continue
				}
				if s.LiveRole == failover.RolePrimary {
					warned = false
					continue
				}
				if warned {
					continue
				}
				since, ok := backupSince(s)
				if !ok || time.Since(since) < after {
					continue
				}
				warned = true
				send(Event{
					Kind: "primary_stuck",
					Text: fmt.Sprintf("⚠️ primary недоступен уже %s — трафик держит backup. "+
						"Детали: /doctor. Закрепить backup: /switch <роутер> backup, "+
						"либо поменять местами источники в 🔗 Источники.", shortDur(time.Since(since))),
					Time: time.Now(),
				})
			}
		}
	}()
	return out
}

// backupSince is when production was last pointed at backup: the `.At` of
// the most recent transition leaving StateActivePrimary, unless the
// history shows a return to primary after it. Falls back to the daemon
// start time (history truncated / on backup since boot).
func backupSince(s failover.Snapshot) (time.Time, bool) {
	if s.LiveRole != failover.RoleBackup {
		return time.Time{}, false
	}
	for i := len(s.Transitions) - 1; i >= 0; i-- {
		tr := s.Transitions[i]
		if tr.To == failover.StateActivePrimary {
			break
		}
		if tr.From == failover.StateActivePrimary {
			return tr.At, true
		}
	}
	if !s.StartedAt.IsZero() {
		return s.StartedAt, true
	}
	return time.Time{}, false
}

// withReason appends the classified probe-failure reason in parens, if
// there is one -- text unchanged for transitions that weren't triggered by
// a probe failure (e.g. an operator-forced switch has no Detail).
func withReason(text, reason string) string {
	if reason == "" {
		return text
	}
	return text + " (" + reason + ")"
}

// renderFailoverEvent turns one daemon event into a forwardable Event, or
// reports forward=false for the transient state changes that are just
// process narration. leftPrimaryAt is read/written across calls to time
// the "was on backup N" note.
func renderFailoverEvent(fe failover.Event, leftPrimaryAt *time.Time) (Event, bool) {
	if fe.Kind == failover.EventDaemonStart {
		return Event{Kind: "daemon_start", Text: "▶️ демон запущен", Time: fe.At}, true
	}
	if fe.Kind == failover.EventXrayCrashLoop {
		return Event{Kind: "xray_crashloop", Time: fe.At, Text: "⚠️ xray падает и перезапускается (" +
			fe.Detail + ") — глянь /logs и профиль (адрес/ключи/транспорт)"}, true
	}
	if fe.Kind != failover.EventFailover {
		return Event{Kind: "unknown", Text: fe.From.String() + " → " + fe.To.String(), Time: fe.At}, true
	}

	tr := failover.Transition{At: fe.At, From: fe.From, To: fe.To}
	switch {
	case tr.From == failover.StateActivePrimary && tr.To == failover.StateCooldown:
		// Primary failed its live checks; production is now on backup.
		*leftPrimaryAt = fe.At
		return Event{Kind: "failover", Text: "⚡ " + withReason(describeTransition(tr), fe.Detail), Time: fe.At}, true

	case tr.From == failover.StateConfirmingRecovery && tr.To == failover.StateCooldown:
		// Primary came back and held the live confirmation.
		text := "✅ " + describeTransition(tr)
		if !leftPrimaryAt.IsZero() {
			text += fmt.Sprintf(" (был на backup %s)", shortDur(fe.At.Sub(*leftPrimaryAt)))
		}
		*leftPrimaryAt = time.Time{}
		return Event{Kind: "recovered", Text: text, Time: fe.At}, true

	case tr.From == failover.StateConfirmingRecovery && tr.To == failover.StateActiveBackup:
		// Recovery attempt failed the live confirmation; staying on backup.
		return Event{Kind: "failover", Text: "⚡ " + withReason(describeTransition(tr), fe.Detail), Time: fe.At}, true

	default:
		// TestingRecovery / ConfirmingRecovery entry, the post-recovery
		// Cooldown->ActivePrimary settle, any other Cooldown hop -- all
		// internal, no notification.
		return Event{}, false
	}
}
