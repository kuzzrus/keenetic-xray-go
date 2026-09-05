package botcontrol

import (
	"context"
	"fmt"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

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

// renderFailoverEvent turns one daemon event into a forwardable Event, or
// reports forward=false for the transient state changes that are just
// process narration. leftPrimaryAt is read/written across calls to time
// the "was on backup N" note.
func renderFailoverEvent(fe failover.Event, leftPrimaryAt *time.Time) (Event, bool) {
	if fe.Kind == failover.EventDaemonStart {
		return Event{Kind: "daemon_start", Text: "▶️ демон запущен", Time: fe.At}, true
	}
	if fe.Kind != failover.EventFailover {
		return Event{Kind: "unknown", Text: fe.From.String() + " → " + fe.To.String(), Time: fe.At}, true
	}

	tr := failover.Transition{At: fe.At, From: fe.From, To: fe.To}
	switch {
	case tr.From == failover.StateActivePrimary && tr.To == failover.StateCooldown:
		// Primary failed its live checks; production is now on backup.
		*leftPrimaryAt = fe.At
		return Event{Kind: "failover", Text: "⚡ " + describeTransition(tr), Time: fe.At}, true

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
		return Event{Kind: "failover", Text: "⚡ " + describeTransition(tr), Time: fe.At}, true

	default:
		// TestingRecovery / ConfirmingRecovery entry, the post-recovery
		// Cooldown->ActivePrimary settle, any other Cooldown hop -- all
		// internal, no notification.
		return Event{}, false
	}
}
