package botcontrol

import (
	"context"

	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

// FailoverEvents adapts a failover.Daemon's event stream into the
// protocol Event values the agent forwards, rendering each to Russian
// text here -- where describeTransition already lives -- so the failover
// package stays free of UX strings. The returned channel is closed when
// ctx is cancelled or the source channel closes.
func FailoverEvents(ctx context.Context, in <-chan failover.Event) <-chan Event {
	out := make(chan Event, cap(in))
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case fe, ok := <-in:
				if !ok {
					return
				}
				select {
				case out <- renderFailoverEvent(fe):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out
}

func renderFailoverEvent(fe failover.Event) Event {
	switch fe.Kind {
	case failover.EventDaemonStart:
		return Event{Kind: "daemon_start", Text: "▶️ демон запущен", Time: fe.At}
	case failover.EventFailover:
		tr := failover.Transition{From: fe.From, To: fe.To}
		kind := "failover"
		if isRecoveryTransition(tr) {
			kind = "recovered" // good news: always delivered, clears any flap mute
		}
		return Event{Kind: kind, Text: "⚡ " + describeTransition(tr), Time: fe.At}
	default:
		return Event{Kind: "unknown", Text: fe.From.String() + " → " + fe.To.String(), Time: fe.At}
	}
}

// isRecoveryTransition is true for the state changes that mean "primary
// is healthy again": the confirmed recovery, and settling onto primary.
func isRecoveryTransition(t failover.Transition) bool {
	return t.To == failover.StateActivePrimary ||
		(t.To == failover.StateCooldown && t.From == failover.StateConfirmingRecovery)
}
