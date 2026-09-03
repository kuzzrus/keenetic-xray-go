package botcontrol

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

func TestFailoverEvents_RendersAndCloses(t *testing.T) {
	in := make(chan failover.Event, 4)
	ctx, cancel := context.WithCancel(context.Background())
	out := FailoverEvents(ctx, in)

	in <- failover.Event{Kind: failover.EventDaemonStart, At: time.Now()}
	if ev := recvEvent(t, out); ev.Kind != "daemon_start" || !strings.Contains(ev.Text, "демон") {
		t.Errorf("daemon_start rendered as %+v", ev)
	}

	in <- failover.Event{
		Kind: failover.EventFailover,
		From: failover.StateActivePrimary,
		To:   failover.StateCooldown,
		At:   time.Now(),
	}
	if ev := recvEvent(t, out); ev.Kind != "failover" || !strings.Contains(ev.Text, "backup") {
		t.Errorf("failover rendered as %+v", ev)
	}

	cancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-out:
			if !ok {
				return // closed on ctx cancel -- correct
			}
		case <-deadline:
			t.Fatal("FailoverEvents did not close its output after ctx cancel")
		}
	}
}

func recvEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a rendered event")
		return Event{}
	}
}
