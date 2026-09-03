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

func TestRenderFailoverEvent_Kinds(t *testing.T) {
	cases := []struct {
		name     string
		in       failover.Event
		wantKind string
	}{
		{"daemon start", failover.Event{Kind: failover.EventDaemonStart}, "daemon_start"},
		{"settle onto primary", failover.Event{Kind: failover.EventFailover, From: failover.StateCooldown, To: failover.StateActivePrimary}, "recovered"},
		{"confirmed recovery", failover.Event{Kind: failover.EventFailover, From: failover.StateConfirmingRecovery, To: failover.StateCooldown}, "recovered"},
		{"fail away from primary", failover.Event{Kind: failover.EventFailover, From: failover.StateActivePrimary, To: failover.StateCooldown}, "failover"},
		{"rollback", failover.Event{Kind: failover.EventFailover, From: failover.StateConfirmingRecovery, To: failover.StateActiveBackup}, "failover"},
	}
	for _, c := range cases {
		if got := renderFailoverEvent(c.in).Kind; got != c.wantKind {
			t.Errorf("%s: Kind = %q, want %q", c.name, got, c.wantKind)
		}
	}
}

func TestTelegramBot_NotifyEvent_MutesFlapButNotRecovery(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	b := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}

	for i := 0; i < flapThreshold+3; i++ {
		b.NotifyEvent("r1", Event{Kind: "failover", Text: "⚡ flap"})
	}
	b.NotifyEvent("r1", Event{Kind: "recovered", Text: "⚡ primary восстановился"})
	b.NotifyEvent("r1", Event{Kind: "failover", Text: "⚡ flap again"})

	texts := fake.sentTexts()
	rawFlaps := 0
	for _, tx := range texts {
		if strings.Contains(tx, "⚡ flap") {
			rawFlaps++
		}
	}
	// (flapThreshold-1) before the mute + 1 more after "recovered" clears it.
	if rawFlaps > flapThreshold {
		t.Errorf("too many raw flap messages got through: %d\n%v", rawFlaps, texts)
	}
	if !anyContains(texts, "приглушены") {
		t.Errorf("expected a mute notice, got %v", texts)
	}
	if !anyContains(texts, "восстановился") {
		t.Errorf("a 'recovered' event must always be delivered, got %v", texts)
	}
}

func anyContains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func TestTelegramBot_FlapCheck(t *testing.T) {
	b := &TelegramBot{}

	for i := 0; i < flapThreshold-1; i++ {
		if drop, notice := b.flapCheck("r1"); drop || notice != "" {
			t.Fatalf("event %d passed through wrong: drop=%v notice=%q", i, drop, notice)
		}
	}
	drop, notice := b.flapCheck("r1")
	if drop || notice == "" {
		t.Fatalf("threshold event: want a mute notice, got drop=%v notice=%q", drop, notice)
	}
	if drop, _ := b.flapCheck("r1"); !drop {
		t.Fatal("event after the mute should be dropped")
	}

	b.clearFlap("r1")
	if drop, notice := b.flapCheck("r1"); drop || notice != "" {
		t.Fatalf("after clearFlap: drop=%v notice=%q", drop, notice)
	}

	// A different router is tracked independently.
	if drop, notice := b.flapCheck("r2"); drop || notice != "" {
		t.Fatalf("r2 first event: drop=%v notice=%q", drop, notice)
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
