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
		name        string
		in          failover.Event
		wantForward bool
		wantKind    string // only checked when wantForward
	}{
		{"daemon start", failover.Event{Kind: failover.EventDaemonStart}, true, "daemon_start"},
		{"fail away from primary", failover.Event{Kind: failover.EventFailover, From: failover.StateActivePrimary, To: failover.StateCooldown}, true, "failover"},
		{"confirmed recovery", failover.Event{Kind: failover.EventFailover, From: failover.StateConfirmingRecovery, To: failover.StateCooldown}, true, "recovered"},
		{"rollback", failover.Event{Kind: failover.EventFailover, From: failover.StateConfirmingRecovery, To: failover.StateActiveBackup}, true, "failover"},
		// Internal churn -- coalesced away, not notified.
		{"settle onto primary", failover.Event{Kind: failover.EventFailover, From: failover.StateCooldown, To: failover.StateActivePrimary}, false, ""},
		{"enter recovery testing", failover.Event{Kind: failover.EventFailover, From: failover.StateCooldown, To: failover.StateTestingRecovery}, false, ""},
		{"switch back, confirming", failover.Event{Kind: failover.EventFailover, From: failover.StateTestingRecovery, To: failover.StateConfirmingRecovery}, false, ""},
	}
	for _, c := range cases {
		var leftAt time.Time
		ev, forward := renderFailoverEvent(c.in, &leftAt)
		if forward != c.wantForward {
			t.Errorf("%s: forward = %v, want %v", c.name, forward, c.wantForward)
			continue
		}
		if forward && ev.Kind != c.wantKind {
			t.Errorf("%s: Kind = %q, want %q", c.name, ev.Kind, c.wantKind)
		}
	}
}

func TestRenderFailoverEvent_CoalescesAndTimesRecovery(t *testing.T) {
	var leftAt time.Time
	t0 := time.Now()

	// Leave primary.
	ev, fwd := renderFailoverEvent(failover.Event{
		Kind: failover.EventFailover, From: failover.StateActivePrimary, To: failover.StateCooldown, At: t0,
	}, &leftAt)
	if !fwd || ev.Kind != "failover" {
		t.Fatalf("leave-primary: fwd=%v kind=%q", fwd, ev.Kind)
	}

	// Internal churn -- all dropped.
	for _, tr := range [][2]failover.State{
		{failover.StateCooldown, failover.StateTestingRecovery},
		{failover.StateTestingRecovery, failover.StateConfirmingRecovery},
	} {
		if _, fwd := renderFailoverEvent(failover.Event{
			Kind: failover.EventFailover, From: tr[0], To: tr[1], At: t0.Add(time.Minute),
		}, &leftAt); fwd {
			t.Errorf("%v->%v should be dropped", tr[0], tr[1])
		}
	}

	// Recovery confirmed 4 minutes later -- one message, with the elapsed note.
	ev, fwd = renderFailoverEvent(failover.Event{
		Kind: failover.EventFailover, From: failover.StateConfirmingRecovery, To: failover.StateCooldown, At: t0.Add(4 * time.Minute),
	}, &leftAt)
	if !fwd || ev.Kind != "recovered" {
		t.Fatalf("recovery: fwd=%v kind=%q", fwd, ev.Kind)
	}
	if !strings.Contains(ev.Text, "был на backup 4m") {
		t.Errorf("recovery text = %q, want the 'был на backup 4m' note", ev.Text)
	}
	if !leftAt.IsZero() {
		t.Error("leftPrimaryAt should be cleared after a recovery")
	}
}

func TestTelegramBot_NotifyEvent_MuteHoldsThroughRecovery(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	b := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}

	// Drive it past the flap threshold, interleaving recoveries the way a
	// real recover-then-fail-again storm does.
	for i := 0; i < flapThreshold+3; i++ {
		b.NotifyEvent("r1", Event{Kind: "failover", Text: "⚡ flap"})
		b.NotifyEvent("r1", Event{Kind: "recovered", Text: "✅ primary восстановился"})
	}

	texts := fake.sentTexts()
	rawFlaps, recoveries := 0, 0
	for _, tx := range texts {
		if strings.Contains(tx, "⚡ flap") {
			rawFlaps++
		}
		if strings.Contains(tx, "восстановился") {
			recoveries++
		}
	}
	if rawFlaps >= flapThreshold {
		t.Errorf("raw flap messages not muted: %d\n%v", rawFlaps, texts)
	}
	if recoveries >= flapThreshold {
		t.Errorf("recovery messages should also be muted during a flap storm: %d\n%v", recoveries, texts)
	}
	if !anyContains(texts, "приглушены") {
		t.Errorf("expected a mute notice, got %v", texts)
	}

	// daemon_start clears the mute and is always delivered.
	b.NotifyEvent("r1", Event{Kind: "daemon_start", Text: "▶️ демон запущен"})
	if !anyContains(fake.sentTexts(), "демон запущен") {
		t.Error("daemon_start must be delivered and clear the mute")
	}
	b.NotifyEvent("r1", Event{Kind: "failover", Text: "⚡ post-restart flap"})
	if !anyContains(fake.sentTexts(), "post-restart flap") {
		t.Error("after daemon_start cleared the mute, a fresh failover should get through")
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
