package botcontrol

import (
	"testing"
	"time"
)

func TestRouterDot(t *testing.T) {
	if got := routerDot(time.Time{}); got != "⚪" {
		t.Errorf("never-polled dot = %q, want ⚪", got)
	}
	if got := routerDot(time.Now()); got != "🟢" {
		t.Errorf("fresh dot = %q, want 🟢", got)
	}
	if got := routerDot(time.Now().Add(-2 * DefaultOfflineThreshold)); got != "🔴" {
		t.Errorf("stale dot = %q, want 🔴", got)
	}
}

func TestOfflineWatcher_NotifiesOnTransitions(t *testing.T) {
	store, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, err := store.AddRouter("r1", "Router One"); err != nil {
		t.Fatalf("AddRouter: %v", err)
	}

	var calls []bool // online value of each Notify call, in order
	w := &OfflineWatcher{
		Store:     store,
		Threshold: 150 * time.Millisecond,
		Notify:    func(id string, online bool) { calls = append(calls, online) },
	}
	w.online = map[string]bool{}

	const th = 150 * time.Millisecond

	// r1 has polled once and is fresh: seed scan marks it online, silently.
	if _, err := store.Dequeue("r1"); err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	w.scan(th, false)
	if len(calls) != 0 {
		t.Fatalf("seed scan must not notify, got %v", calls)
	}
	if !w.online["r1"] {
		t.Fatal("r1 should be seeded online")
	}

	// Let it go stale -> one offline notification.
	time.Sleep(300 * time.Millisecond)
	w.scan(th, true)
	if len(calls) != 1 || calls[0] != false {
		t.Fatalf("expected one offline notification, got %v", calls)
	}

	// A fresh poll -> one online notification.
	if _, err := store.Dequeue("r1"); err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	w.scan(th, true)
	if len(calls) != 2 || calls[1] != true {
		t.Fatalf("expected a follow-up online notification, got %v", calls)
	}

	// Steady state: no new notifications.
	w.scan(th, true)
	if len(calls) != 2 {
		t.Fatalf("no transition -> no notification, got %v", calls)
	}
}

func TestOfflineWatcher_IgnoresNeverConnectedRouter(t *testing.T) {
	store, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, err := store.AddRouter("r-new", ""); err != nil {
		t.Fatalf("AddRouter: %v", err)
	}

	notified := false
	w := &OfflineWatcher{Store: store, Notify: func(string, bool) { notified = true }}
	w.online = map[string]bool{}

	w.scan(time.Millisecond, false)
	time.Sleep(5 * time.Millisecond)
	w.scan(time.Millisecond, true)

	if notified {
		t.Error("a router that has never polled must not trigger an offline notification")
	}
	if _, tracked := w.online["r-new"]; tracked {
		t.Error("a never-connected router should not be tracked")
	}
}

func TestOfflineWatcher_DropsStateForRemovedRouter(t *testing.T) {
	store, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, err := store.AddRouter("gone", ""); err != nil {
		t.Fatalf("AddRouter: %v", err)
	}
	if _, err := store.Dequeue("gone"); err != nil {
		t.Fatalf("Dequeue: %v", err)
	}

	w := &OfflineWatcher{Store: store, Notify: func(string, bool) {}}
	w.online = map[string]bool{}
	w.scan(time.Minute, false)
	if _, ok := w.online["gone"]; !ok {
		t.Fatal("precondition: router should be tracked after the seed scan")
	}

	if err := store.RemoveRouter("gone"); err != nil {
		t.Fatalf("RemoveRouter: %v", err)
	}
	w.scan(time.Minute, true)
	if _, ok := w.online["gone"]; ok {
		t.Error("state for a removed router should be dropped")
	}
}
