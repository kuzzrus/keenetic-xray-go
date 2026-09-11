package botcontrol

import (
	"strings"
	"testing"
	"time"
)

// The 📊 Статус button inside 📍 Маршруты used to be wired through the
// generic act: pipeline, which always lands back on the router card --
// from inside 📍 Маршруты that reads as being bounced out of the screen.
// It should instead show the result in place, on the routes screen's own
// keyboard.
func TestTelegramBot_RoutesStatusStaysOnRoutesScreen(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{
		Token:         "t",
		AllowedChats:  map[int64]bool{1: true},
		Store:         store,
		APIBase:       srv.URL,
		ResultTimeout: 3 * time.Second,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// Router agent: answer each queued command in turn -- first the list
	// snapshot (opening 📍 Маршруты), then the drift check (tapping
	// Статус).
	go func() {
		for _, out := range []string{"", "всё синхронно"} {
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if cmd, _ := store.Dequeue("home"); cmd != nil {
					_ = store.RecordResult("home", Result{CommandID: cmd.ID, Output: out})
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	fake.pushCallback(1, msgID, "rtm:home")
	// "Списков пока нет" only appears once the list snapshot has come back
	// and routesListKB is drawn -- routesBackKB's own transient "⏳
	// загружаю списки…" edit also contains "Маршруты", so waiting on that
	// word alone can race and catch the loading edit instead.
	fake.waitForEditContaining(t, 3*time.Second, "Списков пока нет")
	if !fake.lastEdit(t).hasButton("rtSt:home") {
		t.Fatalf("routes screen buttons = %v, want rtSt:home", fake.lastEdit(t).Buttons)
	}

	fake.pushCallback(1, msgID, "rtSt:home")
	got := fake.waitForEditContaining(t, 3*time.Second, "всё синхронно")
	if !strings.Contains(got, "Маршруты") {
		t.Errorf("result edit = %q, want the routes screen text plus the output", got)
	}
	edit := fake.lastEdit(t)
	if !edit.hasButton("rtm:home") {
		t.Errorf("buttons after Статус = %v, want to stay on the routes screen, not bounce to the router card", edit.Buttons)
	}
	if edit.hasButton("act:status:home") || edit.hasButton("del:home") {
		t.Errorf("buttons after Статус = %v, want the routes screen's keyboard, not the router card's", edit.Buttons)
	}
}

// 📋 Ручные списки reports the operator's own (non-keenetic-xray) route
// lists -- read-only, no config counterpart, so it must follow the same
// "stay on the routes screen" rule as 📊 Статус above.
func TestTelegramBot_RoutesManualStaysOnRoutesScreen(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{
		Token:         "t",
		AllowedChats:  map[int64]bool{1: true},
		Store:         store,
		APIBase:       srv.URL,
		ResultTimeout: 3 * time.Second,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	go func() {
		for _, out := range []string{"", "📁 youtube · 2 записей · → Proxy0"} {
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if cmd, _ := store.Dequeue("home"); cmd != nil {
					_ = store.RecordResult("home", Result{CommandID: cmd.ID, Output: out})
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	fake.pushCallback(1, msgID, "rtm:home")
	fake.waitForEditContaining(t, 3*time.Second, "Списков пока нет")
	if !fake.lastEdit(t).hasButton("rtManual:home") {
		t.Fatalf("routes screen buttons = %v, want rtManual:home", fake.lastEdit(t).Buttons)
	}

	fake.pushCallback(1, msgID, "rtManual:home")
	got := fake.waitForEditContaining(t, 3*time.Second, "youtube")
	if !strings.Contains(got, "Маршруты") {
		t.Errorf("result edit = %q, want the routes screen text plus the output", got)
	}
	edit := fake.lastEdit(t)
	if !edit.hasButton("rtm:home") {
		t.Errorf("buttons after Ручные списки = %v, want to stay on the routes screen, not bounce to the router card", edit.Buttons)
	}
	if edit.hasButton("act:status:home") || edit.hasButton("del:home") {
		t.Errorf("buttons after Ручные списки = %v, want the routes screen's keyboard, not the router card's", edit.Buttons)
	}
}
