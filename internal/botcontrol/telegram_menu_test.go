package botcontrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTelegramBot_MenuCommandSendsKeyboard(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)

	msg := fake.lastSent(t)
	if !msg.hasButton("routers") || !msg.hasButton("add") || !msg.hasButton("help") || !msg.hasButton("svup") {
		t.Errorf("main menu buttons = %v", msg.Buttons)
	}
}

func TestTelegramBot_ServerSelfUpdate(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	trigger := filepath.Join(t.TempDir(), "update.request")
	bot := &TelegramBot{
		Token: "t", AllowedChats: map[int64]bool{1: true},
		Store: newBotStore(t), APIBase: srv.URL, SelfUpdatePath: trigger,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	fake.pushCallback(1, msgID, "svup")
	fake.waitForEditContaining(t, 3*time.Second, "перезапустится")
	fake.pushCallback(1, msgID, "svupyes")
	fake.waitForEditContaining(t, 3*time.Second, "обновление сервера запущено")

	if _, err := os.Stat(trigger); err != nil {
		t.Errorf("trigger file not written: %v", err)
	}
}

func TestTelegramBot_ServerSelfUpdate_NotConfigured(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "svupyes")
	fake.waitForEditContaining(t, 3*time.Second, "не настроено")
}

func TestTelegramBot_CallbackOpensRouterCardAndRunsAction(t *testing.T) {
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

	// Open the menu to get a real message id to attach callbacks to.
	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// Tap "Роутеры" -> the message is edited to the list, with a button per router.
	fake.pushCallback(1, msgID, "routers")
	fake.waitForEditContaining(t, 3*time.Second, "home")
	if !fake.lastEdit(t).hasButton("router:home") {
		t.Fatalf("router list buttons = %v", fake.lastEdit(t).Buttons)
	}

	// Tap the router -> its card, with a Статус button. ("снимок состояния"
	// is card-only text -- the routers list also contains "home".)
	fake.pushCallback(1, msgID, "router:home")
	fake.waitForEditContaining(t, 3*time.Second, "снимок состояния")
	if !fake.lastEdit(t).hasButton("act:status:home") || !fake.lastEdit(t).hasButton("del:home") {
		t.Fatalf("router card buttons = %v", fake.lastEdit(t).Buttons)
	}

	// Router agent: answer the status command the bot enqueues.
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cmd, _ := store.Dequeue("home"); cmd != nil {
				_ = store.RecordResult("home", Result{CommandID: cmd.ID, Output: "variant: full"})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	// Tap "Статус" -> queued, then the same message is edited with the result.
	fake.pushCallback(1, msgID, "act:status:home")
	got := fake.waitForEditContaining(t, 3*time.Second, "variant: full")
	if !strings.Contains(got, "home") {
		t.Errorf("result edit = %q, want the router card plus the output", got)
	}
}

func TestTelegramBot_CallbackDeleteFlow(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	fake.pushCallback(1, msgID, "del:home")
	fake.waitForEditContaining(t, 3*time.Second, "Удалить роутер home")
	if !fake.lastEdit(t).hasButton("delyes:home") {
		t.Fatalf("confirm buttons = %v", fake.lastEdit(t).Buttons)
	}

	fake.pushCallback(1, msgID, "delyes:home")
	fake.waitForEditContaining(t, 3*time.Second, "удалён")
	if store.HasRouter("home") {
		t.Error("router still registered after confirming delete")
	}
}

func TestTelegramBot_CallbackFromUnauthorizedChatIgnored(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.pushCallback(999, 5, "delyes:home")
	time.Sleep(300 * time.Millisecond)
	if !store.HasRouter("home") {
		t.Error("unauthorized callback deleted a router")
	}
	fake.mu.Lock()
	edits := len(fake.edits)
	fake.mu.Unlock()
	if edits != 0 {
		t.Errorf("unauthorized callback produced %d edits, want 0", edits)
	}
}

func TestTelegramBot_AddRouterWizard(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	bot := &TelegramBot{
		Token:        "t",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		Fingerprint:  "deadbeef",
		ServerURL:    "https://vps.example.com:8443",
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	// Start via the menu button.
	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "add")
	fake.waitFor(t, 3*time.Second, "wizard prompt", func() string {
		if strings.Contains(fake.lastSent(t).Text, "Введите id") {
			return "ok"
		}
		return ""
	})

	fake.push(1, "home")
	fake.waitForReply(t, 3*time.Second) // "Имя для отображения..."
	fake.push(1, "Дом")

	got := fake.waitFor(t, 3*time.Second, "the configure hint", func() string {
		txt := fake.lastSent(t).Text
		if strings.Contains(txt, "agent configure") {
			return txt
		}
		return ""
	})
	if !store.HasRouter("home") {
		t.Fatal("wizard did not register the router")
	}
	tok, _ := store.TokenFor("home")
	if !strings.Contains(got, "https://vps.example.com:8443 home deadbeef "+tok) {
		t.Errorf("hint = %q", got)
	}
}

func TestTelegramBot_WizardAbortedBySlashCommand(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "add")
	fake.waitFor(t, 3*time.Second, "wizard prompt", func() string {
		if strings.Contains(fake.lastSent(t).Text, "Введите id") {
			return "ok"
		}
		return ""
	})

	// A slash command mid-wizard aborts the dialog and still runs.
	fake.push(1, "/routers")
	got := fake.waitFor(t, 3*time.Second, "the /routers reply", func() string {
		if strings.Contains(fake.lastSent(t).Text, "Роутеров пока нет") {
			return "ok"
		}
		return ""
	})
	if got != "ok" {
		t.Fatal("/routers did not run after aborting the wizard")
	}
}
