package botcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTelegram is a minimal stand-in for the real Telegram Bot API:
// getUpdates returns one queued update at a time (then blanks until the
// test pushes another), sendMessage records what was sent so the test can
// assert on the bot's replies.
type fakeTelegram struct {
	mu      sync.Mutex
	updates []tgUpdate
	sent    []sentMessage
}

type sentMessage struct {
	ChatID int64
	Text   string
}

func newFakeTelegram(t *testing.T) (*httptest.Server, *fakeTelegram) {
	t.Helper()
	f := &fakeTelegram{}
	mux := http.NewServeMux()
	mux.HandleFunc("/bot", http.NotFound) // unused, keeps path prefix explicit below
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.mu.Lock()
			pending := f.updates
			f.updates = nil
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tgGetUpdatesResponse{OK: true, Result: pending})
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			var body struct {
				ChatID int64  `json:"chat_id"`
				Text   string `json:"text"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.sent = append(f.sent, sentMessage{ChatID: body.ChatID, Text: body.Text})
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, f
}

func (f *fakeTelegram) push(chatID int64, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	nextID := int64(len(f.sent) + len(f.updates) + 1) // any strictly-increasing value works
	f.updates = append(f.updates, tgUpdate{UpdateID: nextID, Message: &tgMessage{Chat: tgChat{ID: chatID}, Text: text}})
}

func (f *fakeTelegram) sentTexts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.sent))
	for i, m := range f.sent {
		out[i] = m.Text
	}
	return out
}

func (f *fakeTelegram) waitForReply(t *testing.T, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.sent)
		f.mu.Unlock()
		if n > 0 {
			f.mu.Lock()
			text := f.sent[n-1].Text
			f.mu.Unlock()
			return text
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for a bot reply")
	return ""
}

func newBotStore(t *testing.T) *Store {
	t.Helper()
	store, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	return store
}

func mustRegister(t *testing.T, store *Store, id string) {
	t.Helper()
	if _, err := store.AddRouter(id, ""); err != nil {
		t.Fatalf("AddRouter(%q): %v", id, err)
	}
}

func runBotInBackground(t *testing.T, bot *TelegramBot) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = bot.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return cancel
}

func TestTelegramBot_UnauthorizedChatIsIgnored(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:        "test-token",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	fake.push(999, "/status router-1") // chat 999 is not allowlisted
	time.Sleep(200 * time.Millisecond)
	if texts := fake.sentTexts(); len(texts) != 0 {
		t.Errorf("bot replied to an unauthorized chat: %v", texts)
	}
}

func TestTelegramBot_Help(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:        "test-token",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/help")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "/status") {
		t.Errorf("help reply = %q, want it to mention /status", reply)
	}
}

func TestTelegramBot_AddRouterReturnsConfigureLine(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	bot := &TelegramBot{
		Token:        "test-token",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		Fingerprint:  "deadbeef",
		ServerURL:    "https://vps.example.com:8443",
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/add_router home Дом")
	reply := fake.waitForReply(t, 3*time.Second)

	if !store.HasRouter("home") {
		t.Fatal("router not registered after /add_router")
	}
	tok, _ := store.TokenFor("home")
	want := "keenetic-xray agent configure https://vps.example.com:8443 home deadbeef " + tok
	if !strings.Contains(reply, want) {
		t.Errorf("reply = %q\nwant it to contain %q", reply, want)
	}
}

func TestTelegramBot_AddRouterRejectsBadID(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/add_router bad/id")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "id роутера") {
		t.Errorf("reply = %q, want an invalid-id message", reply)
	}
	if len(store.Routers()) != 0 {
		t.Error("an invalid id must not be registered")
	}
}

func TestTelegramBot_RemoveRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/remove_router home")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "убран из реестра") {
		t.Errorf("reply = %q", reply)
	}
	if store.HasRouter("home") {
		t.Error("router still registered after /remove_router")
	}
}

func TestTelegramBot_ListRoutersEmpty(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/routers")
	if reply := fake.waitForReply(t, 3*time.Second); !strings.Contains(reply, "/add_router") {
		t.Errorf("empty /routers = %q, want a hint to add one", reply)
	}
}

func TestTelegramBot_ListRoutersWithEntries(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/routers")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "home") || !strings.Contains(reply, "ещё не подключался") {
		t.Errorf("/routers = %q, want it to list 'home'", reply)
	}
}

func TestTelegramBot_UnknownRouterRejected(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:        "test-token",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/status router-99")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "unknown router") {
		t.Errorf("reply = %q, want an unknown-router message", reply)
	}
}

func TestTelegramBot_StatusRoundTrip(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:         "test-token",
		AllowedChats:  map[int64]bool{1: true},
		Store:         store,
		APIBase:       srv.URL,
		ResultTimeout: 3 * time.Second,
	}
	runBotInBackground(t, bot)

	// Simulate the router agent: watch for the command the bot enqueues
	// and post a result back, like the real /agent/poll+/agent/result
	// round trip would (but driven directly against the Store here,
	// since this test is about the bot's behavior, not the HTTP layer
	// already covered by server_test.go).
	go func() {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if cmd, _ := store.Dequeue("router-1"); cmd != nil {
				_ = store.RecordResult("router-1", Result{CommandID: cmd.ID, Output: "variant: full"})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	fake.push(1, "/status router-1")
	reply := fake.waitForReply(t, 3*time.Second)
	want := "router-1: variant: full"
	if reply != want {
		t.Errorf("reply = %q, want %q", reply, want)
	}
}

func TestTelegramBot_TimesOutWhenRouterNeverAnswers(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:         "test-token",
		AllowedChats:  map[int64]bool{1: true},
		Store:         store,
		APIBase:       srv.URL,
		ResultTimeout: 100 * time.Millisecond,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/status router-1")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "hasn't answered yet") {
		t.Errorf("reply = %q, want a not-answered-yet message", reply)
	}
}

func TestTelegramBot_SwitchDispatchesCorrectAction(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:         "test-token",
		AllowedChats:  map[int64]bool{1: true},
		Store:         store,
		APIBase:       srv.URL,
		ResultTimeout: 2 * time.Second,
	}
	runBotInBackground(t, bot)

	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if cmd, _ := store.Dequeue("router-1"); cmd != nil {
				_ = store.RecordResult("router-1", Result{CommandID: cmd.ID, Output: fmt.Sprintf("ran %s", cmd.Action)})
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	fake.push(1, "/switch router-1 backup")
	reply := fake.waitForReply(t, 3*time.Second)
	want := "router-1: ran " + ActionSwitchBackup
	if reply != want {
		t.Errorf("reply = %q, want %q", reply, want)
	}
}

func TestTelegramBot_SwitchInvalidRoleRejectedWithoutEnqueue(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "router-1")
	bot := &TelegramBot{
		Token:        "test-token",
		AllowedChats: map[int64]bool{1: true},
		Store:        store,
		APIBase:      srv.URL,
	}
	runBotInBackground(t, bot)

	fake.push(1, "/switch router-1 sideways")
	reply := fake.waitForReply(t, 3*time.Second)
	if !strings.Contains(reply, "usage") {
		t.Errorf("reply = %q, want a usage message", reply)
	}
	if n := store.PendingCount("router-1"); n != 0 {
		t.Errorf("pending commands = %d, want 0 (invalid role must not enqueue)", n)
	}
}
