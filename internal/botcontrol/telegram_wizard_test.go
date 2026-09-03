package botcontrol

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder is a concurrency-safe list of the actions a fakeAgent saw.
type recorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *recorder) add(a string) {
	r.mu.Lock()
	r.seen = append(r.seen, a)
	r.mu.Unlock()
}

func (r *recorder) has(a string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return contains(r.seen, a)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func TestParseProfileRows(t *testing.T) {
	in := "0: alpha -- a.example.com:443 [primary]\n1: beta -- b.example.com:443 [backup]\n2: gamma -- c:80"
	got := parseProfileRows(in)
	if len(got) != 3 {
		t.Fatalf("parseProfileRows returned %d rows: %+v", len(got), got)
	}
	if got[0].remark != "alpha" || !got[0].primary || got[0].backup {
		t.Errorf("row 0 = %+v", got[0])
	}
	if got[1].remark != "beta" || got[1].primary || !got[1].backup {
		t.Errorf("row 1 = %+v", got[1])
	}
	if got[2].remark != "gamma" || got[2].primary || got[2].backup {
		t.Errorf("row 2 = %+v", got[2])
	}
	if parseProfileRows("no profiles configured") != nil {
		t.Error("a non-list string should parse to nil")
	}
}

func TestStepResult(t *testing.T) {
	b := &TelegramBot{Store: newBotStore(t)}
	if got := b.stepResult("r", true, "", "done"); got != "done" {
		t.Errorf("answered/no-err = %q", got)
	}
	if got := b.stepResult("r", true, "boom", ""); !strings.Contains(got, "boom") {
		t.Errorf("answered/err = %q", got)
	}
	if got := b.stepResult("r", false, "queue full", ""); got != "queue full" {
		t.Errorf("queue error = %q", got)
	}
	// No answer + never polled -> the offline phrasing, not "try again".
	if got := b.stepResult("r", false, "", ""); !strings.Contains(got, "офлайн") {
		t.Errorf("offline no-answer = %q", got)
	}
}

func TestQueuedNote(t *testing.T) {
	if got := queuedNote(time.Time{}); !strings.Contains(got, "офлайн") {
		t.Errorf("never polled: %q", got)
	}
	if got := queuedNote(time.Now()); strings.Contains(got, "офлайн") {
		t.Errorf("fresh poll should not read as offline: %q", got)
	}
}

// waitSent blocks until some sent message contains want (most recent
// first), or fails the test. Unlike fake.lastSent it does not fatal
// while nothing has been sent yet.
func waitSent(t *testing.T, f *fakeTelegram, timeout time.Duration, want string) string {
	t.Helper()
	return f.waitFor(t, timeout, "a sent message containing "+want, func() string {
		texts := f.sentTexts()
		for i := len(texts) - 1; i >= 0; i-- {
			if strings.Contains(texts[i], want) {
				return texts[i]
			}
		}
		return ""
	})
}

// fakeAgent drains routerID's command queue and answers each command with
// reply(action), until the test ends.
func fakeAgent(t *testing.T, store *Store, routerID string, reply func(action string) string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cmd, _ := store.Dequeue(routerID); cmd != nil {
				_ = store.RecordResult(routerID, Result{CommandID: cmd.ID, Output: reply(cmd.Action)})
				continue
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
}

func TestTelegramBot_SourcesMenu_UnknownRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "srcm:nope")
	fake.waitForEditContaining(t, 3*time.Second, "нет такого роутера")
}

func TestTelegramBot_SlotSourceWizard_PrimaryFromLink(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	rec := &recorder{}
	fakeAgent(t, store, "r1", func(action string) string {
		rec.add(action)
		if action == ActionSetPrimarySource {
			return "primary ← RU-1"
		}
		return "ok"
	})

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// 🔗 Источники -> ⬆️ Основная -> paste a link.
	fake.pushCallback(1, msgID, "srcm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Источники r1")
	fake.pushCallback(1, msgID, "srcp:r1")
	waitSent(t, fake, 3*time.Second, "Источник для основной")

	// A non-URL is rejected without ending the dialog.
	fake.push(1, "garbage")
	waitSent(t, fake, 3*time.Second, "нужна vless")

	fake.push(1, "vless://11111111-2222-3333-4444-555555555555@a.example:443?type=tcp&security=none#RU-1")
	got := waitSent(t, fake, 4*time.Second, "primary ← RU-1")
	if got == "" {
		t.Fatal("no confirmation")
	}
	if !rec.has(ActionSetPrimarySource) {
		t.Errorf("router did not receive set_primary_source, saw %v", rec.list())
	}
}

func TestTelegramBot_ProfilesScreen_ShowsRolesAndSets(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	rec := &recorder{}
	fakeAgent(t, store, "r1", func(action string) string {
		rec.add(action)
		if action == ActionProfileList {
			return "0: alpha -- a:443 [primary] [backup]\n1: beta -- b:443"
		}
		return "ok"
	})

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	fake.pushCallback(1, msgID, "pf:r1")
	screen := fake.waitForEditContaining(t, 4*time.Second, "1: beta")
	if !strings.Contains(screen, "0: alpha ⬆️осн ⬇️рез") {
		t.Errorf("profiles screen = %q", screen)
	}

	fake.pushCallback(1, msgID, "pfp:r1:1") // make profile 1 primary
	deadline := time.Now().Add(4 * time.Second)
	for !rec.has(ActionSubSetPrimary) {
		if time.Now().After(deadline) {
			t.Fatalf("pfp button did not enqueue sub_setprimary, saw %v", rec.list())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
