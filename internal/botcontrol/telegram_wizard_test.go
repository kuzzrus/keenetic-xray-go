package botcontrol

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
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

// recordingAgent is fakeAgent that hands the whole Command to reply (so a
// test can assert on args) and records every command it saw.
func recordingAgent(t *testing.T, store *Store, routerID string, reply func(Command) string) *recorder {
	t.Helper()
	rec := &recorder{}
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
				rec.add(cmd.Action + " " + strings.Join(cmd.Args, "|"))
				_ = store.RecordResult(routerID, Result{CommandID: cmd.ID, Output: reply(*cmd)})
				continue
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
	return rec
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

// TestTelegramBot_SlotSourceWizard_BackupFromNaiveLink is the regression
// test for a real bug: this wizard's own prefix check (independent of --
// and, until now, out of sync with -- config.ParseProfileURI on the
// router side) only allowed vless:// and http(s)://, so a pasted
// naive+https:// link was rejected right here in the control server,
// before ever reaching the router where naive is actually understood.
func TestTelegramBot_SlotSourceWizard_BackupFromNaiveLink(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	rec := &recorder{}
	fakeAgent(t, store, "r1", func(action string) string {
		rec.add(action)
		if action == ActionSetBackupSource {
			return "backup ← Naive-1"
		}
		return "ok"
	})

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// 🔗 Источники -> ⬇️ Резервная -> paste a naive+https:// link.
	fake.pushCallback(1, msgID, "srcm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Источники r1")
	fake.pushCallback(1, msgID, "srcb:r1")
	waitSent(t, fake, 3*time.Second, "Источник для резервной")

	fake.push(1, "naive+https://alice:s3cret@n.example.com:8443#Naive-1")
	got := waitSent(t, fake, 4*time.Second, "backup ← Naive-1")
	if got == "" {
		t.Fatal("no confirmation -- naive+https:// link was rejected instead of forwarded")
	}
	if !rec.has(ActionSetBackupSource) {
		t.Errorf("router did not receive set_backup_source, saw %v", rec.list())
	}
}

func TestTelegramBot_PortsWizard(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// "⚙️ Порты и транспорт" opens a screen; "✏️ Порты SOCKS/HTTP" on it
	// starts the actual wizard.
	fake.pushCallback(1, msgID, "ptm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Порты и транспорт")
	fake.pushCallback(1, msgID, "ptwiz:r1")
	waitSent(t, fake, 3*time.Second, "Смена портов")

	// Malformed input (not two fields) is rejected without ending the dialog.
	fake.push(1, "1090")
	waitSent(t, fake, 3*time.Second, "нужно два числа")

	fake.push(1, "1090 1091")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionSetPorts {
				t.Errorf("dequeued action = %q, want %q", cmd.Action, ActionSetPorts)
			}
			if len(cmd.Args) != 2 || cmd.Args[0] != "1090" || cmd.Args[1] != "1091" {
				t.Errorf("dequeued args = %v, want [1090 1091]", cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "SOCKS: 1090, HTTP: 1091"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitSent(t, fake, 3*time.Second, "SOCKS: 1090, HTTP: 1091")
}

func TestTelegramBot_TransportScreen_ProtocolAndInterface(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	rec := &recorder{}
	fakeAgent(t, store, "r1", func(action string) string {
		rec.add(action)
		return "ok"
	})

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "ptm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Порты и транспорт")

	// HTTP protocol button -> proxy0_config with ["http", ""].
	fake.pushCallback(1, msgID, "ptpr:r1:http")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionProxy0Config || len(cmd.Args) != 2 || cmd.Args[0] != "http" || cmd.Args[1] != "" {
				t.Errorf("dequeued = %q %v, want proxy0_config [http ]", cmd.Action, cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "proxy0: http"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// "✏️ Интерфейс Keenetic" -> one-step wizard -> proxy0_config with ["", "Proxy1"].
	fake.pushCallback(1, msgID, "ptif:r1")
	waitSent(t, fake, 3*time.Second, "Интерфейс Keenetic")
	fake.push(1, "proxy 1") // not a valid single token
	waitSent(t, fake, 3*time.Second, "Proxy0 / Proxy1")
	fake.push(1, "Proxy1")
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionProxy0Config || len(cmd.Args) != 2 || cmd.Args[0] != "" || cmd.Args[1] != "Proxy1" {
				t.Errorf("dequeued = %q %v, want proxy0_config [ Proxy1]", cmd.Action, cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "proxy0: socks5 через Proxy1"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// "📶 MSS: Авто" preset -> set_mss carrying "auto".
	fake.pushCallback(1, msgID, "ptmss:r1:auto")
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionSetMSS || len(cmd.Args) != 1 || cmd.Args[0] != "auto" {
				t.Errorf("dequeued = %q %v, want set_mss [auto]", cmd.Action, cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "MSS-клампинг (Proxy0): авто (1360)"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// "🔌 WG-транспорт" -> its sub-screen; "Включить" -> wg_on.
	fake.pushCallback(1, msgID, "wgt:r1")
	fake.waitForEditContaining(t, 3*time.Second, "WG-транспорт")
	fake.pushCallback(1, msgID, "act:wg_on:r1")
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionWGTransportOn {
				t.Errorf("dequeued = %q, want wg_on", cmd.Action)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "WG-транспорт включён"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTelegramBot_CoreScreen(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	fake.pushCallback(1, msgID, "corem:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Ядро xray")

	// "Пререлиз" button -> update_core carrying the prerelease tag.
	fake.pushCallback(1, msgID, "corepre:r1")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionUpdateCore || len(cmd.Args) != 1 || cmd.Args[0] != xraycore.PrereleaseTag {
				t.Errorf("dequeued = %q %v, want update_core [%s]", cmd.Action, cmd.Args, xraycore.PrereleaseTag)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "xray-core обновлён"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// "Стабильное" button -> update_core stable.
	fake.pushCallback(1, msgID, "corestable:r1")
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionUpdateCore || len(cmd.Args) != 1 || cmd.Args[0] != "stable" {
				t.Errorf("dequeued = %q %v, want update_core [stable]", cmd.Action, cmd.Args)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTelegramBot_RoutesScreen_ListButtonsAndIface(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	iface := "Proxy0"
	rec := recordingAgent(t, store, "r1", func(c Command) string {
		switch c.Action {
		case ActionRoutesNames:
			return "youtube\t12\ton\t" + iface + "\ninsta\t3\toff\tProxy0"
		case ActionRoutesSetIface:
			iface = c.Args[1] // reflect the change in the next routes_names
			return "список \"" + c.Args[0] + "\": → " + c.Args[1]
		}
		return "ok"
	})

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// Open 📍 Маршруты -> list rendered from routes_names, one button per list.
	fake.pushCallback(1, msgID, "rtm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "youtube")
	if txt := fake.waitForEditContaining(t, 3*time.Second, "insta"); !strings.Contains(txt, "2 списка") {
		t.Errorf("routes list text = %q", txt)
	}

	// Tap the first list -> its own screen; then 🎯 Интерфейс -> choices.
	fake.pushCallback(1, msgID, "rtL:r1:0")
	fake.waitForEditContaining(t, 3*time.Second, "📁 youtube")
	fake.pushCallback(1, msgID, "rtI:r1:0")
	fake.waitForEditContaining(t, 3*time.Second, "куда гнать")

	// Pick Wireguard4 -> routes_setiface [youtube Wireguard4], then the list
	// re-renders with the new interface (the "→ Wireguard4" form only
	// appears in the list render, not the iface-choice screen copy).
	fake.pushCallback(1, msgID, "rtSi:r1:0:w4")
	fake.waitForEditContaining(t, 3*time.Second, "youtube · 12 · → Wireguard4")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !rec.has("routes_setiface youtube|Wireguard4") {
		time.Sleep(20 * time.Millisecond)
	}
	if !rec.has("routes_setiface youtube|Wireguard4") {
		t.Errorf("recorded commands = %v, want routes_setiface youtube|Wireguard4", rec.list())
	}
}

func TestTelegramBot_RoutesScreen_NewListWizard(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// ➕ Новый список -> asks for a name (rejects non-latin), then entries.
	fake.pushCallback(1, msgID, "rtNew:r1")
	waitSent(t, fake, 3*time.Second, "Название списка")
	fake.push(1, "соцсети")
	waitSent(t, fake, 3*time.Second, "латинская буква")
	fake.push(1, "youtube")
	waitSent(t, fake, 3*time.Second, "youtube")

	fake.push(1, "youtube.com googlevideo.com\n1.2.3.0/24")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionRoutesAdd || len(cmd.Args) != 2 || cmd.Args[0] != "youtube" {
				t.Errorf("dequeued = %q %v, want routes_add [youtube ...]", cmd.Action, cmd.Args)
			}
			if !strings.Contains(cmd.Args[1], "youtube.com") || !strings.Contains(cmd.Args[1], "1.2.3.0/24") {
				t.Errorf("entries arg = %q", cmd.Args[1])
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "создан список \"youtube\": +3 записей"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitSent(t, fake, 3*time.Second, "создан список")
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
