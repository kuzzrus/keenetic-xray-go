package botcontrol

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
)

// scanAgent stands in for the router: it dequeues every command, records
// it, and answers with whatever handle returns.
type scanAgent struct {
	mu   sync.Mutex
	cmds []Command
}

func startScanAgent(t *testing.T, store *Store, handle func(Command) (out, errText string)) *scanAgent {
	t.Helper()
	a := &scanAgent{}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			cmd, _ := store.Dequeue("r1")
			if cmd == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			a.mu.Lock()
			a.cmds = append(a.cmds, *cmd)
			a.mu.Unlock()
			out, errText := handle(*cmd)
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: out, Err: errText})
		}
	}()
	return a
}

func (a *scanAgent) args(action string) [][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out [][]string
	for _, c := range a.cmds {
		if c.Action == action {
			out = append(out, c.Args)
		}
	}
	return out
}

func scanResultTSV(hosts ...depscan.Host) string {
	r := &depscan.Result{
		Pages: []depscan.Page{{Seed: "example.com", FinalHost: "www.example.com", Status: 200, Direct: depscan.Reach{Tried: true, Err: "сброс"}}},
		Hosts: hosts,
	}
	return r.TSV()
}

func needHost(name string) depscan.Host {
	return depscan.Host{Name: name, Class: depscan.ClassNeed, Via: []string{depscan.ViaHTML},
		Direct: depscan.Reach{Tried: true, Err: "таймаут"}, Tunnel: depscan.Reach{Tried: true, OK: true, Status: 200}}
}

func maybeHost(name string) depscan.Host {
	h := needHost(name)
	h.Class, h.Tier, h.Via = depscan.ClassMaybe, depscan.TierMaybe, []string{depscan.ViaCSP}
	return h
}

func newScanBot(t *testing.T) (*TelegramBot, *fakeTelegram, *Store) {
	t.Helper()
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{
		Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL,
		ResultTimeout: 2 * time.Second, ScanTimeout: 3 * time.Second,
	}
	runBotInBackground(t, bot)
	return bot, fake, store
}

// waitLastEdit waits until the newest edit satisfies pred -- for a change that
// shows only as the absence or return of some text.
func waitLastEdit(t *testing.T, f *fakeTelegram, what string, pred func(sentMessage) bool) {
	t.Helper()
	f.waitFor(t, 3*time.Second, what, func() string {
		f.mu.Lock()
		defer f.mu.Unlock()
		if n := len(f.edits); n > 0 && pred(f.edits[n-1]) {
			return "x"
		}
		return ""
	})
}

// waitForButtonMsg returns the newest sent message that carries a button
// whose callback_data starts with prefix.
func waitForButtonMsg(t *testing.T, f *fakeTelegram, prefix string) sentMessage {
	t.Helper()
	var found sentMessage
	f.waitFor(t, 5*time.Second, "a message with a "+prefix+" button", func() string {
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := len(f.sent) - 1; i >= 0; i-- {
			for _, b := range f.sent[i].Buttons {
				if strings.HasPrefix(b, prefix) {
					found = f.sent[i]
					return "x"
				}
			}
		}
		return ""
	})
	return found
}

func buttonWithPrefix(m sentMessage, prefix string) string {
	for _, b := range m.Buttons {
		if strings.HasPrefix(b, prefix) {
			return b
		}
	}
	return ""
}

// addThroughWizard walks "новый список" -> name -> entries, ending with the
// bot's "✅ added" message.
func addThroughWizard(t *testing.T, f *fakeTelegram, entries string) {
	t.Helper()
	f.push(1, "/menu")
	f.waitForReply(t, 3*time.Second)
	f.pushCallback(1, f.lastSent(t).MessageID, "rtNew:r1")
	f.waitFor(t, 3*time.Second, "the name prompt", func() string {
		for _, s := range f.sentTexts() {
			if strings.Contains(s, "Название списка") {
				return s
			}
		}
		return ""
	})
	f.push(1, "mylist")
	f.waitFor(t, 3*time.Second, "the entries prompt", func() string {
		for _, s := range f.sentTexts() {
			if strings.Contains(s, "вставь домены") {
				return s
			}
		}
		return ""
	})
	f.push(1, entries)
}

func TestTelegramBot_ScanFlow_AddScanTickAdd(t *testing.T) {
	_, fake, store := newScanBot(t)
	agent := startScanAgent(t, store, func(c Command) (string, string) {
		switch c.Action {
		case ActionRoutesAdd:
			return fmt.Sprintf("список %q: +%d записей", c.Args[0], len(strings.Fields(c.Args[1]))), ""
		case ActionRoutesScan:
			return scanResultTSV(needHost("img.example-a.net"), needHost("login.example-b.org"), needHost("cdn.example-c.net"),
				maybeHost("csp.example-d.net")), ""
		}
		return "ok", ""
	})

	addThroughWizard(t, fake, "example.com 10.1.2.0/24")
	offer := waitForButtonMsg(t, fake, "rsq:")
	if !strings.Contains(offer.Text, "+2 записей") || !strings.Contains(offer.Text, "Найти") && !strings.Contains(offer.Text, "найти") {
		t.Errorf("the offer = %q, want the ✅ result and the scan prompt", offer.Text)
	}
	if got := agent.args(ActionRoutesAdd); len(got) != 1 || got[0][0] != "mylist" {
		t.Errorf("routes_add = %v", got)
	}
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	if !offer.hasButton("rsx:" + tok) {
		t.Errorf("no decline button: %v", offer.Buttons)
	}

	// Scan: only the domain is read; the subnet is no page to fetch.
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Нужны (3)")
	if got := agent.args(ActionRoutesScan); len(got) != 1 || strings.Join(got[0], " ") != "example.com" {
		t.Errorf("routes_scan args = %v, want just example.com", got)
	}
	screen := fake.lastEdit(t)
	for _, want := range []string{"rst:" + tok + ":0", "rst:" + tok + ":1", "rst:" + tok + ":2", "rsa:" + tok, "rsm:" + tok, "rsx:" + tok} {
		if !screen.hasButton(want) {
			t.Errorf("result screen lacks %s: %v", want, screen.Buttons)
		}
	}
	if screen.hasButton("rst:" + tok + ":3") {
		t.Error("a 'maybe' host is tickable before it is shown")
	}
	for _, want := range []string{"☑ 1. img.example-a.net", "☑ 2. login.example-b.org", "☑ 3. cdn.example-c.net", "Возможно нужны: 1"} {
		if !strings.Contains(screen.Text, want) {
			t.Errorf("screen lacks %q:\n%s", want, screen.Text)
		}
	}

	// Untick the second one, then add.
	fake.pushCallback(1, offer.MessageID, "rst:"+tok+":1")
	fake.waitForEditContaining(t, 3*time.Second, "☐ 2. login.example-b.org")
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Роутер узнаёт адреса")
	adds := agent.args(ActionRoutesAdd)
	if len(adds) != 2 || adds[1][0] != "mylist" || adds[1][1] != "img.example-a.net cdn.example-c.net" {
		t.Errorf("second routes_add = %v, want the two still-ticked hosts in result order", adds)
	}

	// Done: the session is gone, a stale button says so.
	fake.pushCallback(1, offer.MessageID, "rst:"+tok+":0")
	fake.waitForEditContaining(t, 3*time.Second, "устарели")
}

func TestTelegramBot_ScanOffer_OnlyForDomains(t *testing.T) {
	_, fake, store := newScanBot(t)
	startScanAgent(t, store, func(c Command) (string, string) { return "список: +1 записей", "" })
	addThroughWizard(t, fake, "10.1.2.0/24")
	got := fake.waitFor(t, 3*time.Second, "the ✅ message", func() string {
		for _, s := range fake.sentTexts() {
			if strings.Contains(s, "+1 записей") {
				return s
			}
		}
		return ""
	})
	if fake.lastSent(t).Text != got || buttonWithPrefix(fake.lastSent(t), "rsq:") != "" {
		t.Errorf("a subnet-only add offered a page scan: %+v", fake.lastSent(t))
	}
}

func TestTelegramBot_ScanOffer_NotAfterRemoving(t *testing.T) {
	// Removing entries is not adding: the result is just text, no scan offer.
	bot, fake, store := newScanBot(t)
	startScanAgent(t, store, func(c Command) (string, string) { return "список: -1 записей", "" })
	fake.push(1, "/menu") // Run builds its HTTP client on start; wait for it to be answering
	fake.waitForReply(t, 3*time.Second)
	bot.wizardRouteEntries(context.Background(), 1, &wizState{step: wizRouteEntries, routerID: "r1", listName: "mylist", del: true}, "example.com")
	fake.waitFor(t, 3*time.Second, "the result", func() string {
		for _, s := range fake.sentTexts() {
			if strings.Contains(s, "-1 записей") {
				return s
			}
		}
		return ""
	})
	if m := fake.lastSent(t); len(m.Buttons) != 0 {
		t.Errorf("removing entries offered buttons: %v", m.Buttons)
	}
}

func TestTelegramBot_ScanFlow_DeclineAndExpire(t *testing.T) {
	_, fake, store := newScanBot(t)
	startScanAgent(t, store, func(c Command) (string, string) { return "список: +1 записей", "" })
	addThroughWizard(t, fake, "example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")

	fake.pushCallback(1, offer.MessageID, "rsx:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "без поиска")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "устарели")
	// A token that never existed.
	fake.pushCallback(1, offer.MessageID, "rsa:deadbeef")
	fake.waitForEditContaining(t, 3*time.Second, "устарели")
}

func TestTelegramBot_ScanFlow_Failures(t *testing.T) {
	cases := []struct {
		name    string
		handle  func(Command) (string, string)
		timeout time.Duration
		want    string
	}{
		{"old agent", func(c Command) (string, string) {
			if c.Action == ActionRoutesScan {
				return "", `unknown action "routes_scan"`
			}
			return "список: +1 записей", ""
		}, 0, "ещё не умеет искать связанные домены"},
		{"scan error", func(c Command) (string, string) {
			if c.Action == ActionRoutesScan {
				return "", "туннель не работает (xray не запущен или не настроен профиль) — сканировать нечем"
			}
			return "список: +1 записей", ""
		}, 0, "туннель не работает"},
		{"garbage answer", func(c Command) (string, string) {
			if c.Action == ActionRoutesScan {
				return "это не TSV", ""
			}
			return "список: +1 записей", ""
		}, 0, "не разобрал ответ роутера"},
		{"no answer in time", func(c Command) (string, string) {
			if c.Action == ActionRoutesScan {
				time.Sleep(2 * time.Second)
				return "", ""
			}
			return "список: +1 записей", ""
		}, 300 * time.Millisecond, "не ответил вовремя"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bot, fake, store := newScanBot(t)
			if tc.timeout > 0 {
				bot.ScanTimeout = tc.timeout
			}
			startScanAgent(t, store, tc.handle)
			addThroughWizard(t, fake, "example.com")
			offer := waitForButtonMsg(t, fake, "rsq:")
			tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
			fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
			fake.waitForEditContaining(t, 5*time.Second, tc.want)
			if e := fake.lastEdit(t); !e.hasButton("rsq:"+tok) || !e.hasButton("rsx:"+tok) {
				t.Errorf("a failed scan offers no retry/close: %v", e.Buttons)
			}
		})
	}
}

func TestTelegramBot_ScanFlow_PagingAndMaybe(t *testing.T) {
	_, fake, store := newScanBot(t)
	var hosts []depscan.Host
	for i := 0; i < 23; i++ {
		hosts = append(hosts, needHost(fmt.Sprintf("h%02d.example-a.net", i)))
	}
	hosts = append(hosts, maybeHost("maybe1.example-b.net"), maybeHost("maybe2.example-b.net"))
	var added []string
	var mu sync.Mutex
	startScanAgent(t, store, func(c Command) (string, string) {
		switch c.Action {
		case ActionRoutesScan:
			return scanResultTSV(hosts...), ""
		case ActionRoutesAdd:
			mu.Lock()
			added = append(added, c.Args[1])
			mu.Unlock()
		}
		return "ok: +1 записей", ""
	})
	addThroughWizard(t, fake, "example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Нужны (23)")

	first := fake.lastEdit(t)
	if !first.hasButton("rsp:"+tok+":1") || first.hasButton("rsp:"+tok+":-1") {
		t.Errorf("page 1 navigation: %v", first.Buttons)
	}
	if !strings.Contains(first.Text, "10. h09.example-a.net") || strings.Contains(first.Text, "11. h10.") {
		t.Errorf("page 1 should show 1..10:\n%s", first.Text)
	}

	fake.pushCallback(1, offer.MessageID, "rsp:"+tok+":2")
	fake.waitForEditContaining(t, 3*time.Second, "21. h20.example-a.net")
	last := fake.lastEdit(t)
	if !last.hasButton("rsp:"+tok+":1") || last.hasButton("rsp:"+tok+":3") || !last.hasButton("rst:"+tok+":22") {
		t.Errorf("page 3 buttons: %v", last.Buttons)
	}

	// Show the "maybe" ones: they join the list, unticked.
	fake.pushCallback(1, offer.MessageID, "rsm:"+tok)
	waitLastEdit(t, fake, "the maybe-footer to go once they are shown", func(m sentMessage) bool { return !strings.Contains(m.Text, "Возможно нужны: 2") })
	fake.pushCallback(1, offer.MessageID, "rsp:"+tok+":2")
	fake.waitForEditContaining(t, 3*time.Second, "☐ 24. ❔ maybe1.example-b.net")
	// Tick one of them, then hide the maybes again: the tick is dropped.
	fake.pushCallback(1, offer.MessageID, "rst:"+tok+":23")
	fake.waitForEditContaining(t, 3*time.Second, "☑ 24. ❔ maybe1.example-b.net")
	fake.pushCallback(1, offer.MessageID, "rsm:"+tok)
	waitLastEdit(t, fake, "the maybe-footer to return once they are hidden", func(m sentMessage) bool { return strings.Contains(m.Text, "Возможно нужны: 2") })
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Роутер узнаёт адреса")
	mu.Lock()
	defer mu.Unlock()
	// 23 "need" hosts, none of the maybes.
	if len(added) != 2 || len(strings.Fields(added[len(added)-1])) != 23 || strings.Contains(added[len(added)-1], "maybe") {
		t.Errorf("added %q", added)
	}
}

func TestTelegramBot_ScanFlow_NothingTickedKeepsTheScreen(t *testing.T) {
	_, fake, store := newScanBot(t)
	startScanAgent(t, store, func(c Command) (string, string) {
		if c.Action == ActionRoutesScan {
			return scanResultTSV(needHost("img.example-a.net")), ""
		}
		return "список: +1 записей", ""
	})
	addThroughWizard(t, fake, "example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Нужны (1)")
	fake.pushCallback(1, offer.MessageID, "rst:"+tok+":0")
	fake.waitForEditContaining(t, 3*time.Second, "☐ 1. img.example-a.net")
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "Ничего не отмечено")
	if e := fake.lastEdit(t); !e.hasButton("rst:" + tok + ":0") {
		t.Errorf("the screen lost its buttons: %v", e.Buttons)
	}
}

func TestScanScreen_ButtonsFitTelegram(t *testing.T) {
	long := strings.Repeat("a", 60) + ".example-a.net"
	s := &scanSession{routerID: "r1", sel: map[string]bool{}, showMaybe: true}
	r := &depscan.Result{Pages: []depscan.Page{{Seed: "example.com", Status: 200}}}
	for i := 0; i < 60; i++ {
		h := needHost(fmt.Sprintf("%d.%s", i, long))
		if i%3 == 0 {
			h = maybeHost(h.Name)
		}
		r.Hosts = append(r.Hosts, h)
		s.sel[h.Name] = i%2 == 0
	}
	s.res = r
	tok := "deadbeef"
	for page := 0; page*scanPageSize < len(s.view()); page++ {
		s.page = page
		text, kb := scanScreen(tok, s, "")
		buttons := 0
		for _, row := range kb.InlineKeyboard {
			if len(row) > 8 {
				t.Errorf("page %d: a row of %d buttons (Telegram allows 8)", page, len(row))
			}
			for _, b := range row {
				buttons++
				if len(b.CallbackData) > 64 {
					t.Errorf("callback_data %q is %d bytes", b.CallbackData, len(b.CallbackData))
				}
				if len([]rune(b.Text)) > 32 {
					t.Errorf("button text %q is long", b.Text)
				}
			}
		}
		if buttons > 100 {
			t.Errorf("page %d: %d buttons (Telegram allows 100)", page, buttons)
		}
		if n := len([]rune(text)); n > telegramTextLimit {
			t.Errorf("page %d: text of %d runes exceeds the limit", page, n)
		}
	}
}

func TestScanSessions_ExpireAndEvict(t *testing.T) {
	b := &TelegramBot{}
	old := b.putScan(&scanSession{chatID: 1})
	b.scanMu.Lock()
	b.scans[old].created = time.Now().Add(-scanSessionTTL - time.Minute)
	b.scanMu.Unlock()
	fresh := b.putScan(&scanSession{chatID: 1}) // sweeps the expired one
	if b.withScan(old, 1, func(*scanSession) {}) {
		t.Error("an expired session survived")
	}
	if !b.withScan(fresh, 1, func(*scanSession) {}) {
		t.Error("a fresh session was lost")
	}
	if b.withScan(fresh, 2, func(*scanSession) {}) {
		t.Error("another chat reached this chat's session")
	}
	for i := 0; i < scanMaxSessions+10; i++ {
		b.putScan(&scanSession{chatID: 1})
	}
	b.scanMu.Lock()
	n := len(b.scans)
	b.scanMu.Unlock()
	if n > scanMaxSessions {
		t.Errorf("%d sessions kept, cap is %d", n, scanMaxSessions)
	}
}

func TestNewScanToken_UniqueAndShort(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		tok := newScanToken()
		if len(tok) != 8 || seen[tok] {
			t.Fatalf("token %q (len %d), duplicate=%v", tok, len(tok), seen[tok])
		}
		seen[tok] = true
	}
}

// The offer names the domains it will read, and says so when it will not
// read all of them.
func TestTelegramBot_ScanOffer_NamesTheDomains(t *testing.T) {
	_, fake, store := newScanBot(t)
	startScanAgent(t, store, func(c Command) (string, string) { return "список: +5 записей", "" })
	addThroughWizard(t, fake, "a.example.com b.example.com c.example.com d.example.com e.example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	for _, want := range []string{"a.example.com, b.example.com, c.example.com", "первые 3 из 5"} {
		if !strings.Contains(offer.Text, want) {
			t.Errorf("the offer lacks %q:\n%s", want, offer.Text)
		}
	}
	if strings.Contains(offer.Text, "d.example.com,") || strings.Contains(offer.Text, ", d.example.com") {
		t.Errorf("the offer names a domain it will not read:\n%s", offer.Text)
	}
}
