package botcontrol

import (
	"strings"
	"testing"
	"time"
)

// addonListTSV is a canned ActionAddonList reply: unbound installed &
// running, the other three not.
const addonListTSV = "unbound\tUnbound — рекурсивный DNS\t1\t1\t1.19.3\t127.0.0.1:5353\n" +
	"nfqws2\tnfqws2 — обход DPI\t0\t-\t-\t-\n" +
	"conntrack\tconntrack\t0\t-\t-\t-\n" +
	"cron\tcron\t1\t1\t-\t-"

func newAddonTestBot(t *testing.T) (*fakeTelegram, *Store, *recorder) {
	t.Helper()
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	rec := recordingAgent(t, store, "r1", func(c Command) string {
		switch c.Action {
		case ActionAddonList:
			return addonListTSV
		case ActionAddonShow:
			return "🧩 " + c.Args[0] + "\n\nописание\n\nсостояние: не установлен"
		case ActionAddonStatus:
			return c.Args[0] + ": не установлен"
		case ActionAddonInstall:
			return c.Args[0] + ": установлен"
		case ActionAddonRemove:
			return c.Args[0] + ": удалён"
		case ActionAddonConfigure:
			return c.Args[0] + ": настройки применены"
		}
		return "ok"
	})
	return fake, store, rec
}

func openMenu(t *testing.T, fake *fakeTelegram) int {
	t.Helper()
	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	return fake.lastSent(t).MessageID
}

func TestTelegramBot_AddonsScreen_ListsComponents(t *testing.T) {
	fake, _, rec := newAddonTestBot(t)
	msgID := openMenu(t, fake)

	fake.pushCallback(1, msgID, "adnm:r1")
	txt := fake.waitForEditContaining(t, 3*time.Second, "Unbound")
	if !strings.Contains(txt, "✅") || !strings.Contains(txt, "⬜") {
		t.Errorf("addons screen should mix ticked/unticked rows: %q", txt)
	}
	if !strings.Contains(txt, "1.19.3") || !strings.Contains(txt, "работает") {
		t.Errorf("addons screen should show version/running for unbound: %q", txt)
	}
	if !rec.has("addon_list ") {
		t.Errorf("recorded = %v, want addon_list", rec.list())
	}
}

func TestTelegramBot_AddonsScreen_OpenComponentThenInstall(t *testing.T) {
	fake, _, rec := newAddonTestBot(t)
	msgID := openMenu(t, fake)

	fake.pushCallback(1, msgID, "adnm:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Unbound")

	// Open the conntrack component screen.
	fake.pushCallback(1, msgID, "adn:r1:conntrack")
	fake.waitForEditContaining(t, 3*time.Second, "🧩 conntrack")

	// Install it.
	fake.pushCallback(1, msgID, "adni:r1:conntrack")
	fake.waitForEditContaining(t, 3*time.Second, "conntrack: установлен")

	if !rec.has("addon_show conntrack") || !rec.has("addon_install conntrack") {
		t.Errorf("recorded = %v, want addon_show + addon_install conntrack", rec.list())
	}
}

func TestTelegramBot_AddonsScreen_StatusAndRemove(t *testing.T) {
	fake, _, rec := newAddonTestBot(t)
	msgID := openMenu(t, fake)
	fake.pushCallback(1, msgID, "adn:r1:nfqws2")
	fake.waitForEditContaining(t, 3*time.Second, "🧩 nfqws2")

	fake.pushCallback(1, msgID, "adns:r1:nfqws2")
	fake.waitForEditContaining(t, 3*time.Second, "nfqws2: не установлен")

	fake.pushCallback(1, msgID, "adnr:r1:nfqws2")
	fake.waitForEditContaining(t, 3*time.Second, "nfqws2: удалён")

	for _, want := range []string{"addon_status nfqws2", "addon_remove nfqws2"} {
		if !rec.has(want) {
			t.Errorf("recorded = %v, want %q", rec.list(), want)
		}
	}
}

func TestTelegramBot_AddonsScreen_ConfigureWizard(t *testing.T) {
	fake, store, _ := newAddonTestBot(t)
	msgID := openMenu(t, fake)

	fake.pushCallback(1, msgID, "adnc:r1:nfqws2")
	waitSent(t, fake, 3*time.Second, "настройка")

	// A bare word (no '=') is rejected without ending the dialog.
	fake.push(1, "garbage")
	waitSent(t, fake, 3*time.Second, "key=value")

	// A valid line goes through as addon_configure with id + pairs.
	fake.push(1, "mode=list tcp_ports=443,80")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionAddonConfigure {
				t.Fatalf("dequeued %q, want addon_configure", cmd.Action)
			}
			if len(cmd.Args) != 3 || cmd.Args[0] != "nfqws2" || cmd.Args[1] != "mode=list" || cmd.Args[2] != "tcp_ports=443,80" {
				t.Fatalf("args = %v, want [nfqws2 mode=list tcp_ports=443,80]", cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "nfqws2: настройки применены"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitSent(t, fake, 3*time.Second, "применены")
}

func TestTelegramBot_AddonsScreen_UnknownRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	fake.pushCallback(1, msgID, "adnm:nope")
	fake.waitForEditContaining(t, 3*time.Second, "нет такого роутера")
}

func TestParseAddonList_SkipsShortAndBlankLines(t *testing.T) {
	in := addonListTSV + "\n\n" + "too\tfew\tfields\n"
	rows := parseAddonList(in)
	if len(rows) != 4 {
		t.Fatalf("parseAddonList = %d rows, want 4 (blank + short lines skipped)", len(rows))
	}
	if rows[0].id != "unbound" || !rows[0].installed || rows[0].running != "1" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].version != "" || rows[1].detail != "" {
		t.Errorf("row 1 dashes should decode to empty: %+v", rows[1])
	}
}

func TestAddonsListText_Formatting(t *testing.T) {
	rows := parseAddonList(addonListTSV)
	txt := addonsListText(rows)
	if !strings.Contains(txt, "✅ Unbound — рекурсивный DNS  · 1.19.3 · работает · 127.0.0.1:5353") {
		t.Errorf("unbound line not formatted as expected:\n%s", txt)
	}
	if !strings.Contains(txt, "⬜ conntrack") {
		t.Errorf("conntrack should be an empty box: %s", txt)
	}
}

func TestAddonScreenKB_Buttons(t *testing.T) {
	kb := addonScreenKB("r1", "unbound")
	var datas []string
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			datas = append(datas, b.CallbackData)
		}
	}
	for _, want := range []string{"adni:r1:unbound", "adnr:r1:unbound", "adnc:r1:unbound", "adns:r1:unbound", "adnm:r1"} {
		if !contains(datas, want) {
			t.Errorf("addonScreenKB missing %q; got %v", want, datas)
		}
	}
	for _, want := range []string{"adnx:r1:unbound:router-dns=on", "adnx:r1:unbound:router-dns=off"} {
		if !contains(datas, want) {
			t.Errorf("unbound screen missing router-dns button %q; got %v", want, datas)
		}
	}
	for _, row := range addonScreenKB("r1", "nfqws2").InlineKeyboard {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, "adnx:") {
				t.Errorf("nfqws2 screen should not have an adnx button: %q", b.CallbackData)
			}
		}
	}
}

func TestTelegramBot_AddonsScreen_UnboundRouterDNSButton(t *testing.T) {
	fake, _, rec := newAddonTestBot(t)
	msgID := openMenu(t, fake)

	fake.pushCallback(1, msgID, "adn:r1:unbound")
	fake.waitForEditContaining(t, 3*time.Second, "🧩 unbound")

	fake.pushCallback(1, msgID, "adnx:r1:unbound:router-dns=on")
	fake.waitForEditContaining(t, 3*time.Second, "настройки применены")
	if !rec.has("addon_configure unbound|router-dns=on") {
		t.Errorf("recorded = %v, want addon_configure unbound|router-dns=on", rec.list())
	}
}
