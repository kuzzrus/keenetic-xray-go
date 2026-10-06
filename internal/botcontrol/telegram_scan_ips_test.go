package botcontrol

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
)

// The addresses (IPs) part of the 🔎 flow: what an app that connects by
// address needs, kept in a list of its own next to the domains.

func scanTSV(pages []depscan.Page, hosts ...depscan.Host) string {
	return (&depscan.Result{Pages: pages, Hosts: hosts}).TSV()
}

func withIPs(h depscan.Host, ips ...string) depscan.Host {
	h.IPs = ips
	return h
}

func lastEditText(f *fakeTelegram) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.edits) == 0 {
		return ""
	}
	return f.edits[len(f.edits)-1].Text
}

func TestTelegramBot_ScanFlow_AddressesGoToTheCompanionList(t *testing.T) {
	_, fake, store := newScanBot(t)
	agent := startScanAgent(t, store, func(c Command) (string, string) {
		switch c.Action {
		case ActionRoutesScan:
			return scanTSV(
				[]depscan.Page{{Seed: "example.com", Status: 200, SeedIPs: []string{"93.184.216.34"}, SeedIPsDropped: 1}},
				withIPs(needHost("img.example-a.net"), "95.47.173.36", "95.47.173.35"),
				withIPs(needHost("cdn.example-c.net"), "8.8.4.4"),
				withIPs(maybeHost("csp.example-d.net"), "1.0.0.1"),
			), ""
		case ActionRoutesAdd:
			return "список: +2 записей", ""
		case ActionRoutesAddIP:
			return `создан IP-список "mylist-ip" (интерфейс и режим как у "mylist"): +4 записей`, ""
		}
		return "ok", ""
	})
	addThroughWizard(t, fake, "example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	if !strings.Contains(offer.Text, "IP-адреса") {
		t.Errorf("the offer does not mention addresses:\n%s", offer.Text)
	}
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Нужны (2)")

	screen := fake.lastEdit(t)
	// The domain's own address and the two ticked hosts' -- not the unticked "maybe" host's.
	if !strings.Contains(screen.Text, "🔢 IP-адреса: 4") || !strings.Contains(screen.Text, "Сейчас: выключено") || !strings.Contains(screen.Text, "Ещё 1 отброшено") {
		t.Errorf("address block:\n%s", screen.Text)
	}
	if !screen.hasButton("rsi:" + tok) {
		t.Errorf("no address toggle: %v", screen.Buttons)
	}
	// Switch on, untick one host, add.
	fake.pushCallback(1, offer.MessageID, "rsi:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "Сейчас: ВКЛЮЧЕНО")
	if txt := lastEditText(fake); !strings.Contains(txt, "8.8.4.4, 93.184.216.34, 95.47.173.35, 95.47.173.36") {
		t.Errorf("the addresses to be added are not shown, in address order:\n%s", txt)
	}
	fake.pushCallback(1, offer.MessageID, "rst:"+tok+":1") // untick cdn.example-c.net: its 8.8.4.4 goes with it
	fake.waitForEditContaining(t, 3*time.Second, "🔢 IP-адреса: 3")
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "отдельном списке")

	adds, ipAdds := agent.args(ActionRoutesAdd), agent.args(ActionRoutesAddIP)
	if len(adds) != 2 || adds[1][0] != "mylist" || adds[1][1] != "img.example-a.net" {
		t.Errorf("routes_add = %v", adds)
	}
	if len(ipAdds) != 1 || ipAdds[0][0] != "mylist" || ipAdds[0][1] != "93.184.216.34 95.47.173.35 95.47.173.36" {
		t.Errorf("routes_add_ip = %v, want the domain's own address and the ticked host's", ipAdds)
	}
	final := lastEditText(fake)
	for _, want := range []string{"создан IP-список", "WireGuard или OpkgTun", "🎯 Интерфейс"} {
		if !strings.Contains(final, want) {
			t.Errorf("final message lacks %q:\n%s", want, final)
		}
	}
}

func TestTelegramBot_ScanFlow_AnAppHostWithNoPage(t *testing.T) {
	// A call app's host has no web page: the scan reads nothing, but the
	// addresses of the name are the whole point.
	_, fake, store := newScanBot(t)
	agent := startScanAgent(t, store, func(c Command) (string, string) {
		switch c.Action {
		case ActionRoutesScan:
			return scanTSV([]depscan.Page{{
				Seed: "voip.example.com", Note: "страница не открылась через туннель (таймаут) — IP-адреса домена найдены",
				SeedIPs: []string{"149.154.167.51", "149.154.167.91"},
			}}), ""
		case ActionRoutesAddIP:
			return `IP-список "mylist-ip": +2 записей, всего 2`, ""
		}
		return "список: +1 записей", ""
	})
	addThroughWizard(t, fake, "voip.example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "🔢 IP-адреса: 2")

	screen := fake.lastEdit(t)
	if strings.Contains(screen.Text, "Добавлять нечего") {
		t.Errorf("says there is nothing to add though addresses were found:\n%s", screen.Text)
	}
	if !screen.hasButton("rsi:"+tok) || !screen.hasButton("rsa:"+tok) || screen.hasButton("rst:"+tok+":0") {
		t.Errorf("buttons = %v", screen.Buttons)
	}
	// Adding with the addresses off adds nothing.
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "Ничего не отмечено")
	if got := agent.args(ActionRoutesAddIP); len(got) != 0 {
		t.Fatalf("addresses sent with the switch off: %v", got)
	}
	// On: only the address call, no domain call from the scan.
	fake.pushCallback(1, offer.MessageID, "rsi:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "149.154.167.51, 149.154.167.91")
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "отдельном списке")
	if got := agent.args(ActionRoutesAddIP); len(got) != 1 || got[0][1] != "149.154.167.51 149.154.167.91" {
		t.Errorf("routes_add_ip = %v", got)
	}
	if got := agent.args(ActionRoutesAdd); len(got) != 1 { // only the wizard's own add of the domain
		t.Errorf("a domain add was sent for a scan with no hosts: %v", got)
	}
}

func TestTelegramBot_ScanFlow_AFailedDomainAddStopsTheAddresses(t *testing.T) {
	_, fake, store := newScanBot(t)
	var adds int32
	agent := startScanAgent(t, store, func(c Command) (string, string) {
		switch c.Action {
		case ActionRoutesScan:
			return scanTSV([]depscan.Page{{Seed: "example.com", Status: 200, SeedIPs: []string{"93.184.216.34"}}},
				withIPs(needHost("img.example-a.net"), "95.47.173.35")), ""
		case ActionRoutesAdd:
			if atomic.AddInt32(&adds, 1) > 1 { // the wizard's add works; the scan's fails
				return "", "в списке уже 256 записей"
			}
			return "список: +1 записей", ""
		}
		return "ok", ""
	})
	addThroughWizard(t, fake, "example.com")
	offer := waitForButtonMsg(t, fake, "rsq:")
	tok := strings.TrimPrefix(buttonWithPrefix(offer, "rsq:"), "rsq:")
	fake.pushCallback(1, offer.MessageID, "rsq:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "Нужны (1)")
	fake.pushCallback(1, offer.MessageID, "rsi:"+tok)
	fake.waitForEditContaining(t, 3*time.Second, "Сейчас: ВКЛЮЧЕНО")
	fake.pushCallback(1, offer.MessageID, "rsa:"+tok)
	fake.waitForEditContaining(t, 5*time.Second, "в списке уже 256 записей")
	if got := agent.args(ActionRoutesAddIP); len(got) != 0 {
		t.Errorf("addresses were added after the domains failed: %v", got)
	}
}

func TestScanScreen_AddressBlockAndButtons(t *testing.T) {
	r := &depscan.Result{
		Pages: []depscan.Page{{Seed: "example.com", Status: 200, SeedIPs: []string{"93.184.216.34"}, SeedIPsDropped: 2}},
		Hosts: []depscan.Host{
			withIPs(needHost("a.example-a.net"), "1.1.1.1", "1.1.1.2"),
			withIPs(needHost("b.example-a.net"), "2.2.2.2"),
		},
	}
	s := &scanSession{routerID: "r1", res: r, sel: map[string]bool{"a.example-a.net": true, "b.example-a.net": true}}
	labels := func() []string {
		_, kb := scanScreen("tok12345", s, "")
		var out []string
		for _, row := range kb.InlineKeyboard {
			for _, b := range row {
				out = append(out, b.Text)
			}
		}
		return out
	}
	has := func(label string) bool { return slices.Contains(labels(), label) }

	text, _ := scanScreen("tok12345", s, "")
	if !strings.Contains(text, "🔢 IP-адреса: 4") || strings.Contains(text, "1.1.1.1") {
		t.Errorf("off: the count is shown, the addresses are not:\n%s", text)
	}
	if !has("🔢 + IP (4): выкл") || !has("✅ Добавить выбранные (2)") {
		t.Errorf("off: %v", labels())
	}
	s.withIPs = true
	text, _ = scanScreen("tok12345", s, "")
	if !strings.Contains(text, "1.1.1.1, 1.1.1.2, 2.2.2.2, 93.184.216.34") || !strings.Contains(text, "Ещё 2 отброшено") {
		t.Errorf("on:\n%s", text)
	}
	if !has("🔢 + IP (4): ВКЛ") || !has("✅ Добавить: 2 доменов + 4 IP") {
		t.Errorf("on: %v", labels())
	}
	// Untick everything: the domain's own address remains, and the button says addresses only.
	s.sel = map[string]bool{}
	if !has("✅ Добавить IP (1)") || !has("🔢 + IP (1): ВКЛ") {
		t.Errorf("nothing ticked: %v", labels())
	}
	// No addresses anywhere: no toggle at all.
	s.res = &depscan.Result{Pages: []depscan.Page{{Seed: "example.com", Status: 200}}, Hosts: []depscan.Host{needHost("a.example-a.net")}}
	s.withIPs = false
	if slices.ContainsFunc(labels(), func(l string) bool { return strings.Contains(l, "IP") }) {
		t.Errorf("an address toggle with no addresses: %v", labels())
	}
}

func TestScanScreen_LongAddressListsStayWithinLimits(t *testing.T) {
	r := &depscan.Result{Pages: []depscan.Page{{Seed: "example.com", Status: 200}}}
	s := &scanSession{routerID: "r1", res: r, sel: map[string]bool{}, withIPs: true}
	for i := 0; i < 30; i++ {
		var ips []string
		for j := 0; j < 8; j++ {
			ips = append(ips, fmt.Sprintf("93.%d.%d.%d", i, j, i+j+1))
		}
		h := withIPs(needHost(fmt.Sprintf("host%02d.%s.example-a.net", i, strings.Repeat("x", 30))), ips...)
		r.Hosts = append(r.Hosts, h)
		s.sel[h.Name] = true
	}
	for page := 0; page*scanPageSize < len(s.view()); page++ {
		s.page = page
		text, kb := scanScreen("deadbeef", s, "")
		if n := len([]rune(text)); n > telegramTextLimit {
			t.Errorf("page %d: %d runes", page, n)
		}
		for _, row := range kb.InlineKeyboard {
			for _, b := range row {
				if len(b.CallbackData) > 64 {
					t.Errorf("callback_data %q is %d bytes", b.CallbackData, len(b.CallbackData))
				}
			}
		}
		if !strings.Contains(text, ", …") {
			t.Errorf("page %d: 240 addresses are not truncated:\n%s", page, text)
		}
	}
}

func TestScanScreen_AllAddressesDroppedIsSaid(t *testing.T) {
	r := &depscan.Result{
		Pages: []depscan.Page{{Seed: "yandex.ru", Status: 200, SeedIPsDropped: 3}},
		Hosts: []depscan.Host{needHost("img.example-a.net")},
	}
	s := &scanSession{routerID: "r1", res: r, sel: map[string]bool{"img.example-a.net": true}}
	text, kb := scanScreen("tok12345", s, "")
	if !strings.Contains(text, "🔢 IP-адреса: подходящих нет — отброшено 3") {
		t.Errorf("silent about dropped addresses:\n%s", text)
	}
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			if strings.HasPrefix(b.CallbackData, "rsi:") {
				t.Errorf("an address switch with no addresses: %q", b.Text)
			}
		}
	}
}
