package botcontrol

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
)

func TestMsField(t *testing.T) {
	if got := msField(dnsupstream.Timing{OK: true, Latency: 45 * time.Millisecond}); got != "45" {
		t.Errorf("msField(ok, 45ms) = %q, want %q", got, "45")
	}
	if got := msField(dnsupstream.Timing{OK: false, Err: "timeout"}); got != "" {
		t.Errorf("msField(not ok) = %q, want empty", got)
	}
}

func TestParseDNSTestTop(t *testing.T) {
	out := "cloudflare\tCloudflare\t45\t52\n" +
		"quad9\tQuad9\t-\t80\n" +
		"dead\tDead Provider\t-\t-\n"
	rows := parseDNSTestTop(out)
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3: %+v", len(rows), rows)
	}
	if rows[0] != (dnsTestTopRow{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"}) {
		t.Errorf("rows[0] = %+v", rows[0])
	}
	if rows[1].DoTMs != "" || rows[1].DoHMs != "80" {
		t.Errorf("rows[1] = %+v, want DoT unavailable (dash undone), DoH 80", rows[1])
	}
	if rows[2].DoTMs != "" || rows[2].DoHMs != "" {
		t.Errorf("rows[2] = %+v, want both unavailable", rows[2])
	}
}

func TestParseDNSTestTop_DropsMalformedLines(t *testing.T) {
	out := "cloudflare\tCloudflare\t45\t52\n" +
		"too\tfew\tfields\n" +
		"quad9\tQuad9\t60\t65\n"
	rows := parseDNSTestTop(out)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (malformed line dropped): %+v", len(rows), rows)
	}
	if rows[0].ID != "cloudflare" || rows[1].ID != "quad9" {
		t.Errorf("rows = %+v, want cloudflare then quad9 (the bad line skipped, not shifting the rest)", rows)
	}
}

func TestParseDNSTestTop_Empty(t *testing.T) {
	if rows := parseDNSTestTop(""); len(rows) != 0 {
		t.Errorf("parseDNSTestTop(\"\") = %+v, want empty", rows)
	}
}

func TestMsLabel(t *testing.T) {
	if got := msLabel("45"); got != "45 мс" {
		t.Errorf("msLabel(45) = %q", got)
	}
	if got := msLabel(""); got != "—" {
		t.Errorf("msLabel(\"\") = %q, want the em-dash placeholder", got)
	}
}

// TestDNSTestTopKB: "apply the whole top" first, then one button per
// provider that answered -- each applying only the protocols that did --
// then back. A provider nothing of which answered gets no button.
func TestDNSTestTopKB(t *testing.T) {
	rows := []dnsTestTopRow{
		{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"},
		{ID: "quad9", Name: "Quad9", DoTMs: "", DoHMs: "80"},
		{ID: "google", Name: "Google"}, // nothing answered
	}
	kb := dnsTestTopKB("r1", rows)
	var got []string
	for _, row := range kb.InlineKeyboard {
		got = append(got, row[0].CallbackData)
	}
	want := []string{"dnall:r1", "dna:r1:cloudflare:both", "dna:r1:quad9:doh", "dnsm:r1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("buttons = %v, want %v", got, want)
	}
	if !strings.Contains(kb.InlineKeyboard[0][0].Text, "(2)") {
		t.Errorf("apply-all button = %q, want the count of providers it applies", kb.InlineKeyboard[0][0].Text)
	}

	// One answering provider: nothing to "apply all" of.
	kb = dnsTestTopKB("r1", rows[1:])
	if kb.InlineKeyboard[0][0].CallbackData != "dna:r1:quad9:doh" {
		t.Errorf("single answering provider: first button %q, want its own apply", kb.InlineKeyboard[0][0].CallbackData)
	}
}

func TestDNSTestTopText_MentionsEveryProviderAndLatency(t *testing.T) {
	rows := []dnsTestTopRow{
		{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"},
		{ID: "quad9", Name: "Quad9", DoTMs: "", DoHMs: "80"},
	}
	text := dnsTestTopText("r1", rows)
	for _, want := range []string{"Cloudflare", "45 мс", "52 мс", "Quad9", "80 мс", "—"} {
		if !strings.Contains(text, want) {
			t.Errorf("dnsTestTopText output missing %q:\n%s", want, text)
		}
	}
}

// TestTelegramBot_DNSApplyWholeTop: test, then "✅ Применить весь топ" --
// the router gets every provider that answered, each with only the
// protocols that answered, in one dns_preset_multi.
func TestTelegramBot_DNSApplyWholeTop(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	var mu sync.Mutex
	var multiArgs []string
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
				time.Sleep(10 * time.Millisecond)
				continue
			}
			out := "ok"
			switch cmd.Action {
			case ActionDNSTestTop:
				out = "controld-p1\tControlD Malware\t-\t20\ndns4eu\tDNS4EU\t35\t40\ncloudflare\tCloudflare\t-\t-\n"
			case ActionDNSPresetMulti:
				mu.Lock()
				multiArgs = cmd.Args
				mu.Unlock()
				out = "DNS → ControlD Malware, DNS4EU"
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: out})
		}
	}()

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "dntest:r1")
	fake.waitForEditContaining(t, 3*time.Second, "топ по задержке")
	if edit := fake.lastEdit(t); !edit.hasButton("dnall:r1") {
		t.Fatalf("no apply-all button on the ranking: %v", edit.Buttons)
	}
	fake.pushCallback(1, msgID, "dnall:r1")
	fake.waitForEditContaining(t, 3*time.Second, "DNS → ControlD Malware, DNS4EU")
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(multiArgs, " ") != "controld-p1:doh dns4eu:both" {
		t.Errorf("dns_preset_multi args = %v, want the two that answered, each with its own protocols", multiArgs)
	}
}

// TestTelegramBot_DNSApplyWholeTop_NeedsAFreshTest: after a control-server
// restart the ranking is gone; the button asks for a new test instead
// of applying nothing.
func TestTelegramBot_DNSApplyWholeTop_NeedsAFreshTest(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)
	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	fake.pushCallback(1, fake.lastSent(t).MessageID, "dnall:r1")
	fake.waitForEditContaining(t, 3*time.Second, "Результатов теста уже нет")
	if cmd, _ := store.Dequeue("r1"); cmd != nil {
		t.Errorf("queued %q with no ranking to apply", cmd.Action)
	}
}
