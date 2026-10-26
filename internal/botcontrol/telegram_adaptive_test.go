package botcontrol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// sampleAdaptiveAnswer is what a router answers to adrt_list: a few headers,
// then one row per entry. Built with formatAdaptiveList so the format and its
// parser are tested against each other, not against a hand-copied string.
func sampleAdaptiveEntries() []adaptiveroute.Entry {
	return adaptiveroute.JoinEntries([]adaptiveroute.Member{
		{Addr: "149.154.167.41", Left: 5*time.Hour + 54*time.Minute, HasTimeout: true},
		{Addr: "2.2.2.2", Left: 4 * time.Hour, HasTimeout: true},
		{Addr: "31.13.72.0/24", Left: 24 * time.Minute, HasTimeout: true},
		{Addr: "198.51.100.9", Left: 41 * time.Second, HasTimeout: true},
		{Addr: "203.0.113.5", Left: time.Hour, HasTimeout: true},
		{Addr: "198.51.100.77", Left: 3 * time.Hour, HasTimeout: true},
	}, (&adaptiveroute.Snapshot{Notes: []adaptiveroute.Note{
		{Addr: "149.154.167.41", Tier: adaptiveroute.TierConfirmed, Reason: "silent-syn", Client: "192.168.1.50", Proto: "tcp", DPort: 443},
		{Addr: "2.2.2.2", Tier: adaptiveroute.TierConfirmed, Reason: "tcp-stall", Client: "192.168.1.51", Proto: "tcp", DPort: 443},
		{Addr: "31.13.72.0/24", Tier: adaptiveroute.TierBlock, Reason: "block-widen"},
		{Addr: "198.51.100.9", Tier: adaptiveroute.TierProbation, Reason: "quic-no-reply", Client: "192.168.1.50", Proto: "udp", DPort: 443},
		{Addr: "198.51.100.77", Tier: adaptiveroute.TierL7SNI, Reason: "l7sni", Host: "youtube.com\tevil"},
	}}).Lookup)
}

func sampleStats() adaptiveroute.StatsSnapshot {
	var st adaptiveroute.StatsSnapshot
	st.Since = time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC)
	st.Hour[adaptiveroute.EventProbation], st.Hour[adaptiveroute.EventConfirmed], st.Hour[adaptiveroute.EventLapsed], st.Hour[adaptiveroute.EventFailed] = 14, 3, 9, 2
	st.Day[adaptiveroute.EventProbation], st.Day[adaptiveroute.EventConfirmed] = 40, 11
	st.Total[adaptiveroute.EventProbation] = 52
	return st
}

func TestAdaptiveList_FormatAndParseAgree(t *testing.T) {
	entries := sampleAdaptiveEntries()
	out := formatAdaptiveList(entries, sampleStats(), 3)

	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "198.51.100.77") && strings.Count(line, "\t") != 7 {
			t.Errorf("a tab in a hostname broke the row format (%d tabs): %q", strings.Count(line, "\t"), line)
		}
	}
	d := parseAdaptiveList(out)
	if d.total != 6 || d.probation != 1 || d.confirmed != 2 || d.block != 1 || d.l7sni != 1 || d.unknown != 1 {
		t.Errorf("counts = %+v", d)
	}
	if d.hour.Of(adaptiveroute.EventLapsed) != 9 || d.day.Of(adaptiveroute.EventConfirmed) != 11 || d.all.Of(adaptiveroute.EventProbation) != 52 {
		t.Errorf("counters hour=%v day=%v total=%v", d.hour, d.day, d.all)
	}
	if !d.since.Equal(time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC)) || d.excluded != 3 {
		t.Errorf("since=%v excluded=%d", d.since, d.excluded)
	}
	if len(d.entries) != 6 {
		t.Fatalf("entries = %d, want 6", len(d.entries))
	}
	// confirmed first (longest left first), then the name match, the subnet, the probation, the unknown
	var order []string
	for _, e := range d.entries {
		order = append(order, e.addr)
	}
	want := "149.154.167.41,2.2.2.2,198.51.100.77,31.13.72.0/24,198.51.100.9,203.0.113.5"
	if strings.Join(order, ",") != want {
		t.Errorf("order = %v, want %s", order, want)
	}
	first := d.entries[0]
	if first.tier != "confirmed" || first.leftSec != 5*3600+54*60 || first.reason != "silent-syn" ||
		first.client != "192.168.1.50" || first.proto != "tcp" || first.dport != 443 {
		t.Errorf("first entry = %+v", first)
	}
	if e := d.entries[2]; e.host != "youtube.com evil" {
		t.Errorf("host = %q, want the tab turned into a space", e.host)
	}
	if e := d.entries[5]; e.tier != "" || e.reason != "" || e.client != "" {
		t.Errorf("an entry with no note = %+v, want empty tier, reason and client", e)
	}
}

func TestAdaptiveList_NeverExpiringAndCap(t *testing.T) {
	entries := make([]adaptiveroute.Entry, 0, adaptiveListMaxRows+50)
	for i := 0; i < adaptiveListMaxRows+50; i++ {
		entries = append(entries, adaptiveroute.Entry{Member: adaptiveroute.Member{Addr: fmt.Sprintf("10.%d.%d.1", i/250, i%250)}})
	}
	d := parseAdaptiveList(formatAdaptiveList(entries, adaptiveroute.StatsSnapshot{}, 0))
	if d.total != adaptiveListMaxRows+50 {
		t.Errorf("total = %d, want the whole set counted in the header", d.total)
	}
	if len(d.entries) != adaptiveListMaxRows {
		t.Errorf("rows = %d, want the cap of %d", len(d.entries), adaptiveListMaxRows)
	}
	if d.entries[0].leftSec != -1 {
		t.Errorf("leftSec = %d, want -1 for an entry that never expires", d.entries[0].leftSec)
	}
	if !d.since.IsZero() {
		t.Errorf("since = %v, want zero when nothing was recorded", d.since)
	}
	text := adaptiveListScreenText("home", d, 0, "")
	if !strings.Contains(text, fmt.Sprintf("из %d (показаны первые %d)", adaptiveListMaxRows+50, adaptiveListMaxRows)) {
		t.Errorf("screen does not say the list is cut:\n%s", text)
	}
}

func TestParseAdaptiveList_ToleratesOtherVersions(t *testing.T) {
	out := "#n\t1\t0\t1\t0\t0\t0\r\n" +
		"#future-header\t1\t2\t3\r\n" +
		"#since\n" +
		"#hour\t1\t2\n" + // fewer counters than this build knows
		"\n" +
		"short\trow\n" +
		"1.2.3.4\tconfirmed\t100\tsilent-syn\t192.168.1.5\ttcp\t443\t\r\n"
	d := parseAdaptiveList(out)
	if d.total != 1 || len(d.entries) != 1 || d.entries[0].addr != "1.2.3.4" || d.entries[0].leftSec != 100 {
		t.Errorf("parsed = %+v", d)
	}
	if d.hour.Of(adaptiveroute.EventProbation) != 1 || d.hour.Of(adaptiveroute.EventConfirmed) != 2 || d.hour.Of(adaptiveroute.EventLapsed) != 0 {
		t.Errorf("hour = %v", d.hour)
	}
	if got := parseAdaptiveList(""); got.total != 0 || len(got.entries) != 0 {
		t.Errorf("empty answer parsed to %+v", got)
	}
}

func TestParseAdaptiveExcluded(t *testing.T) {
	entries, skipped := parseAdaptiveExcluded("#excl\t2\t3\r\n1.2.3.4\r\n\n8.8.8.0/24\n")
	if strings.Join(entries, ",") != "1.2.3.4,8.8.8.0/24" || skipped != 3 {
		t.Errorf("entries = %v, skipped = %d", entries, skipped)
	}
	if entries, skipped := parseAdaptiveExcluded(""); len(entries) != 0 || skipped != 0 {
		t.Errorf("empty = %v, %d", entries, skipped)
	}
}

func TestAdaptiveListScreen_FirstPage(t *testing.T) {
	d := parseAdaptiveList(formatAdaptiveList(sampleAdaptiveEntries(), sampleStats(), 3))
	text := adaptiveListScreenText("home", d, 0, "🚫 Исключено: 1.1.1.1")
	for _, want := range []string{
		"🚫 Исключено: 1.1.1.1",
		"🎯 Что перенаправлено — home",
		"Сейчас перенаправлено: 6 — на пробе 1 · подтверждено 2 · подсетей 1 · по имени 1 · без пометки 1",
		"За час: проб 14 · подтверждено 3 · истекло без вердикта 9 · не помогло 2",
		"Исключений (не перенаправляются никогда): 3",
		"Адреса 1–6 из 6:",
		"1. ✅ 149.154.167.41 · ещё 5ч 54м · SYN ушёл, ответа нет · 192.168.1.50 tcp/443",
		"3. 🔍 198.51.100.77 · ещё 3ч · youtube.com evil",
		"4. 🌐 31.13.72.0/24 · ещё 24м · укрупнение: несколько подтверждённых адресов в одной сети",
		"5. 🧪 198.51.100.9 · ещё 41с · QUIC без ответа · 192.168.1.50 udp/443",
		"6. ❔ 203.0.113.5 · ещё 1ч",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("screen lacks %q:\n%s", want, text)
		}
	}
	if n := len([]rune(text)); n > telegramTextLimit {
		t.Errorf("screen is %d runes, over the %d limit", n, telegramTextLimit)
	}

	kb := adaptiveListKB("home", d, 0)
	cb := callbacks(kb)
	for i := 0; i < 6; i++ {
		if !cb[fmt.Sprintf("adxI:home:%d", i)] {
			t.Errorf("no button for entry %d among %v", i, cb)
		}
	}
	for _, want := range []string{"adxX:home", "adxO:home", "adrt:home"} {
		if !cb[want] {
			t.Errorf("keyboard lacks %s: %v", want, cb)
		}
	}
	if cb["adxL:home:1"] {
		t.Error("a single page must not offer paging")
	}
	for data := range cb {
		if len(data) > 64 {
			t.Errorf("callback_data %q is %d bytes, over Telegram's 64", data, len(data))
		}
	}
}

func callbacks(kb inlineKeyboard) map[string]bool {
	out := map[string]bool{}
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			out[b.CallbackData] = true
		}
	}
	return out
}

func TestAdaptiveListScreen_Paging(t *testing.T) {
	var d adaptiveListData
	d.total = 20
	for i := 0; i < 20; i++ {
		d.entries = append(d.entries, adaptiveListEntry{addr: fmt.Sprintf("10.0.0.%d", i+1), tier: "confirmed", leftSec: 3600})
	}
	t0 := adaptiveListScreenText("home", d, 0, "")
	t2 := adaptiveListScreenText("home", d, 2, "")
	if !strings.Contains(t0, "Адреса 1–8 из 20:") || !strings.Contains(t0, "8. ✅ 10.0.0.8") || strings.Contains(t0, "9. ") {
		t.Errorf("page 0:\n%s", t0)
	}
	if !strings.Contains(t2, "Адреса 17–20 из 20:") || !strings.Contains(t2, "20. ✅ 10.0.0.20") {
		t.Errorf("last page:\n%s", t2)
	}
	if clamp := adaptiveListScreenText("home", d, 99, ""); !strings.Contains(clamp, "Адреса 17–20 из 20:") {
		t.Errorf("a page past the end should show the last one:\n%s", clamp)
	}

	first, middle, last := callbacks(adaptiveListKB("home", d, 0)), callbacks(adaptiveListKB("home", d, 1)), callbacks(adaptiveListKB("home", d, 2))
	if first["adxL:home:-1"] || !first["adxL:home:1"] {
		t.Errorf("first page nav = %v", first)
	}
	if !middle["adxL:home:0"] || !middle["adxL:home:2"] || !middle["adxI:home:8"] || middle["adxI:home:7"] {
		t.Errorf("middle page nav = %v", middle)
	}
	if !last["adxL:home:1"] || last["adxL:home:3"] || !last["adxI:home:19"] {
		t.Errorf("last page nav = %v", last)
	}
}

func TestAdaptiveListScreen_Empty(t *testing.T) {
	text := adaptiveListScreenText("home", parseAdaptiveList(formatAdaptiveList(nil, adaptiveroute.StatsSnapshot{}, 0)), 0, "")
	if !strings.Contains(text, "Список пуст") || !strings.Contains(text, "С запуска демона классификатор ничего не ловил") {
		t.Errorf("empty screen:\n%s", text)
	}
	cb := callbacks(adaptiveListKB("home", adaptiveListData{}, 0))
	if !cb["adxX:home"] || !cb["adrt:home"] {
		t.Errorf("empty list keyboard = %v", cb)
	}
}

func TestAdaptiveItemCard(t *testing.T) {
	d := parseAdaptiveList(formatAdaptiveList(sampleAdaptiveEntries(), sampleStats(), 0))

	addr := d.entries[0] // 149.154.167.41, confirmed
	text := adaptiveItemText(addr)
	for _, want := range []string{"🎯 149.154.167.41", "✅ подтверждён", "Осталось в списке: 5ч 54м", "Что заметил: SYN ушёл, ответа нет", "Кто: 192.168.1.50 tcp/443", "Подтверждён: через туннель реально заработало"} {
		if !strings.Contains(text, want) {
			t.Errorf("card lacks %q:\n%s", want, text)
		}
	}
	cb := callbacks(adaptiveItemKB("home", 0, addr))
	if !cb["adxE:home:0:a"] || !cb["adxE:home:0:n"] || !cb["adxO:home"] {
		t.Errorf("address card keyboard = %v", cb)
	}
	if kb := adaptiveItemKB("home", 0, addr); !strings.Contains(kb.InlineKeyboard[1][0].Text, "149.154.167.0/24") {
		t.Errorf("the /24 button should name the network: %+v", kb.InlineKeyboard[1])
	}

	var block adaptiveListEntry
	for _, e := range d.entries {
		if strings.Contains(e.addr, "/") {
			block = e
		}
	}
	if block.addr == "" {
		t.Fatal("no block in the sample")
	}
	bk := adaptiveItemKB("home", 3, block)
	if cb := callbacks(bk); !cb["adxE:home:3:a"] || cb["adxE:home:3:n"] {
		t.Errorf("a block card should offer excluding the block only: %v", cb)
	}
	if !strings.Contains(bk.InlineKeyboard[0][0].Text, "подсеть") {
		t.Errorf("block button = %q", bk.InlineKeyboard[0][0].Text)
	}

	named := d.entries[2]
	if text := adaptiveItemText(named); !strings.Contains(text, "Имя: youtube.com evil") || !strings.Contains(text, "По имени:") {
		t.Errorf("l7sni card:\n%s", text)
	}
	unknown := d.entries[5]
	if text := adaptiveItemText(unknown); !strings.Contains(text, "Без пометки:") || strings.Contains(text, "Что заметил") {
		t.Errorf("unknown card:\n%s", text)
	}
	forever := adaptiveListEntry{addr: "1.2.3.4", leftSec: -1}
	if text := adaptiveItemText(forever); !strings.Contains(text, "Срока нет") {
		t.Errorf("never-expiring card:\n%s", text)
	}
}

func TestAdaptiveNet24(t *testing.T) {
	for in, want := range map[string]string{"149.154.167.41": "149.154.167.0/24", "1.2.3.255": "1.2.3.0/24"} {
		if got, ok := adaptiveNet24(in); !ok || got != want {
			t.Errorf("adaptiveNet24(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"31.13.72.0/24", "garbage", "::1", ""} {
		if got, ok := adaptiveNet24(in); ok {
			t.Errorf("adaptiveNet24(%q) = %q, want none", in, got)
		}
	}
}

func TestAdaptiveExcludedScreen(t *testing.T) {
	entries := []string{"1.1.1.1", "8.8.8.0/24"}
	text := adaptiveExcludedText("home", entries, 2, 0, "↩️ Возвращено: 9.9.9.9")
	for _, want := range []string{"↩️ Возвращено: 9.9.9.9", "🚫 Исключения — home", "Записи 1–2 из 2:", "1. 1.1.1.1", "2. 8.8.8.0/24", "строк, которые не удалось разобрать: 2"} {
		if !strings.Contains(text, want) {
			t.Errorf("screen lacks %q:\n%s", want, text)
		}
	}
	cb := callbacks(adaptiveExcludedKB("home", entries, 0))
	for _, want := range []string{"adxR:home:0", "adxR:home:1", "adxO:home", "adrt:home"} {
		if !cb[want] {
			t.Errorf("keyboard lacks %s: %v", want, cb)
		}
	}

	if text := adaptiveExcludedText("home", nil, 0, 0, ""); !strings.Contains(text, "Список пуст") {
		t.Errorf("empty screen:\n%s", text)
	}

	var many []string
	for i := 0; i < 25; i++ {
		many = append(many, fmt.Sprintf("10.0.0.%d", i+1))
	}
	if text := adaptiveExcludedText("home", many, 0, 2, ""); !strings.Contains(text, "Записи 21–25 из 25:") {
		t.Errorf("third page:\n%s", text)
	}
	mid := callbacks(adaptiveExcludedKB("home", many, 1))
	if !mid["adxP:home:0"] || !mid["adxP:home:2"] || !mid["adxR:home:10"] || mid["adxR:home:9"] {
		t.Errorf("middle page = %v", mid)
	}
}

func TestAdaptiveActivityText(t *testing.T) {
	got := adaptiveActivityText(adaptiveroute.Tally{Total: 29, Probation: 12, Confirmed: 15, Block: 2}, sampleStats(), 3)
	for _, want := range []string{
		"\nСейчас перенаправлено: 29 — на пробе 12 · подтверждено 15 · подсетей 2",
		"\nЗа час: проб 14 · подтверждено 3 · истекло без вердикта 9 · не помогло 2",
		"\nЗа сутки: проб 40 · подтверждено 11",
		"(счётчики с ",
		"\nИсключений (не перенаправляются никогда): 3",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("activity text lacks %q:\n%s", want, got)
		}
	}
	quiet := adaptiveActivityText(adaptiveroute.Tally{}, adaptiveroute.StatsSnapshot{}, 0)
	if quiet != "\nСейчас перенаправлено: 0\nС запуска демона классификатор ничего не ловил" {
		t.Errorf("quiet = %q", quiet)
	}
}

// --- the router's side of exclude / include / excluded ---

func newAdaptiveHandler(t *testing.T) *RouterHandler {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	cfg := config.Default()
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	return &RouterHandler{Config: cfg, ConfigPath: cfgPath}
}

func TestRouterHandler_AdaptiveRouteExcludeIncludeExcluded(t *testing.T) {
	h := newAdaptiveHandler(t)
	path := adaptiveroute.ExclusionsPath(h.ConfigPath)

	out, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExclude, Args: []string{" 142.251.153.4 "}})
	if err != nil || !strings.Contains(out, "🚫 Исключено: 142.251.153.4") {
		t.Fatalf("adrt_excl = %q, %v", out, err)
	}
	out, err = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExclude, Args: []string{"142.251.153.4"}})
	if err != nil || !strings.Contains(out, "уже в списке исключений") {
		t.Errorf("a repeated adrt_excl = %q, %v", out, err)
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExclude, Args: []string{"8.8.8.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if ex, _ := adaptiveroute.LoadExclusions(path); ex.Len() != 2 || !ex.Contains("8.8.8.77") {
		t.Errorf("file after two excludes = %v", ex.Entries())
	}

	out, err = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExcluded})
	if err != nil {
		t.Fatal(err)
	}
	entries, skipped := parseAdaptiveExcluded(out)
	if strings.Join(entries, ",") != "142.251.153.4,8.8.8.0/24" || skipped != 0 {
		t.Errorf("adrt_exlist = %q -> %v, %d", out, entries, skipped)
	}

	out, err = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteInclude, Args: []string{"142.251.153.4"}})
	if err != nil || !strings.Contains(out, "↩️ Возвращено: 142.251.153.4") {
		t.Fatalf("adrt_incl = %q, %v", out, err)
	}
	out, err = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteInclude, Args: []string{"142.251.153.4"}})
	if err != nil || !strings.Contains(out, "не было в списке исключений") {
		t.Errorf("a repeated adrt_incl = %q, %v", out, err)
	}
	if ex, _ := adaptiveroute.LoadExclusions(path); ex.Len() != 1 || ex.Contains("142.251.153.4") {
		t.Errorf("file after include = %v", ex.Entries())
	}
}

func TestRouterHandler_AdaptiveRouteExclude_RejectsBadInput(t *testing.T) {
	h := newAdaptiveHandler(t)
	for _, args := range [][]string{nil, {""}, {"not-an-ip"}, {"0.0.0.0/0"}, {"2001:db8::1"}} {
		if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExclude, Args: args}); err == nil {
			t.Errorf("adrt_excl %v should have failed", args)
		}
	}
	if _, err := os.Stat(adaptiveroute.ExclusionsPath(h.ConfigPath)); !os.IsNotExist(err) {
		t.Errorf("a rejected entry still created the list file (stat err = %v)", err)
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteInclude}); err == nil {
		t.Error("adrt_incl with no argument should fail")
	}
}

func TestRouterHandler_AdaptiveRouteExclude_NeedsAConfigPath(t *testing.T) {
	h := &RouterHandler{Config: config.Default()} // no ConfigPath: the list has nowhere to live
	for _, a := range []string{ActionAdaptiveRouteExcluded} {
		if _, err := h.Handle(context.Background(), Command{Action: a}); err == nil {
			t.Errorf("%s without a config path should fail rather than write into the working directory", a)
		}
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteExclude, Args: []string{"1.2.3.4"}}); err == nil {
		t.Error("adrt_excl without a config path should fail")
	}
}

func TestRouterHandler_AdaptiveRouteList_WithoutNdmc(t *testing.T) {
	h := newAdaptiveHandler(t)
	if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteList}); err == nil || !strings.Contains(err.Error(), "выключена") {
		t.Errorf("adrt_list with the feature off = %v, want it to say so", err)
	}
	h.Config.AdaptiveRoute.Enabled = true
	if _, err := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteList}); err == nil || !strings.Contains(err.Error(), "ndmc") {
		t.Errorf("adrt_list off the router = %v, want the not-a-Keenetic error", err)
	}
}

func TestAdaptiveScreen_OffersTheNewLists(t *testing.T) {
	cb := callbacks(adaptiveRouteScreenKB("home"))
	if !cb["adxO:home"] || !cb["adxX:home"] {
		t.Errorf("adaptive screen keyboard = %v, want the two list entry points", cb)
	}
	text := adaptiveRouteScreenText("home")
	for _, want := range []string{"Что перенаправлено", "Исключения", "transport adaptive list"} {
		if !strings.Contains(text, want) {
			t.Errorf("adaptive screen text lacks %q", want)
		}
	}
	if n := len([]rune(text)); n > telegramTextLimit-100 {
		t.Errorf("adaptive screen text is %d runes -- too close to the %d limit, the tail would be cut", n, telegramTextLimit)
	}
}

// --- the whole flow through the bot ---

// answerCommands plays the router: it answers the next len(outputs) queued
// commands in order, recording the action and args it was asked for.
func answerCommands(t *testing.T, store *Store, router string, outputs []Result) <-chan Command {
	t.Helper()
	seen := make(chan Command, len(outputs))
	go func() {
		for _, res := range outputs {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if cmd, _ := store.Dequeue(router); cmd != nil {
					seen <- *cmd
					res.CommandID = cmd.ID
					_ = store.RecordResult(router, res)
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()
	return seen
}

func TestTelegramBot_AdaptiveListThenExclude(t *testing.T) {
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

	list := formatAdaptiveList(sampleAdaptiveEntries(), sampleStats(), 0)
	// after excluding 198.51.100.9 the router would answer without it
	var kept []adaptiveroute.Entry
	for _, e := range sampleAdaptiveEntries() {
		if e.Addr != "198.51.100.9" {
			kept = append(kept, e)
		}
	}
	seen := answerCommands(t, store, "home", []Result{
		{Output: list},
		{Output: "🚫 Исключено: 198.51.100.9\nУбрано из перенаправления: 198.51.100.9. Открытые соединения оборваны — переподключатся напрямую."},
		{Output: formatAdaptiveList(kept, sampleStats(), 1)},
	})

	// 1. open the list
	fake.pushCallback(1, msgID, "adxO:home")
	text := fake.waitForEditContaining(t, 3*time.Second, "Адреса 1–6 из 6:")
	if !strings.Contains(text, "5. 🧪 198.51.100.9") {
		t.Fatalf("list screen:\n%s", text)
	}
	if cmd := <-seen; cmd.Action != ActionAdaptiveRouteList {
		t.Errorf("first command = %s, want %s", cmd.Action, ActionAdaptiveRouteList)
	}
	edit := fake.lastEdit(t)
	if !edit.hasButton("adxI:home:4") || !edit.hasButton("adxX:home") {
		t.Fatalf("list buttons = %v", edit.Buttons)
	}

	// 2. open entry 5's card (index 4)
	fake.pushCallback(1, msgID, "adxI:home:4")
	card := fake.waitForEditContaining(t, 3*time.Second, "🎯 198.51.100.9")
	if !strings.Contains(card, "Проба:") {
		t.Errorf("card:\n%s", card)
	}
	if !fake.lastEdit(t).hasButton("adxE:home:4:a") {
		t.Fatalf("card buttons = %v", fake.lastEdit(t).Buttons)
	}

	// 3. exclude it: the router is asked, then the list is fetched again
	fake.pushCallback(1, msgID, "adxE:home:4:a")
	after := fake.waitForEditContaining(t, 3*time.Second, "Адреса 1–5 из 5:")
	if !strings.Contains(after, "🚫 Исключено: 198.51.100.9") {
		t.Errorf("the router's answer should head the refreshed list:\n%s", after)
	}
	if strings.Contains(after, "5. 🧪 198.51.100.9") {
		t.Errorf("the excluded entry is still listed:\n%s", after)
	}
	cmd := <-seen
	if cmd.Action != ActionAdaptiveRouteExclude || len(cmd.Args) != 1 || cmd.Args[0] != "198.51.100.9" {
		t.Errorf("exclude command = %+v", cmd)
	}
	if cmd := <-seen; cmd.Action != ActionAdaptiveRouteList {
		t.Errorf("after excluding, the list should be re-fetched; got %s", cmd.Action)
	}
	if !strings.Contains(after, "Исключений (не перенаправляются никогда): 1") {
		t.Errorf("the refreshed list should count the new exclusion:\n%s", after)
	}
}

func TestTelegramBot_AdaptiveExcludeWholeNet24AndReturn(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	seen := answerCommands(t, store, "home", []Result{
		{Output: formatAdaptiveList(sampleAdaptiveEntries(), sampleStats(), 0)},
		{Output: "🚫 Исключено: 149.154.167.0/24"},
		{Output: formatAdaptiveList(sampleAdaptiveEntries(), sampleStats(), 1)},
		{Output: "#excl\t1\t0\n149.154.167.0/24\n"},
		{Output: "↩️ Возвращено: 149.154.167.0/24."},
		{Output: "#excl\t0\t0\n"},
	})

	fake.pushCallback(1, msgID, "adxO:home")
	fake.waitForEditContaining(t, 3*time.Second, "Адреса 1–6 из 6:")
	<-seen

	fake.pushCallback(1, msgID, "adxI:home:0")
	fake.waitForEditContaining(t, 3*time.Second, "🎯 149.154.167.41")
	fake.pushCallback(1, msgID, "adxE:home:0:n")
	fake.waitForEditContaining(t, 3*time.Second, "Исключений (не перенаправляются никогда): 1")
	if cmd := <-seen; cmd.Action != ActionAdaptiveRouteExclude || cmd.Args[0] != "149.154.167.0/24" {
		t.Errorf("exclude command = %+v, want the whole /24", cmd)
	}
	<-seen

	// the exclusions screen, then return the entry
	fake.pushCallback(1, msgID, "adxX:home")
	scr := fake.waitForEditContaining(t, 3*time.Second, "1. 149.154.167.0/24")
	if !strings.Contains(scr, "🚫 Исключения — home") {
		t.Errorf("exclusions screen:\n%s", scr)
	}
	if cmd := <-seen; cmd.Action != ActionAdaptiveRouteExcluded {
		t.Errorf("command = %s, want %s", cmd.Action, ActionAdaptiveRouteExcluded)
	}
	if !fake.lastEdit(t).hasButton("adxR:home:0") {
		t.Fatalf("exclusions buttons = %v", fake.lastEdit(t).Buttons)
	}
	fake.pushCallback(1, msgID, "adxR:home:0")
	empty := fake.waitForEditContaining(t, 3*time.Second, "Список пуст")
	if !strings.Contains(empty, "↩️ Возвращено: 149.154.167.0/24") {
		t.Errorf("screen after returning:\n%s", empty)
	}
	if cmd := <-seen; cmd.Action != ActionAdaptiveRouteInclude || cmd.Args[0] != "149.154.167.0/24" {
		t.Errorf("include command = %+v", cmd)
	}
}

func TestTelegramBot_AdaptiveStaleButtonsDoNotCrash(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	edits := func() int {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return len(fake.edits)
	}
	press := func(data string) {
		t.Helper()
		before := edits()
		fake.pushCallback(1, msgID, data)
		fake.waitFor(t, 3*time.Second, "an edit after "+data, func() string {
			if edits() > before {
				return "x"
			}
			return ""
		})
	}

	// No list has been opened in this chat: the cached snapshot is absent.
	for _, data := range []string{"adxL:home:1", "adxI:home:3", "adxE:home:3:a", "adxP:home:0", "adxR:home:0", "adxE:home:x:a"} {
		press(data)
		if got := fake.lastEdit(t); !strings.Contains(got.Text, "список устарел") {
			t.Errorf("%s answered %q, want the stale-list note", data, got.Text)
		}
	}
	// Malformed buttons are refused, never a panic.
	press("adxE:home")
	if got := fake.lastEdit(t); !strings.Contains(got.Text, "плохая кнопка") {
		t.Errorf("adxE:home answered %q", got.Text)
	}
	press("adxQ:home")
	if got := fake.lastEdit(t); !strings.Contains(got.Text, "неизвестная кнопка") {
		t.Errorf("adxQ:home answered %q", got.Text)
	}
	press("adxO:nosuchrouter")
	if got := fake.lastEdit(t); !strings.Contains(got.Text, "нет такого роутера") {
		t.Errorf("adxO:nosuchrouter answered %q", got.Text)
	}
	press("adxX:nosuchrouter")
	if got := fake.lastEdit(t); !strings.Contains(got.Text, "нет такого роутера") {
		t.Errorf("adxX:nosuchrouter answered %q", got.Text)
	}
	if n := store.PendingCount("home"); n != 0 {
		t.Errorf("%d commands were queued by stale or malformed buttons, want none", n)
	}
}
