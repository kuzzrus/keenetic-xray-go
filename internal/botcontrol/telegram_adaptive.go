package botcontrol

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
)

// The 🎯 Адаптивная маршрутизация screen's two lists: "что перенаправлено"
// (what is in the redirect set right now, why, and a button to exclude each
// entry) and "исключения" (the operator's never-route list, with a button to
// return each entry). Both follow the 📍 Маршруты pattern: opening a screen
// fetches the router's answer and caches it per chat, and every button after
// that carries only an index into that cached snapshot.

const (
	adaptiveListPageSize = 8  // entries per page of the redirect list
	adaptiveExclPageSize = 10 // entries per page of the exclusions screen
)

// adaptiveListEntry is one parsed row of the router's adrt_list answer.
type adaptiveListEntry struct {
	addr, tier, reason, client, proto, host string
	leftSec                                 int // -1: never expires
	dport                                   int
}

// adaptiveListData is the parsed answer: the counts and counters of the
// header lines, then the entries in the router's display order.
type adaptiveListData struct {
	total, probation, confirmed, block, l7sni, unknown int
	hour, day, all                                     adaptiveroute.Counts
	since                                              time.Time
	excluded                                           int
	entries                                            []adaptiveListEntry
}

// adaptiveMenu is what the bot last showed one chat on these screens.
type adaptiveMenu struct {
	routerID string
	list     adaptiveListData
	hasList  bool
	excluded []string
	exclSkip int // lines of the list file the router could not parse
	hasExcl  bool
}

func parseCounts(f []string) adaptiveroute.Counts {
	var c adaptiveroute.Counts
	for i := range c {
		if i < len(f) {
			c[i] = atoiOr(f[i], 0)
		}
	}
	return c
}

// parseAdaptiveList reads the router's adrt_list answer (see
// formatAdaptiveList). Unknown header lines and short rows are skipped: the
// router and the control server are updated separately, and a newer router's
// extra header must not break an older bot.
func parseAdaptiveList(out string) adaptiveListData {
	var d adaptiveListData
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if strings.HasPrefix(f[0], "#") {
			switch f[0] {
			case "#n":
				if len(f) >= 7 {
					d.total, d.probation, d.confirmed = atoiOr(f[1], 0), atoiOr(f[2], 0), atoiOr(f[3], 0)
					d.block, d.l7sni, d.unknown = atoiOr(f[4], 0), atoiOr(f[5], 0), atoiOr(f[6], 0)
				}
			case "#hour":
				d.hour = parseCounts(f[1:])
			case "#day":
				d.day = parseCounts(f[1:])
			case "#total":
				d.all = parseCounts(f[1:])
			case "#since":
				if len(f) >= 2 {
					if n := atoiOr(f[1], 0); n > 0 {
						d.since = time.Unix(int64(n), 0)
					}
				}
			case "#excl":
				if len(f) >= 2 {
					d.excluded = atoiOr(f[1], 0)
				}
			}
			continue
		}
		if len(f) < 8 {
			continue
		}
		d.entries = append(d.entries, adaptiveListEntry{
			addr: f[0], tier: f[1], leftSec: atoiOr(f[2], -1), reason: f[3],
			client: f[4], proto: f[5], dport: atoiOr(f[6], 0), host: f[7],
		})
	}
	return d
}

// parseAdaptiveExcluded reads adrt_exlist: the entries, and how many lines of
// the file the router could not make sense of.
func parseAdaptiveExcluded(out string) (entries []string, skipped int) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case line == "":
		case strings.HasPrefix(line, "#"):
			if f := strings.Split(line, "\t"); f[0] == "#excl" && len(f) >= 3 {
				skipped = atoiOr(f[2], 0)
			}
		default:
			entries = append(entries, line)
		}
	}
	return entries, skipped
}

// --- per-chat snapshot ---

func (b *TelegramBot) adaptiveMenuFor(chatID int64, routerID string) adaptiveMenu {
	b.adaptiveMenuMu.Lock()
	defer b.adaptiveMenuMu.Unlock()
	m := b.adaptiveMenus[chatID]
	if m.routerID != routerID {
		return adaptiveMenu{routerID: routerID}
	}
	return m
}

func (b *TelegramBot) storeAdaptiveMenu(chatID int64, m adaptiveMenu) {
	b.adaptiveMenuMu.Lock()
	defer b.adaptiveMenuMu.Unlock()
	if b.adaptiveMenus == nil {
		b.adaptiveMenus = make(map[int64]adaptiveMenu)
	}
	b.adaptiveMenus[chatID] = m
}

func (b *TelegramBot) setAdaptiveList(chatID int64, routerID string, d adaptiveListData) {
	m := b.adaptiveMenuFor(chatID, routerID)
	m.list, m.hasList = d, true
	b.storeAdaptiveMenu(chatID, m)
}

func (b *TelegramBot) setAdaptiveExcluded(chatID int64, routerID string, entries []string, skipped int) {
	m := b.adaptiveMenuFor(chatID, routerID)
	m.excluded, m.exclSkip, m.hasExcl = entries, skipped, true
	b.storeAdaptiveMenu(chatID, m)
}

// --- rendering ---

func adaptivePages(n, size int) int {
	if n <= 0 {
		return 1
	}
	return (n + size - 1) / size
}

// pageBounds clamps page into range and returns it with the entry range it
// covers.
func pageBounds(n, size, page int) (p, from, to int) {
	pages := adaptivePages(n, size)
	if page >= pages {
		page = pages - 1
	}
	if page < 0 {
		page = 0
	}
	from = page * size
	to = from + size
	if to > n {
		to = n
	}
	return page, from, to
}

func adaptiveBackKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔄 Ещё раз", CallbackData: "adxO:" + id}, {Text: "⬅️ Назад", CallbackData: "adrt:" + id}},
	}}
}

func entryClient(e adaptiveListEntry) string {
	return adaptiveroute.Note{Client: e.client, Proto: e.proto, DPort: uint(e.dport)}.Flow()
}

// adaptiveEntryLine is one entry of the list page.
func adaptiveEntryLine(n int, e adaptiveListEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d. %s %s", n, adaptiveroute.TierIcon(e.tier), e.addr)
	if e.leftSec >= 0 {
		b.WriteString(" · ещё " + adaptiveroute.FormatLeft(time.Duration(e.leftSec)*time.Second))
	}
	switch {
	case e.host != "":
		b.WriteString(" · " + e.host)
	case e.reason != "":
		b.WriteString(" · " + adaptiveroute.ReasonLabel(e.reason))
	}
	if c := entryClient(e); c != "" {
		b.WriteString(" · " + c)
	}
	return b.String()
}

// adaptiveListScreenText renders one page of the redirect list. head, when
// set, is the router's answer to the button that led here ("🚫 Исключено …").
func adaptiveListScreenText(id string, d adaptiveListData, page int, head string) string {
	var b strings.Builder
	if head != "" {
		b.WriteString(head + "\n\n")
	}
	fmt.Fprintf(&b, "🎯 Что перенаправлено — %s\n", id)
	t := adaptiveroute.Tally{Total: d.total, Probation: d.probation, Confirmed: d.confirmed, Block: d.block, L7SNI: d.l7sni, Unknown: d.unknown}
	st := adaptiveroute.StatsSnapshot{Since: d.since, Total: d.all, Hour: d.hour, Day: d.day}
	b.WriteString(adaptiveActivityText(t, st, d.excluded))
	b.WriteString("\n\n🧪 проба · ✅ подтверждён · 🌐 подсеть · 🔍 по имени · ❔ без пометки\n")

	if len(d.entries) == 0 {
		b.WriteString("\nСписок пуст — сейчас ничего не перенаправляется.")
		return b.String()
	}
	_, from, to := pageBounds(len(d.entries), adaptiveListPageSize, page)
	of := fmt.Sprintf("%d", len(d.entries))
	if d.total > len(d.entries) {
		of = fmt.Sprintf("%d (показаны первые %d)", d.total, len(d.entries))
	}
	fmt.Fprintf(&b, "\nАдреса %d–%d из %s:", from+1, to, of)
	for i := from; i < to; i++ {
		b.WriteString("\n" + adaptiveEntryLine(i+1, d.entries[i]))
	}
	b.WriteString("\n\nНажми номер — откроется карточка адреса с кнопкой «Исключить».")
	return b.String()
}

func adaptiveListKB(id string, d adaptiveListData, page int) inlineKeyboard {
	var rows [][]inlineButton
	page, from, to := pageBounds(len(d.entries), adaptiveListPageSize, page)
	var nums []inlineButton
	for i := from; i < to; i++ {
		nums = append(nums, inlineButton{Text: fmt.Sprintf("%d", i+1), CallbackData: fmt.Sprintf("adxI:%s:%d", id, i)})
		if len(nums) == 4 {
			rows, nums = append(rows, nums), nil
		}
	}
	if len(nums) > 0 {
		rows = append(rows, nums)
	}
	if pages := adaptivePages(len(d.entries), adaptiveListPageSize); pages > 1 {
		var nav []inlineButton
		if page > 0 {
			nav = append(nav, inlineButton{Text: "◀️", CallbackData: fmt.Sprintf("adxL:%s:%d", id, page-1)})
		}
		nav = append(nav, inlineButton{Text: fmt.Sprintf("%d/%d", page+1, pages), CallbackData: fmt.Sprintf("adxL:%s:%d", id, page)})
		if page < pages-1 {
			nav = append(nav, inlineButton{Text: "▶️", CallbackData: fmt.Sprintf("adxL:%s:%d", id, page+1)})
		}
		rows = append(rows, nav)
	}
	rows = append(rows,
		[]inlineButton{
			{Text: fmt.Sprintf("🚫 Исключения (%d)", d.excluded), CallbackData: "adxX:" + id},
			{Text: "🔄 Обновить", CallbackData: "adxO:" + id},
		},
		[]inlineButton{{Text: "⬅️ Назад", CallbackData: "adrt:" + id}},
	)
	return inlineKeyboard{InlineKeyboard: rows}
}

// adaptiveTierNote explains what a tier means, for the entry's own card.
func adaptiveTierNote(tier string) string {
	switch tier {
	case adaptiveroute.TierProbation:
		return "Проба: адрес на минуту пущен в туннель, пока смотрим, поможет ли это. Не подтвердится — исчезнет из списка сам."
	case adaptiveroute.TierConfirmed:
		return "Подтверждён: через туннель реально заработало, поэтому адрес держится в списке часами."
	case adaptiveroute.TierBlock:
		return "Подсеть: в ней набралось несколько подтверждённых адресов, и её забрали в туннель целиком."
	case adaptiveroute.TierL7SNI:
		return "По имени: домен из твоих списков маршрутов, увиденный в TLS/HTTP."
	}
	return "Без пометки: демон не видел, как этот адрес попал в список (перезапуск демона или добавлено не им)."
}

func adaptiveItemText(e adaptiveListEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "🎯 %s\n\n%s %s", e.addr, adaptiveroute.TierIcon(e.tier), adaptiveroute.TierLabel(e.tier))
	if e.leftSec >= 0 {
		b.WriteString("\nОсталось в списке: " + adaptiveroute.FormatLeft(time.Duration(e.leftSec)*time.Second))
	} else {
		b.WriteString("\nСрока нет: пока не уберёт демон")
	}
	if e.reason != "" {
		b.WriteString("\nЧто заметил: " + adaptiveroute.ReasonLabel(e.reason))
	}
	if e.host != "" {
		b.WriteString("\nИмя: " + e.host)
	}
	if c := entryClient(e); c != "" {
		b.WriteString("\nКто: " + c)
	}
	b.WriteString("\n\n" + adaptiveTierNote(e.tier))
	b.WriteString("\n\nЕсли этот адрес не должен идти через туннель — исключи его. Он больше не попадёт в перенаправление " +
		"ни по классификатору, ни по l7sni, а открытые соединения к нему оборвутся и переподключатся напрямую. " +
		"Вернуть можно на экране 🚫 Исключения.")
	return b.String()
}

// adaptiveNet24 is the /24 around a bare IPv4 address.
func adaptiveNet24(addr string) (string, bool) {
	if strings.Contains(addr, "/") {
		return "", false
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2]), true
}

func adaptiveItemKB(id string, idx int, e adaptiveListEntry) inlineKeyboard {
	label := "🚫 Исключить адрес"
	if strings.Contains(e.addr, "/") {
		label = "🚫 Исключить подсеть"
	}
	rows := [][]inlineButton{{{Text: label, CallbackData: fmt.Sprintf("adxE:%s:%d:a", id, idx)}}}
	if n24, ok := adaptiveNet24(e.addr); ok {
		rows = append(rows, []inlineButton{{Text: "🚫 Исключить всю " + n24, CallbackData: fmt.Sprintf("adxE:%s:%d:n", id, idx)}})
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ К списку", CallbackData: "adxO:" + id}})
	return inlineKeyboard{InlineKeyboard: rows}
}

func adaptiveExcludedText(id string, entries []string, skipped, page int, head string) string {
	var b strings.Builder
	if head != "" {
		b.WriteString(head + "\n\n")
	}
	fmt.Fprintf(&b, "🚫 Исключения — %s\n\n", id)
	b.WriteString("Эти адреса и сети адаптивная маршрутизация не перенаправляет никогда: ни по классификатору, ни по l7sni.")
	if skipped > 0 {
		fmt.Fprintf(&b, "\n⚠️ В файле adaptive-exclude.txt строк, которые не удалось разобрать: %d — они игнорируются.", skipped)
	}
	if len(entries) == 0 {
		b.WriteString("\n\nСписок пуст. Добавить адрес можно из карточки на экране «Что перенаправлено» " +
			"или командой `transport adaptive exclude <ip|сеть>`.")
		return b.String()
	}
	_, from, to := pageBounds(len(entries), adaptiveExclPageSize, page)
	fmt.Fprintf(&b, "\n\nЗаписи %d–%d из %d:", from+1, to, len(entries))
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "\n%d. %s", i+1, entries[i])
	}
	b.WriteString("\n\nНажми номер — запись вернётся в игру: классификатор снова сможет ловить этот адрес.")
	return b.String()
}

func adaptiveExcludedKB(id string, entries []string, page int) inlineKeyboard {
	var rows [][]inlineButton
	page, from, to := pageBounds(len(entries), adaptiveExclPageSize, page)
	var nums []inlineButton
	for i := from; i < to; i++ {
		nums = append(nums, inlineButton{Text: fmt.Sprintf("↩️ %d", i+1), CallbackData: fmt.Sprintf("adxR:%s:%d", id, i)})
		if len(nums) == 5 {
			rows, nums = append(rows, nums), nil
		}
	}
	if len(nums) > 0 {
		rows = append(rows, nums)
	}
	if pages := adaptivePages(len(entries), adaptiveExclPageSize); pages > 1 {
		var nav []inlineButton
		if page > 0 {
			nav = append(nav, inlineButton{Text: "◀️", CallbackData: fmt.Sprintf("adxP:%s:%d", id, page-1)})
		}
		nav = append(nav, inlineButton{Text: fmt.Sprintf("%d/%d", page+1, pages), CallbackData: fmt.Sprintf("adxP:%s:%d", id, page)})
		if page < pages-1 {
			nav = append(nav, inlineButton{Text: "▶️", CallbackData: fmt.Sprintf("adxP:%s:%d", id, page+1)})
		}
		rows = append(rows, nav)
	}
	rows = append(rows,
		[]inlineButton{{Text: "📋 Что перенаправлено", CallbackData: "adxO:" + id}},
		[]inlineButton{{Text: "⬅️ Назад", CallbackData: "adrt:" + id}},
	)
	return inlineKeyboard{InlineKeyboard: rows}
}

// --- flows ---

// showAdaptiveList fetches the redirect list and shows its first page in
// place of message msgID. head, when set, goes on top.
func (b *TelegramBot) showAdaptiveList(ctx context.Context, chatID int64, msgID int, id, head string) {
	title := "🎯 Что перенаправлено — " + id
	cmdID, err := b.Store.Enqueue(id, ActionAdaptiveRouteList, nil)
	if err != nil {
		b.editMessageText(ctx, chatID, msgID, title+"\n\nне поставлено в очередь: "+err.Error(), adaptiveBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, title+"\n\n⏳ загружаю…", adaptiveBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		switch {
		case !ok:
			b.editMessageText(ctx, chatID, msgID, withHead(head, title+"\n\n⌛ роутер не ответил"), adaptiveBackKB(id))
		case res.Err != "":
			b.editMessageText(ctx, chatID, msgID, withHead(head, title+"\n\n⚠️ "+res.Err), adaptiveBackKB(id))
		default:
			d := parseAdaptiveList(res.Output)
			b.setAdaptiveList(chatID, id, d)
			b.editMessageText(ctx, chatID, msgID, adaptiveListScreenText(id, d, 0, head), adaptiveListKB(id, d, 0))
		}
	}()
}

// showAdaptiveExcluded is showAdaptiveList for the exclusions screen.
func (b *TelegramBot) showAdaptiveExcluded(ctx context.Context, chatID int64, msgID int, id, head string) {
	title := "🚫 Исключения — " + id
	cmdID, err := b.Store.Enqueue(id, ActionAdaptiveRouteExcluded, nil)
	if err != nil {
		b.editMessageText(ctx, chatID, msgID, title+"\n\nне поставлено в очередь: "+err.Error(), adaptiveBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, title+"\n\n⏳ загружаю…", adaptiveBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		switch {
		case !ok:
			b.editMessageText(ctx, chatID, msgID, withHead(head, title+"\n\n⌛ роутер не ответил"), adaptiveBackKB(id))
		case res.Err != "":
			b.editMessageText(ctx, chatID, msgID, withHead(head, title+"\n\n⚠️ "+res.Err), adaptiveBackKB(id))
		default:
			entries, skipped := parseAdaptiveExcluded(res.Output)
			b.setAdaptiveExcluded(chatID, id, entries, skipped)
			b.editMessageText(ctx, chatID, msgID, adaptiveExcludedText(id, entries, skipped, 0, head), adaptiveExcludedKB(id, entries, 0))
		}
	}()
}

func withHead(head, text string) string {
	if head == "" {
		return text
	}
	return head + "\n\n" + text
}

// adaptiveMutate runs one change from a button -- exclude an entry, return
// one -- and then shows the screen it came from again, fresh, with the
// router's answer on top. If the change itself failed there is nothing new to
// show, only the reason.
func (b *TelegramBot) adaptiveMutate(ctx context.Context, chatID int64, msgID int, id, action string, args []string,
	refresh func(ctx context.Context, chatID int64, msgID int, id, head string)) {
	cmdID, err := b.Store.Enqueue(id, action, args)
	if err != nil {
		b.editMessageText(ctx, chatID, msgID, "не поставлено в очередь: "+err.Error(), adaptiveBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "🎯 Адаптивная маршрутизация "+id+"\n\n⏳ …", adaptiveBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		switch {
		case !ok:
			b.editMessageText(ctx, chatID, msgID, "⌛ роутер не ответил — изменение выполнится при следующем poll", adaptiveBackKB(id))
		case res.Err != "":
			b.editMessageText(ctx, chatID, msgID, "⚠️ "+res.Err, adaptiveBackKB(id))
		default:
			head := strings.TrimSpace(res.Output)
			if head == "" {
				head = "✅ готово"
			}
			refresh(ctx, chatID, msgID, id, head)
		}
	}()
}

// handleAdaptiveCallback routes every adx* button of the two screens.
// Returns false if data is not one of ours.
func (b *TelegramBot) handleAdaptiveCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	stale := func(id string) {
		b.editCB(ctx, cb, "список устарел — открой его заново", adaptiveBackKB(id))
	}
	switch {
	case strings.HasPrefix(data, "adxO:"): // open / refresh the redirect list
		id := strings.TrimPrefix(data, "adxO:")
		if !b.Store.HasRouter(id) {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return true
		}
		b.showAdaptiveList(ctx, chatID, msgID, id, "")
	case strings.HasPrefix(data, "adxL:"): // a page of the cached list
		id, page, ok := parseRouteRef(data, "adxL:")
		if !ok {
			return true
		}
		m := b.adaptiveMenuFor(chatID, id)
		if !m.hasList {
			stale(id)
			return true
		}
		b.editCB(ctx, cb, adaptiveListScreenText(id, m.list, page, ""), adaptiveListKB(id, m.list, page))
	case strings.HasPrefix(data, "adxI:"): // one entry's card
		id, idx, ok := parseRouteRef(data, "adxI:")
		if !ok {
			return true
		}
		m := b.adaptiveMenuFor(chatID, id)
		if !m.hasList || idx < 0 || idx >= len(m.list.entries) {
			stale(id)
			return true
		}
		e := m.list.entries[idx]
		b.editCB(ctx, cb, adaptiveItemText(e), adaptiveItemKB(id, idx, e))
	case strings.HasPrefix(data, "adxE:"): // exclude an entry
		parts := strings.Split(strings.TrimPrefix(data, "adxE:"), ":")
		if len(parts) != 3 {
			b.editCB(ctx, cb, "плохая кнопка", mainMenuKB())
			return true
		}
		id, mode := parts[0], parts[2]
		idx := atoiOr(parts[1], -1)
		m := b.adaptiveMenuFor(chatID, id)
		if !m.hasList || idx < 0 || idx >= len(m.list.entries) {
			stale(id)
			return true
		}
		target := m.list.entries[idx].addr
		if mode == "n" {
			n24, ok := adaptiveNet24(target)
			if !ok {
				b.editCB(ctx, cb, "для этой записи /24 не применима", adaptiveBackKB(id))
				return true
			}
			target = n24
		}
		b.adaptiveMutate(ctx, chatID, msgID, id, ActionAdaptiveRouteExclude, []string{target}, b.showAdaptiveList)
	case strings.HasPrefix(data, "adxX:"): // open the exclusions screen
		id := strings.TrimPrefix(data, "adxX:")
		if !b.Store.HasRouter(id) {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return true
		}
		b.showAdaptiveExcluded(ctx, chatID, msgID, id, "")
	case strings.HasPrefix(data, "adxP:"): // a page of the cached exclusions
		id, page, ok := parseRouteRef(data, "adxP:")
		if !ok {
			return true
		}
		m := b.adaptiveMenuFor(chatID, id)
		if !m.hasExcl {
			stale(id)
			return true
		}
		b.editCB(ctx, cb, adaptiveExcludedText(id, m.excluded, m.exclSkip, page, ""), adaptiveExcludedKB(id, m.excluded, page))
	case strings.HasPrefix(data, "adxR:"): // return an entry
		id, idx, ok := parseRouteRef(data, "adxR:")
		if !ok {
			return true
		}
		m := b.adaptiveMenuFor(chatID, id)
		if !m.hasExcl || idx < 0 || idx >= len(m.excluded) {
			stale(id)
			return true
		}
		b.adaptiveMutate(ctx, chatID, msgID, id, ActionAdaptiveRouteInclude, []string{m.excluded[idx]}, b.showAdaptiveExcluded)
	default:
		return false
	}
	return true
}
