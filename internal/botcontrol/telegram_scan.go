package botcontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
)

// The 🔎 flow: once domains are added to a route list, offer to read their
// pages through the tunnel and find the other domains those pages load
// pictures, scripts and logins from. A blocked site added by its own name
// otherwise opens half-empty when those are blocked too and in no list.
//
// The router does the scanning (routes_scan, internal/depscan); the bot
// keeps the answer per session -- callback_data holds 64 bytes, so a
// button carries a short token and an index, never a host name -- and adds
// whatever the operator ticks with the ordinary routes_add. Nothing is
// added without a tap.

// DefaultScanTimeout is how long the bot waits for a scan: the agent picks
// a command up on its next poll (up to 5 s), a scan may run its whole
// 35 s budget, and the answer is posted after that.
const DefaultScanTimeout = 55 * time.Second

const (
	scanPageSize    = 10
	scanSessionTTL  = 2 * time.Hour
	scanMaxSessions = 40
)

type scanSession struct {
	routerID string
	chatID   int64
	msgID    int
	list     string   // the list the domains went into: the ticked hosts join it
	seeds    []string // the domains that were added
	created  time.Time

	busy      bool // a scan is running
	res       *depscan.Result
	sel       map[string]bool // ticked host names
	page      int
	showMaybe bool
}

func (b *TelegramBot) scanTimeout() time.Duration {
	if b.ScanTimeout > 0 {
		return b.ScanTimeout
	}
	return DefaultScanTimeout
}

func newScanToken() string {
	var raw [4]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// putScan stores a session under a fresh token, dropping stale ones.
func (b *TelegramBot) putScan(s *scanSession) string {
	b.scanMu.Lock()
	defer b.scanMu.Unlock()
	if b.scans == nil {
		b.scans = map[string]*scanSession{}
	}
	now := time.Now()
	for tok, old := range b.scans {
		if now.Sub(old.created) > scanSessionTTL {
			delete(b.scans, tok)
		}
	}
	for len(b.scans) >= scanMaxSessions {
		var oldestTok string
		var oldest time.Time
		for tok, old := range b.scans {
			if oldestTok == "" || old.created.Before(oldest) {
				oldestTok, oldest = tok, old.created
			}
		}
		delete(b.scans, oldestTok)
	}
	tok := newScanToken()
	s.created = now
	b.scans[tok] = s
	return tok
}

// withScan runs fn on the session behind tok while holding the lock; false
// when there is no such session for this chat (expired, server restarted,
// closed).
func (b *TelegramBot) withScan(tok string, chatID int64, fn func(*scanSession)) bool {
	b.scanMu.Lock()
	defer b.scanMu.Unlock()
	s, ok := b.scans[tok]
	if !ok || s.chatID != chatID {
		return false
	}
	fn(s)
	return true
}

func (b *TelegramBot) dropScan(tok string) {
	b.scanMu.Lock()
	delete(b.scans, tok)
	b.scanMu.Unlock()
}

// offerScan sends text (the "✅ added" message) with a button offering the
// scan, when at least one of the added entries is a domain a page can be
// read from; otherwise it just sends text.
func (b *TelegramBot) offerScan(ctx context.Context, chatID int64, routerID, list string, entries []string, text string) {
	seeds, _ := depscan.ParseSeeds(entries...)
	if len(seeds) == 0 {
		b.sendMessage(ctx, chatID, text)
		return
	}
	tok := b.putScan(&scanSession{routerID: routerID, chatID: chatID, list: list, seeds: seeds})
	who := strings.Join(seeds, ", ")
	if total := depscan.CountSeeds(entries...); total > len(seeds) {
		who += fmt.Sprintf(" (первые %d из %d; остальные добавь отдельно)", len(seeds), total)
	}
	text += "\n\n🔎 Страница сайта часто грузит картинки, скрипты и вход с других доменов; " +
		"если те тоже закрыты, а в списке их нет, сайт откроется не полностью. " +
		"Прочитать через туннель " + who + " и найти такие домены? Займёт до минуты."
	kb := inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔎 Найти связанные домены", CallbackData: "rsq:" + tok}},
		{{Text: "Не надо", CallbackData: "rsx:" + tok}},
	}}
	if id := b.sendMessageKB(ctx, chatID, text, kb); id != 0 {
		b.withScan(tok, chatID, func(s *scanSession) { s.msgID = id })
	}
}

// handleScanCallback handles every rs* callback. false when data is not one.
func (b *TelegramBot) handleScanCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	verb, rest, ok := strings.Cut(data, ":")
	if !ok {
		return false
	}
	switch verb {
	case "rsq", "rsx", "rst", "rsp", "rsm", "rsa":
	default:
		return false
	}
	tok, arg, _ := strings.Cut(rest, ":")
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID

	var text string
	var kb inlineKeyboard
	found := b.withScan(tok, chatID, func(s *scanSession) { s.msgID = msgID })
	if !found {
		b.editMessageText(ctx, chatID, msgID,
			"Результаты поиска устарели (сервер бота перезапускался или прошло много времени). "+
				"Добавь домен ещё раз — предложение найти связанные появится снова.", backKB("menu"))
		return true
	}

	switch verb {
	case "rsx":
		b.dropScan(tok)
		b.editMessageText(ctx, chatID, msgID, "Ок, без поиска связанных доменов.", inlineKeyboard{})
		return true
	case "rsq":
		b.scanStart(ctx, chatID, msgID, tok)
		return true
	case "rst":
		idx, _ := strconv.Atoi(arg)
		b.withScan(tok, chatID, func(s *scanSession) {
			if s.res == nil {
				return // no result yet: nothing to tick
			}
			if view := s.view(); idx >= 0 && idx < len(view) {
				n := view[idx].Name
				s.sel[n] = !s.sel[n]
			}
			text, kb = scanScreen(tok, s, "")
		})
	case "rsp":
		p, _ := strconv.Atoi(arg)
		b.withScan(tok, chatID, func(s *scanSession) {
			if s.res == nil {
				return
			}
			if p >= 0 && p*scanPageSize < len(s.view()) {
				s.page = p
			}
			text, kb = scanScreen(tok, s, "")
		})
	case "rsm":
		b.withScan(tok, chatID, func(s *scanSession) {
			if s.res == nil {
				return
			}
			s.showMaybe = !s.showMaybe
			if !s.showMaybe { // hidden hosts are no longer ticked
				for _, h := range s.res.Hosts {
					if h.Class == depscan.ClassMaybe {
						delete(s.sel, h.Name)
					}
				}
			}
			s.page = 0
			text, kb = scanScreen(tok, s, "")
		})
	case "rsa":
		b.scanAdd(ctx, chatID, msgID, tok)
		return true
	}
	if text != "" {
		b.editMessageText(ctx, chatID, msgID, text, kb)
	}
	return true
}

// scanStart enqueues routes_scan and, when the answer arrives, replaces the
// offer with the result screen.
func (b *TelegramBot) scanStart(ctx context.Context, chatID int64, msgID int, tok string) {
	var routerID string
	var seeds []string
	var already bool
	b.withScan(tok, chatID, func(s *scanSession) {
		already = s.busy
		s.busy = true
		routerID, seeds = s.routerID, append([]string(nil), s.seeds...)
	})
	if already {
		return // a scan for this session is running; the screen will update
	}
	fail := func(msg string) {
		b.withScan(tok, chatID, func(s *scanSession) { s.busy = false })
		b.editMessageText(ctx, chatID, msgID, msg, inlineKeyboard{InlineKeyboard: [][]inlineButton{
			{{Text: "🔄 Ещё раз", CallbackData: "rsq:" + tok}},
			{{Text: "✖ Закрыть", CallbackData: "rsx:" + tok}},
		}})
	}
	cmdID, err := b.Store.Enqueue(routerID, ActionRoutesScan, seeds)
	if err != nil {
		fail("🔎 не поставлено в очередь: " + err.Error())
		return
	}
	b.editMessageText(ctx, chatID, msgID,
		"🔎 Читаю "+strings.Join(seeds, ", ")+" через туннель и проверяю найденные домены — напрямую и через туннель…\n⏳ до минуты", inlineKeyboard{})
	go func() {
		res, ok := b.Store.AwaitResult(ctx, routerID, cmdID, b.scanTimeout())
		switch {
		case !ok:
			fail("🔎 ⌛ роутер не ответил вовремя. " + queuedNote(b.Store.LastPollAt(routerID)))
			return
		case res.Err != "":
			msg := res.Err
			if strings.Contains(msg, "unknown action") {
				msg = "эта версия keenetic-xray на роутере ещё не умеет искать связанные домены — обнови её на карточке роутера"
			}
			fail("🔎 ⚠️ " + msg)
			return
		}
		r, perr := depscan.ParseTSV(res.Output)
		if perr != nil {
			fail("🔎 ⚠️ не разобрал ответ роутера: " + perr.Error())
			return
		}
		var text string
		var kb inlineKeyboard
		if !b.withScan(tok, chatID, func(s *scanSession) {
			s.busy = false
			s.res = r
			s.page, s.showMaybe = 0, false
			s.sel = map[string]bool{}
			for _, h := range r.Hosts {
				if h.Class == depscan.ClassNeed {
					s.sel[h.Name] = true // what the scan recommends starts ticked
				}
			}
			text, kb = scanScreen(tok, s, "")
		}) {
			return // closed while it ran
		}
		b.editMessageText(ctx, chatID, msgID, text, kb)
	}()
}

// scanAdd adds the ticked hosts to the list with the ordinary routes_add.
func (b *TelegramBot) scanAdd(ctx context.Context, chatID int64, msgID int, tok string) {
	var routerID, list string
	var hosts []string
	var text string
	var kb inlineKeyboard
	b.withScan(tok, chatID, func(s *scanSession) {
		routerID, list = s.routerID, s.list
		if s.res == nil {
			return
		}
		for _, h := range s.res.Hosts { // result order, not map order
			if s.sel[h.Name] {
				hosts = append(hosts, h.Name)
			}
		}
		if len(hosts) == 0 {
			text, kb = scanScreen(tok, s, "Ничего не отмечено — отметь номера кнопками или закрой.")
		}
	})
	if routerID == "" {
		return
	}
	if len(hosts) == 0 {
		b.editMessageText(ctx, chatID, msgID, text, kb)
		return
	}
	b.editMessageText(ctx, chatID, msgID, fmt.Sprintf("➕ Добавляю в список %q: %d доменов…", list, len(hosts)), inlineKeyboard{})
	go func() {
		out, answered, errText := b.enqueueAndWait(ctx, routerID, ActionRoutesAdd, []string{list, strings.Join(hosts, " ")})
		msg := b.stepResult(routerID, answered, errText, "✅ "+strings.TrimSpace(out))
		if answered && errText == "" {
			msg += "\n\nРоутер узнаёт адреса из DNS-ответов, поэтому первый заход на сайт может пойти напрямую. " +
				"Если картинки не появились — подожди пару минут или очисти DNS-кэш на устройстве."
			b.dropScan(tok)
		}
		b.editMessageText(ctx, chatID, msgID, msg, backKB("rtm:"+routerID))
	}()
}

// view is the hosts the operator can tick right now: the recommended ones,
// and the "maybe" ones once they are shown.
func (s *scanSession) view() []depscan.Host {
	if s.res == nil {
		return nil
	}
	var out []depscan.Host
	for _, h := range s.res.Hosts {
		if h.Class == depscan.ClassNeed || (s.showMaybe && h.Class == depscan.ClassMaybe) {
			out = append(out, h)
		}
	}
	return out
}

// scanScreen draws the result: text for people, numbered buttons to tick.
// Host names live in the text; a button holds only its number, so a long
// name can never be cut off or break the 64-byte callback limit.
func scanScreen(tok string, s *scanSession, note string) (string, inlineKeyboard) {
	r := s.res
	var b strings.Builder
	for _, p := range r.Pages {
		if p.Status == 0 {
			fmt.Fprintf(&b, "🔎 %s — ⚠️ %s\n", p.Seed, p.Note)
			continue
		}
		fmt.Fprintf(&b, "🔎 %s", p.Seed)
		if p.FinalHost != "" && p.FinalHost != p.Seed {
			fmt.Fprintf(&b, " → %s", p.FinalHost)
		}
		fmt.Fprintf(&b, " — страница открылась через туннель (код %d)\n", p.Status)
		if p.Direct.OK {
			b.WriteString("   Сам сайт открывается и напрямую: в туннель его нужно, только если он режет по адресу страны.\n")
		}
		if p.Note != "" {
			fmt.Fprintf(&b, "   ⚠️ %s\n", p.Note)
		}
	}

	view := s.view()
	needN, maybeN := r.Count(depscan.ClassNeed), r.Count(depscan.ClassMaybe)
	switch {
	case needN == 0 && maybeN == 0:
		b.WriteString("\nДобавлять нечего: связанных доменов, которым нужен туннель, не нашлось.\n")
	case needN == 0:
		b.WriteString("\nУверенно нужных нет, но есть домены, которые могут понадобиться.\n")
	default:
		fmt.Fprintf(&b, "\nНужны (%d) — напрямую не открываются, через туннель открываются:\n", needN)
	}
	start := s.page * scanPageSize
	end := min(start+scanPageSize, len(view))
	for i := start; i < end; i++ {
		h := view[i]
		mark := "☐"
		if s.sel[h.Name] {
			mark = "☑"
		}
		tag := ""
		if h.Class == depscan.ClassMaybe {
			tag = "❔ "
		}
		fmt.Fprintf(&b, "%s %d. %s%s — %s\n", mark, i+1, tag, h.Name, h.Describe())
	}
	if maybeN > 0 && !s.showMaybe {
		fmt.Fprintf(&b, "\nВозможно нужны: %d (не отмечены: найдены только в политике сайта или в скриптах, либо это аналитика) — «👁 Показать».\n", maybeN)
	}
	if n := r.Count(depscan.ClassDirect); n > 0 {
		fmt.Fprintf(&b, "\nОткрываются и напрямую, в список не нужны: %d", n)
		var names []string
		for _, h := range r.Hosts {
			if h.Class == depscan.ClassDirect && len(names) < 6 {
				names = append(names, h.Name)
			}
		}
		fmt.Fprintf(&b, " — %s", strings.Join(names, ", "))
		if n > len(names) {
			b.WriteString(", …")
		}
		b.WriteByte('\n')
	}
	if n := r.Count(depscan.ClassDead); n > 0 {
		fmt.Fprintf(&b, "Не открылись ни так, ни так: %d\n", n)
	}
	if n := r.Count(depscan.ClassCovered); n > 0 {
		fmt.Fprintf(&b, "Уже в списках: %d\n", n)
	}
	if r.More > 0 {
		fmt.Fprintf(&b, "Ещё %d хостов не проверял (лимит на одно сканирование).\n", r.More)
	}
	if note != "" {
		b.WriteString("\n" + note + "\n")
	}

	var rows [][]inlineButton
	var row []inlineButton
	for i := start; i < end; i++ {
		mark := "☐"
		if s.sel[view[i].Name] {
			mark = "☑"
		}
		row = append(row, inlineButton{Text: fmt.Sprintf("%s %d", mark, i+1), CallbackData: fmt.Sprintf("rst:%s:%d", tok, i)})
		if len(row) == 5 {
			rows = append(rows, row)
			row = nil
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if pages := (len(view) + scanPageSize - 1) / scanPageSize; pages > 1 {
		var nav []inlineButton
		if s.page > 0 {
			nav = append(nav, inlineButton{Text: "◀", CallbackData: fmt.Sprintf("rsp:%s:%d", tok, s.page-1)})
		}
		nav = append(nav, inlineButton{Text: fmt.Sprintf("%d/%d", s.page+1, pages), CallbackData: fmt.Sprintf("rsp:%s:%d", tok, s.page)})
		if s.page < pages-1 {
			nav = append(nav, inlineButton{Text: "▶", CallbackData: fmt.Sprintf("rsp:%s:%d", tok, s.page+1)})
		}
		rows = append(rows, nav)
	}
	if len(view) > 0 {
		ticked := 0
		for _, on := range s.sel {
			if on {
				ticked++
			}
		}
		rows = append(rows, []inlineButton{{Text: fmt.Sprintf("✅ Добавить выбранные (%d)", ticked), CallbackData: "rsa:" + tok}})
	}
	if maybeN > 0 {
		label := fmt.Sprintf("👁 Показать возможные (%d)", maybeN)
		if s.showMaybe {
			label = "🙈 Скрыть возможные"
		}
		rows = append(rows, []inlineButton{{Text: label, CallbackData: "rsm:" + tok}})
	}
	rows = append(rows, []inlineButton{{Text: "✖ Закрыть", CallbackData: "rsx:" + tok}})
	return b.String(), inlineKeyboard{InlineKeyboard: rows}
}
