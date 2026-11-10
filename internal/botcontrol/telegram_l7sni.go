package botcontrol

import (
	"context"
	"strings"
	"sync"
)

// The 🔍 L7 SNI и QUIC screen: a child of the adaptive-routing screen (the L7
// capture feeds the same redirect set), with the QUIC capture as a child of
// that -- off / observe / act -- and the capture's counters one tap away. Like
// the adaptive screen it is static text and buttons; the state of a mode is
// whatever the router answered to the last button, or 📊 Показать on the
// adaptive screen.
//
// Callback data: "adxQ:<router>" opens it, "adxQ:<router>:<name>" runs one of
// l7sniScreenNames and shows it again with the router's answer on top, and
// "adxS:<router>" is the counters. They share the "adx" prefix of the
// adaptive screens, whose handler passes them on.

// l7sniScreenNames are the buttons of the L7 screen that change something,
// by the name in their callback data (resolved with callbackAction).
var l7sniScreenNames = map[string]bool{
	"l7sni_on": true, "l7sni_off": true,
	"l7q_off": true, "l7q_obs": true, "l7q_act": true,
}

func l7sniScreenText(id, head string) string {
	return withHead(head, "🔍 L7 SNI и QUIC — "+id+"\n\n"+
		"Порядок: адаптивная маршрутизация включена (L7 ей помогает, а не заменяет — выключать её "+
		"не нужно) → «L7 SNI вкл» → при желании QUIC. Все три — отдельные переключатели.\n\n"+
		"L7 SNI читает TLS SNI и HTTP Host прямо с провода (NFLOG) и досылает в список "+
		"адресов адаптивной маршрутизации совпадения с твоими routes — даже если DNS-запрос "+
		"роутер не видел (DoH/DoT, приложения с зашитым IP). Включение и выключение "+
		"перезапускают демон.\n\n"+
		"QUIC (UDP/443) — отдельный шаг поверх L7 SNI, демон не перезапускается. «QUIC выкл» его "+
		"выключает, остальные две кнопки включают:\n"+
		"• наблюдение — разбирает первые пакеты QUIC-соединений и только считает: сколько "+
		"расшифровано, у скольких имя спрятано за ECH, какие имена видны. Ничего не "+
		"переправляет — с него и стоит начать;\n"+
		"• действие — совпавшее с routes имя переправляется, как для TLS: браузер, у которого "+
		"QUIC к адресу отбит, сам уходит на TCP (приложению без запасного пути на TCP QUIC к "+
		"такому адресу не достанется). Нужна включённая адаптивная маршрутизация.\n\n"+
		"📈 Счётчики показывают, что захват видит и делает, и сколько пакетов дошло до его правил.")
}

func l7sniScreenKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔍 L7 SNI вкл", CallbackData: "adxQ:" + id + ":l7sni_on"}, {Text: "🔍 L7 SNI выкл", CallbackData: "adxQ:" + id + ":l7sni_off"}},
		// "QUIC выкл" is a button, not a state -- the screen's header says where
		// the mode stands -- so each of the three says what pressing it does to QUIC.
		{{Text: "⏹ QUIC выкл", CallbackData: "adxQ:" + id + ":l7q_off"}, {Text: "👁 QUIC наблюдение", CallbackData: "adxQ:" + id + ":l7q_obs"}},
		{{Text: "⚡ QUIC действие (переправлять)", CallbackData: "adxQ:" + id + ":l7q_act"}},
		{{Text: "📈 Счётчики", CallbackData: "adxS:" + id}},
		{{Text: "⬅️ Назад", CallbackData: "adrt:" + id}},
	}}
}

func l7sniStatsKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔄 Обновить", CallbackData: "adxS:" + id}, {Text: "⬅️ Назад", CallbackData: "adxQ:" + id}},
	}}
}

// l7sniMutate runs one change from a button of the L7 screen and shows the
// screen again with the router's answer on top. A failure leaves the operator
// on this screen too, with the reason -- adaptiveMutate's back button leads to
// the redirect list, which is not where this came from.
func (b *TelegramBot) l7sniMutate(ctx context.Context, chatID int64, msgID int, id, action string) {
	cmdID, err := b.Store.Enqueue(id, action, nil)
	if err != nil {
		b.editMessageText(ctx, chatID, msgID, l7sniScreenText(id, "не поставлено в очередь: "+err.Error()), l7sniScreenKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, l7sniScreenText(id, "⏳ …"), l7sniScreenKB(id))
	go func() {
		// Switching on may install iptables and friends first: wait as long as
		// the router may take (waitFor), not the 20 s of an ordinary button.
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.waitFor(action))
		var head string
		switch {
		case !ok:
			head = "⌛ роутер не ответил — изменение выполнится при следующем poll"
		case res.Err != "":
			head = "⚠️ " + res.Err
		default:
			if head = strings.TrimSpace(res.Output); head == "" {
				head = "✅ готово"
			}
		}
		b.editMessageText(ctx, chatID, msgID, l7sniScreenText(id, head), l7sniScreenKB(id))
	}()
}

// openL7SNIScreen shows the screen at once, then asks the router where its
// switches stand and puts the answer on top. The screen must not wait for the
// router -- it is a menu -- and must not fail without one: an agent that does
// not know l7sni_show (older than the control server) or does not answer leaves
// the static screen as it was.
//
// Nothing the operator pressed asks for the state to be drawn, so it is drawn
// only while the message is still on the tap that opened the screen: an
// operator who has already gone Back (or to the counters) must not have that
// screen replaced by this one when the router finally answers.
func (b *TelegramBot) openL7SNIScreen(ctx context.Context, cb tgCallbackQuery, id string) {
	b.editCB(ctx, cb, l7sniScreenText(id, ""), l7sniScreenKB(id))
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	tap := b.screens.current(chatID, msgID)
	cmdID, err := b.Store.Enqueue(id, ActionL7SNIShow, nil)
	if err != nil {
		return
	}
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		if !ok || res.Err != "" || b.screens.current(chatID, msgID) != tap {
			return
		}
		if head := strings.TrimSpace(res.Output); head != "" {
			b.editMessageText(ctx, chatID, msgID, l7sniScreenText(id, head), l7sniScreenKB(id))
		}
	}()
}

// screenSeq counts the taps on each message, so a goroutine that was started by
// one tap can tell that another has come since. Bounded: past a thousand
// messages the table is dropped, which only makes an old goroutine skip its
// edit -- the safe side.
type screenSeq struct {
	mu sync.Mutex
	n  map[screenKey]uint64
}

type screenKey struct {
	chat int64
	msg  int
}

func (s *screenSeq) touch(chat int64, msg int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == nil || len(s.n) > 1024 {
		s.n = map[screenKey]uint64{}
	}
	s.n[screenKey{chat, msg}]++
}

func (s *screenSeq) current(chat int64, msg int) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n[screenKey{chat, msg}]
}

// showL7SNIStats fetches what the L7 capture has counted and shows it in place
// of message msgID.
func (b *TelegramBot) showL7SNIStats(ctx context.Context, chatID int64, msgID int, id string) {
	title := "📈 L7-счётчики — " + id
	cmdID, err := b.Store.Enqueue(id, ActionL7SNIStats, nil)
	if err != nil {
		b.editMessageText(ctx, chatID, msgID, title+"\n\nне поставлено в очередь: "+err.Error(), l7sniStatsKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, title+"\n\n⏳ загружаю…", l7sniStatsKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		switch {
		case !ok:
			b.editMessageText(ctx, chatID, msgID, title+"\n\n⌛ роутер не ответил", l7sniStatsKB(id))
		case res.Err != "":
			b.editMessageText(ctx, chatID, msgID, title+"\n\n⚠️ "+res.Err, l7sniStatsKB(id))
		default:
			b.editMessageText(ctx, chatID, msgID, title+"\n\n"+strings.TrimSpace(res.Output), l7sniStatsKB(id))
		}
	}()
}

// handleL7SNICallback routes the buttons of the L7 screen. It reports false
// when data is not one of them.
func (b *TelegramBot) handleL7SNICallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	switch {
	case strings.HasPrefix(data, "adxQ:"):
		id, name, _ := strings.Cut(strings.TrimPrefix(data, "adxQ:"), ":")
		if !b.Store.HasRouter(id) {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return true
		}
		if name == "" {
			b.openL7SNIScreen(ctx, cb, id)
			return true
		}
		action := callbackAction(name)
		if !l7sniScreenNames[name] || action == "" {
			b.editCB(ctx, cb, "плохая кнопка", mainMenuKB())
			return true
		}
		b.l7sniMutate(ctx, chatID, msgID, id, action)
	case strings.HasPrefix(data, "adxS:"):
		id := strings.TrimPrefix(data, "adxS:")
		if !b.Store.HasRouter(id) {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return true
		}
		b.showL7SNIStats(ctx, chatID, msgID, id)
	default:
		return false
	}
	return true
}
