package botcontrol

import (
	"context"
	"strings"
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
		"L7 SNI читает TLS SNI и HTTP Host прямо с провода (NFLOG) и досылает в список "+
		"адресов адаптивной маршрутизации совпадения с твоими routes — даже если DNS-запрос "+
		"роутер не видел (DoH/DoT, приложения с зашитым IP). Включение и выключение "+
		"перезапускают демон.\n\n"+
		"QUIC (UDP/443) — отдельный шаг поверх L7 SNI, демон не перезапускается:\n"+
		"• наблюдение — разбирает первые пакеты QUIC-соединений и только считает: сколько "+
		"расшифровано, у скольких имя спрятано за ECH, какие имена видны. Ничего не "+
		"переправляет — с него и стоит начать;\n"+
		"• действие — совпавшее с routes имя переправляется, как для TLS: браузер, у которого "+
		"QUIC к адресу отбит, сам уходит на TCP (приложению без запасного пути на TCP QUIC к "+
		"такому адресу не достанется). Нужна включённая адаптивная маршрутизация.\n\n"+
		"📈 Счётчики показывают, что захват видит и делает. Режим сейчас — 📊 Показать на "+
		"экране адаптивной маршрутизации.")
}

func l7sniScreenKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔍 L7 SNI вкл", CallbackData: "adxQ:" + id + ":l7sni_on"}, {Text: "🔍 L7 SNI выкл", CallbackData: "adxQ:" + id + ":l7sni_off"}},
		{{Text: "QUIC: выкл", CallbackData: "adxQ:" + id + ":l7q_off"}, {Text: "👁 наблюдение", CallbackData: "adxQ:" + id + ":l7q_obs"},
			{Text: "⚡ действие", CallbackData: "adxQ:" + id + ":l7q_act"}},
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
			b.editCB(ctx, cb, l7sniScreenText(id, ""), l7sniScreenKB(id))
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
