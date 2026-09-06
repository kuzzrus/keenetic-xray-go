package botcontrol

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// The 📍 Маршруты screen is list-first: opening it fetches the route
// lists from the router (routes_names), caches the ordered snapshot per
// chat, and renders one button per list. Every per-list action --
// enable/disable, change interface, add/remove entries, delete -- is
// then a button on that list's own screen; callback_data carries the
// list's index into the cached snapshot, not its (up to 32-char) name.

func (b *TelegramBot) setRouteMenu(chatID int64, rm routeMenu) {
	b.routeMenuMu.Lock()
	b.routeMenus[chatID] = rm
	b.routeMenuMu.Unlock()
}

func (b *TelegramBot) routeMenuItem(chatID int64, routerID string, idx int) (routeItem, bool) {
	b.routeMenuMu.Lock()
	defer b.routeMenuMu.Unlock()
	rm, ok := b.routeMenus[chatID]
	if !ok || rm.routerID != routerID || idx < 0 || idx >= len(rm.items) {
		return routeItem{}, false
	}
	return rm.items[idx], true
}

// openRoutesScreen fetches the lists and renders them as buttons, in
// place of the message the callback came from.
func (b *TelegramBot) openRoutesScreen(ctx context.Context, cb tgCallbackQuery, id string) {
	if !b.Store.HasRouter(id) {
		b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, ActionRoutesNames, nil)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), routesBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n⏳ загружаю списки…", routesBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		if !ok {
			b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n⌛ роутер не ответил", routesBackKB(id))
			return
		}
		if res.Err != "" {
			b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n⚠️ "+res.Err, routesBackKB(id))
			return
		}
		items := parseRouteNames(res.Output)
		b.setRouteMenu(chatID, routeMenu{routerID: id, items: items})
		b.editMessageText(ctx, chatID, msgID, routesListText(id, items), routesListKB(id, items))
	}()
}

func parseRouteNames(out string) []routeItem {
	var items []routeItem
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		n, _ := strconv.Atoi(f[1])
		items = append(items, routeItem{name: f[0], count: n, disabled: f[2] == "off", iface: f[3]})
	}
	return items
}

func routesListText(id string, items []routeItem) string {
	if len(items) == 0 {
		return "📍 Маршруты " + id + "\n\nСписков пока нет. «➕ Новый список» — создать."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📍 Маршруты %s — %d %s:\n", id, len(items), plural(len(items), "список", "списка", "списков"))
	for _, it := range items {
		state := "✅"
		if it.disabled {
			state = "⛔"
		}
		fmt.Fprintf(&b, "\n%s %s · %d · → %s", state, it.name, it.count, it.iface)
	}
	b.WriteString("\n\nВыбери список кнопкой.")
	return b.String()
}

func routesListKB(id string, items []routeItem) inlineKeyboard {
	rows := make([][]inlineButton, 0, len(items)+2)
	for i, it := range items {
		label := "📁 " + it.name
		if it.disabled {
			label = "⛔ " + it.name
		}
		rows = append(rows, []inlineButton{{Text: label, CallbackData: fmt.Sprintf("rtL:%s:%d", id, i)}})
	}
	rows = append(rows,
		[]inlineButton{{Text: "📦 Готовые списки", CallbackData: "rtp:" + id}},
		[]inlineButton{{Text: "➕ Новый список", CallbackData: "rtNew:" + id}, {Text: "📊 Статус", CallbackData: "act:routes_show:" + id}},
		[]inlineButton{{Text: "⬅️ Назад", CallbackData: "router:" + id}},
	)
	return inlineKeyboard{InlineKeyboard: rows}
}

func routesBackKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔄 Ещё раз", CallbackData: "rtm:" + id}, {Text: "⬅️ Назад", CallbackData: "router:" + id}},
	}}
}

// openRouteListScreen renders one list's own screen from the cached
// snapshot -- instant, no round-trip.
func (b *TelegramBot) openRouteListScreen(ctx context.Context, cb tgCallbackQuery, id string, idx int) {
	it, ok := b.routeMenuItem(cb.Message.Chat.ID, id, idx)
	if !ok {
		b.editCB(ctx, cb, "список устарел — открой 📍 Маршруты заново", routesBackKB(id))
		return
	}
	b.editCB(ctx, cb, routeListScreenText(id, it), routeListScreenKB(id, idx, it))
}

func routeListScreenText(id string, it routeItem) string {
	state := "включён"
	if it.disabled {
		state = "выключен"
	}
	return fmt.Sprintf("📁 %s (%s)\n\n%d записей · %s · интерфейс %s\n\n"+
		"Записи — домены/подсети в этом списке. Интерфейс — куда его гнать.",
		it.name, id, it.count, state, it.iface)
}

func routeListScreenKB(id string, idx int, it routeItem) inlineKeyboard {
	tog := []inlineButton{{Text: "⛔ Выключить", CallbackData: fmt.Sprintf("rtT:%s:%d:0", id, idx)}}
	if it.disabled {
		tog = []inlineButton{{Text: "✅ Включить", CallbackData: fmt.Sprintf("rtT:%s:%d:1", id, idx)}}
	}
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "➕ Записи", CallbackData: fmt.Sprintf("rtEa:%s:%d", id, idx)}, {Text: "➖ Записи", CallbackData: fmt.Sprintf("rtEd:%s:%d", id, idx)}},
		{{Text: "🎯 Интерфейс: " + it.iface, CallbackData: fmt.Sprintf("rtI:%s:%d", id, idx)}},
		tog,
		{{Text: "🗑 Удалить список", CallbackData: fmt.Sprintf("rtDel:%s:%d", id, idx)}},
		{{Text: "⬅️ К спискам", CallbackData: "rtm:" + id}},
	}}
}

// openRouteIfaceScreen offers the common interface choices as buttons,
// plus a manual entry for any other WireguardN.
func (b *TelegramBot) openRouteIfaceScreen(ctx context.Context, cb tgCallbackQuery, id string, idx int) {
	it, ok := b.routeMenuItem(cb.Message.Chat.ID, id, idx)
	if !ok {
		b.editCB(ctx, cb, "список устарел — открой 📍 Маршруты заново", routesBackKB(id))
		return
	}
	kb := inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "Proxy0", CallbackData: fmt.Sprintf("rtSi:%s:%d:p0", id, idx)}, {Text: "Wireguard4", CallbackData: fmt.Sprintf("rtSi:%s:%d:w4", id, idx)}},
		{{Text: "✏️ Другой интерфейс", CallbackData: fmt.Sprintf("rtIm:%s:%d", id, idx)}},
		{{Text: "⬅️ Назад", CallbackData: fmt.Sprintf("rtL:%s:%d", id, idx)}},
	}}
	b.editCB(ctx, cb, fmt.Sprintf("📁 %s — куда гнать?\n\nСейчас: %s\nProxy0 — обычный путь, Wireguard4 — WG-транспорт.", it.name, it.iface), kb)
}

var routeIfaceTokens = map[string]string{"p0": "Proxy0", "w4": "Wireguard4"}

// handleRouteCallback routes every rt* callback that isn't the plain
// "rtm:" open. Returns false if data isn't one of ours.
func (b *TelegramBot) handleRouteCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	switch {
	case strings.HasPrefix(data, "rtL:"):
		id, idx, ok := parseRouteRef(data, "rtL:")
		if ok {
			b.openRouteListScreen(ctx, cb, id, idx)
		}
	case strings.HasPrefix(data, "rtI:"):
		id, idx, ok := parseRouteRef(data, "rtI:")
		if ok {
			b.openRouteIfaceScreen(ctx, cb, id, idx)
		}
	case strings.HasPrefix(data, "rtSi:"):
		rest := strings.TrimPrefix(data, "rtSi:")
		parts := strings.Split(rest, ":")
		if len(parts) != 3 {
			return true
		}
		iface, known := routeIfaceTokens[parts[2]]
		it, ok := b.routeMenuItemByStr(cb, parts[0], parts[1])
		if !known || !ok {
			b.editCB(ctx, cb, "плохая кнопка", routesBackKB(parts[0]))
			return true
		}
		b.enqueueRouteAction(ctx, cb, parts[0], ActionRoutesSetIface, []string{it.name, iface})
	case strings.HasPrefix(data, "rtIm:"):
		id, idx, ok := parseRouteRef(data, "rtIm:")
		if ok {
			if it, found := b.routeMenuItem(cb.Message.Chat.ID, id, idx); found {
				b.startRouteIfaceManualWizard(ctx, cb.Message.Chat.ID, id, it.name)
			}
		}
	case strings.HasPrefix(data, "rtT:"):
		rest := strings.TrimPrefix(data, "rtT:")
		parts := strings.Split(rest, ":")
		if len(parts) != 3 {
			return true
		}
		it, ok := b.routeMenuItemByStr(cb, parts[0], parts[1])
		if !ok {
			b.editCB(ctx, cb, "список устарел — открой 📍 Маршруты заново", routesBackKB(parts[0]))
			return true
		}
		on := "on"
		if parts[2] == "0" {
			on = "off"
		}
		b.enqueueRouteAction(ctx, cb, parts[0], ActionRoutesToggle, []string{it.name, on})
	case strings.HasPrefix(data, "rtEa:"), strings.HasPrefix(data, "rtEd:"):
		del := strings.HasPrefix(data, "rtEd:")
		pfx := "rtEa:"
		if del {
			pfx = "rtEd:"
		}
		id, idx, ok := parseRouteRef(data, pfx)
		if ok {
			if it, found := b.routeMenuItem(cb.Message.Chat.ID, id, idx); found {
				b.startRouteEntriesForList(ctx, cb.Message.Chat.ID, id, it.name, del)
			}
		}
	case strings.HasPrefix(data, "rtDel:"):
		id, idx, ok := parseRouteRef(data, "rtDel:")
		if !ok {
			return true
		}
		it, found := b.routeMenuItem(cb.Message.Chat.ID, id, idx)
		if !found {
			b.editCB(ctx, cb, "список устарел — открой 📍 Маршруты заново", routesBackKB(id))
			return true
		}
		kb := inlineKeyboard{InlineKeyboard: [][]inlineButton{
			{{Text: "🗑 Да, удалить", CallbackData: fmt.Sprintf("rtDy:%s:%d", id, idx)}},
			{{Text: "↩️ Отмена", CallbackData: fmt.Sprintf("rtL:%s:%d", id, idx)}},
		}}
		b.editCB(ctx, cb, fmt.Sprintf("Удалить список «%s» целиком (%d записей)?", it.name, it.count), kb)
	case strings.HasPrefix(data, "rtDy:"):
		id, idx, ok := parseRouteRef(data, "rtDy:")
		if !ok {
			return true
		}
		it, found := b.routeMenuItem(cb.Message.Chat.ID, id, idx)
		if !found {
			b.editCB(ctx, cb, "список устарел — открой 📍 Маршруты заново", routesBackKB(id))
			return true
		}
		b.enqueueRouteAction(ctx, cb, id, ActionRoutesRemoveList, []string{it.name})
	case strings.HasPrefix(data, "rtNew:"):
		b.startRouteEntriesWizard(ctx, cb.Message.Chat.ID, strings.TrimPrefix(data, "rtNew:"), false)
	default:
		return false
	}
	return true
}

func (b *TelegramBot) routeMenuItemByStr(cb tgCallbackQuery, id, idxStr string) (routeItem, bool) {
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		return routeItem{}, false
	}
	return b.routeMenuItem(cb.Message.Chat.ID, id, idx)
}

func parseRouteRef(data, prefix string) (id string, idx int, ok bool) {
	rest := strings.TrimPrefix(data, prefix)
	id, idxStr, cut := strings.Cut(rest, ":")
	if !cut {
		return "", 0, false
	}
	n, err := strconv.Atoi(idxStr)
	if err != nil {
		return "", 0, false
	}
	return id, n, true
}

// enqueueRouteAction runs one route mutation, then re-opens the 📍
// Маршруты list so the change (and any others) shows fresh.
func (b *TelegramBot) enqueueRouteAction(ctx context.Context, cb tgCallbackQuery, id, action string, args []string) {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, action, args)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), routesBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n⏳ …", routesBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		head := "✅ готово"
		switch {
		case !ok:
			head = "⌛ роутер не ответил"
		case res.Err != "":
			head = "⚠️ " + res.Err
		case strings.TrimSpace(res.Output) != "":
			head = strings.TrimSpace(res.Output)
		}
		// Refresh the list snapshot.
		nCmd, e := b.Store.Enqueue(id, ActionRoutesNames, nil)
		if e != nil {
			b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n"+head, routesBackKB(id))
			return
		}
		nr, nok := b.Store.AwaitResult(ctx, id, nCmd, b.resultTimeout())
		if !nok || nr.Err != "" {
			b.editMessageText(ctx, chatID, msgID, "📍 Маршруты "+id+"\n\n"+head, routesBackKB(id))
			return
		}
		items := parseRouteNames(nr.Output)
		b.setRouteMenu(chatID, routeMenu{routerID: id, items: items})
		b.editMessageText(ctx, chatID, msgID, head+"\n\n"+routesListText(id, items), routesListKB(id, items))
	}()
}

// startRouteEntriesForList jumps straight to the "paste domains/subnets"
// step for a list picked by button -- no "type the name" step.
func (b *TelegramBot) startRouteEntriesForList(ctx context.Context, chatID int64, routerID, name string, del bool) {
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRouteEntries, routerID: routerID, listName: name, del: del}
	b.wizardMu.Unlock()
	verb := "Добавить в «" + name + "»"
	if del {
		verb = "Убрать из «" + name + "»"
	}
	b.sendMessage(ctx, chatID, verb+" ("+routerID+").\nПришли домены/IP/подсети (через пробел, запятую или с новой строки).\nОтмена: /cancel")
}

// startRouteIfaceManualWizard asks only for the interface name; the list
// is already chosen.
func (b *TelegramBot) startRouteIfaceManualWizard(ctx context.Context, chatID int64, routerID, name string) {
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRouteIface, routerID: routerID, listName: name}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Интерфейс для «"+name+"» ("+routerID+").\nПришли имя: Proxy0 / Wireguard0 / Wireguard4 …\nОтмена: /cancel")
}

// wizardRouteIface (manual interface entry for an already-chosen list).
func (b *TelegramBot) wizardRouteIface(ctx context.Context, chatID int64, st *wizState, line string) {
	iface := strings.TrimSpace(line)
	if !config.ValidRouteIface(iface) || iface == "" {
		b.sendMessage(ctx, chatID, "нужно имя вида Proxy0 / Wireguard4. Ещё раз или /cancel") // stays armed
		return
	}
	b.wizardClear(chatID)
	out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionRoutesSetIface, []string{st.listName, iface})
	b.sendMessage(ctx, chatID, b.stepResult(st.routerID, answered, errText, "✅ "+strings.TrimSpace(out)))
}

func plural(n int, one, few, many string) string {
	n = n % 100
	if n >= 11 && n <= 14 {
		return many
	}
	switch n % 10 {
	case 1:
		return one
	case 2, 3, 4:
		return few
	default:
		return many
	}
}
