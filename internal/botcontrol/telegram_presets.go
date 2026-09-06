package botcontrol

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// The 📦 Готовые списки screen sits under 📍 Маршруты. Opening it fetches
// the built-in presets from the router (routes_preset_list -- evaluated
// against THAT agent build's embedded lists and the router's live
// config), caches the snapshot per chat, and walks category → service →
// one preset. "Добавить" / "Синхронизировать" go through
// routes_preset_add / routes_preset_sync, which reuse presets.Apply /
// presets.Sync so the bot and the CLI behave identically.

// presetMenu is the last 📦 Готовые списки snapshot shown to one chat.
type presetMenu struct {
	routerID  string
	generated string
	cats      []string
	items     []presetItem // every row, domain presets and their -ip companions
}

type presetItem struct {
	name, service, title, category, kind string
	count                                int
	installed                            bool
	driftAdd, driftRemove                int
}

func (b *TelegramBot) setPresetMenu(chatID int64, pm presetMenu) {
	b.presetMenuMu.Lock()
	b.presetMenus[chatID] = pm
	b.presetMenuMu.Unlock()
}

func (b *TelegramBot) presetSnapshot(chatID int64, routerID string) (presetMenu, bool) {
	b.presetMenuMu.Lock()
	defer b.presetMenuMu.Unlock()
	pm, ok := b.presetMenus[chatID]
	if !ok || pm.routerID != routerID {
		return presetMenu{}, false
	}
	return pm, true
}

func (b *TelegramBot) presetItem(chatID int64, routerID string, idx int) (presetItem, bool) {
	pm, ok := b.presetSnapshot(chatID, routerID)
	if !ok || idx < 0 || idx >= len(pm.items) {
		return presetItem{}, false
	}
	return pm.items[idx], true
}

func parsePresetList(out string) presetMenu {
	var pm presetMenu
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		switch f[0] {
		case "#gen":
			if len(f) > 1 {
				pm.generated = f[1]
			}
			continue
		case "#cats":
			pm.cats = f[1:]
			continue
		}
		if len(f) < 9 {
			continue
		}
		count, _ := strconv.Atoi(f[5])
		dA, _ := strconv.Atoi(f[7])
		dR, _ := strconv.Atoi(f[8])
		pm.items = append(pm.items, presetItem{
			name: f[0], service: f[1], title: f[2], category: f[3], kind: f[4],
			count: count, installed: f[6] == "1", driftAdd: dA, driftRemove: dR,
		})
	}
	return pm
}

// domainItemsInCategory returns (globalIndex, item) for each domain
// preset in one category, title-sorted.
func (pm presetMenu) domainItemsInCategory(cat string) []struct {
	idx  int
	item presetItem
} {
	var out []struct {
		idx  int
		item presetItem
	}
	for i, it := range pm.items {
		if it.kind == "domains" && it.category == cat {
			out = append(out, struct {
				idx  int
				item presetItem
			}{i, it})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].item.title < out[b].item.title })
	return out
}

func (pm presetMenu) hasCompanion(name string) bool {
	for _, it := range pm.items {
		if it.name == name+"-ip" {
			return true
		}
	}
	return false
}

func (pm presetMenu) catIndex(cat string) int {
	for i, c := range pm.cats {
		if c == cat {
			return i
		}
	}
	return 0
}

// openPresetCategoriesScreen fetches routes_preset_list and shows the
// category buttons.
func (b *TelegramBot) openPresetCategoriesScreen(ctx context.Context, cb tgCallbackQuery, id string) {
	if !b.Store.HasRouter(id) {
		b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, ActionRoutesPresetList, nil)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), routesBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "📦 Готовые списки "+id+"\n\n⏳ загружаю…", routesBackKB(id))
	go func() {
		res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout())
		if !ok {
			b.editMessageText(ctx, chatID, msgID, "📦 Готовые списки "+id+"\n\n⌛ роутер не ответил", routesBackKB(id))
			return
		}
		if res.Err != "" {
			b.editMessageText(ctx, chatID, msgID, "📦 Готовые списки "+id+"\n\n⚠️ "+res.Err, routesBackKB(id))
			return
		}
		pm := parsePresetList(res.Output)
		pm.routerID = id
		if len(pm.items) == 0 {
			b.editMessageText(ctx, chatID, msgID, "📦 Готовые списки "+id+"\n\nв этой сборке агента их нет — обнови агент", routesBackKB(id))
			return
		}
		b.setPresetMenu(chatID, pm)
		b.editMessageText(ctx, chatID, msgID, presetCategoriesText(id, pm), presetCategoriesKB(id, pm))
	}()
}

func presetCategoriesText(id string, pm presetMenu) string {
	inst := 0
	for _, it := range pm.items {
		if it.installed && it.kind == "domains" {
			inst++
		}
	}
	s := fmt.Sprintf("📦 Готовые списки %s\n\nКурируемые списки доменов по сервисам, обновляются в репозитории", id)
	if pm.generated != "" {
		s += " (сборка от " + pm.generated + ")"
	}
	s += ".\nВыбери категорию."
	if inst > 0 {
		s += fmt.Sprintf("\n\nСейчас применено: %d.", inst)
	}
	return s
}

func presetCategoriesKB(id string, pm presetMenu) inlineKeyboard {
	var rows [][]inlineButton
	for i := 0; i < len(pm.cats); i += 2 {
		row := []inlineButton{{Text: pm.cats[i], CallbackData: fmt.Sprintf("rtpc:%s:%d", id, i)}}
		if i+1 < len(pm.cats) {
			row = append(row, inlineButton{Text: pm.cats[i+1], CallbackData: fmt.Sprintf("rtpc:%s:%d", id, i+1)})
		}
		rows = append(rows, row)
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ К спискам", CallbackData: "rtm:" + id}})
	return inlineKeyboard{InlineKeyboard: rows}
}

func (b *TelegramBot) openPresetCategoryScreen(ctx context.Context, cb tgCallbackQuery, id string, catIdx int) {
	pm, ok := b.presetSnapshot(cb.Message.Chat.ID, id)
	if !ok || catIdx < 0 || catIdx >= len(pm.cats) {
		b.editCB(ctx, cb, "меню устарело — открой 📦 Готовые списки заново", routesBackKB(id))
		return
	}
	cat := pm.cats[catIdx]
	entries := pm.domainItemsInCategory(cat)
	var rows [][]inlineButton
	for _, e := range entries {
		mark := ""
		if e.item.installed {
			if e.item.driftAdd+e.item.driftRemove > 0 {
				mark = fmt.Sprintf(" ⬆+%d−%d", e.item.driftAdd, e.item.driftRemove)
			} else {
				mark = " ✓"
			}
		}
		rows = append(rows, []inlineButton{{
			Text:         fmt.Sprintf("%s · %d%s", e.item.title, e.item.count, mark),
			CallbackData: fmt.Sprintf("rtps:%s:%d", id, e.idx),
		}})
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ Категории", CallbackData: "rtp:" + id}})
	b.editCB(ctx, cb, fmt.Sprintf("📦 %s (%s)\n\n%d %s. Значок ✓ — уже применён, ⬆ — есть обновление.",
		cat, id, len(entries), plural(len(entries), "сервис", "сервиса", "сервисов")), inlineKeyboard{InlineKeyboard: rows})
}

func (b *TelegramBot) openPresetScreen(ctx context.Context, cb tgCallbackQuery, id string, idx int) {
	it, ok := b.presetItem(cb.Message.Chat.ID, id, idx)
	if !ok {
		b.editCB(ctx, cb, "меню устарело — открой 📦 Готовые списки заново", routesBackKB(id))
		return
	}
	pm, _ := b.presetSnapshot(cb.Message.Chat.ID, id)
	hasIP := pm.hasCompanion(it.name)

	var b2 strings.Builder
	fmt.Fprintf(&b2, "📦 %s\n%s · %d доменов", it.title, it.category, it.count)
	if hasIP {
		b2.WriteString(" (+ список IP-диапазонов)")
	}
	if it.installed {
		if it.driftAdd+it.driftRemove > 0 {
			fmt.Fprintf(&b2, "\n\n⬆ применён, есть обновление: +%d −%d", it.driftAdd, it.driftRemove)
		} else {
			b2.WriteString("\n\n✓ применён, актуально")
		}
	} else {
		b2.WriteString("\n\nещё не применён")
	}

	var rows [][]inlineButton
	addLabel := "➕ Добавить (домены)"
	if it.installed {
		addLabel = "♻️ Перезалить домены"
	}
	rows = append(rows, []inlineButton{{Text: addLabel, CallbackData: fmt.Sprintf("rtpa:%s:%d:d", id, idx)}})
	if hasIP {
		rows = append(rows, []inlineButton{{Text: "➕ Домены + IP-диапазоны", CallbackData: fmt.Sprintf("rtpa:%s:%d:i", id, idx)}})
	}
	if it.installed && it.driftAdd+it.driftRemove > 0 {
		rows = append(rows, []inlineButton{{Text: fmt.Sprintf("🔄 Синхронизировать (+%d −%d)", it.driftAdd, it.driftRemove), CallbackData: fmt.Sprintf("rtpy:%s:%d", id, idx)}})
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ Назад", CallbackData: fmt.Sprintf("rtpc:%s:%d", id, pm.catIndex(it.category))}})
	b.editCB(ctx, cb, b2.String(), inlineKeyboard{InlineKeyboard: rows})
}

// enqueuePresetAction runs one preset mutation then re-fetches the preset
// list and re-renders that preset's category screen so ✓ / ⬆ marks
// update.
func (b *TelegramBot) enqueuePresetAction(ctx context.Context, cb tgCallbackQuery, id string, catIdx int, action string, args []string) {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, action, args)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), routesBackKB(id))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "📦 Готовые списки "+id+"\n\n⏳ …", routesBackKB(id))
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
		nCmd, e := b.Store.Enqueue(id, ActionRoutesPresetList, nil)
		if e != nil {
			b.editMessageText(ctx, chatID, msgID, head, routesBackKB(id))
			return
		}
		nr, nok := b.Store.AwaitResult(ctx, id, nCmd, b.resultTimeout())
		if !nok || nr.Err != "" {
			b.editMessageText(ctx, chatID, msgID, head, routesBackKB(id))
			return
		}
		pm := parsePresetList(nr.Output)
		pm.routerID = id
		b.setPresetMenu(chatID, pm)
		if catIdx < 0 || catIdx >= len(pm.cats) {
			b.editMessageText(ctx, chatID, msgID, head+"\n\n"+presetCategoriesText(id, pm), presetCategoriesKB(id, pm))
			return
		}
		cat := pm.cats[catIdx]
		entries := pm.domainItemsInCategory(cat)
		var rows [][]inlineButton
		for _, en := range entries {
			mark := ""
			if en.item.installed {
				if en.item.driftAdd+en.item.driftRemove > 0 {
					mark = fmt.Sprintf(" ⬆+%d−%d", en.item.driftAdd, en.item.driftRemove)
				} else {
					mark = " ✓"
				}
			}
			rows = append(rows, []inlineButton{{
				Text:         fmt.Sprintf("%s · %d%s", en.item.title, en.item.count, mark),
				CallbackData: fmt.Sprintf("rtps:%s:%d", id, en.idx),
			}})
		}
		rows = append(rows, []inlineButton{{Text: "⬅️ Категории", CallbackData: "rtp:" + id}})
		b.editMessageText(ctx, chatID, msgID, head+"\n\n📦 "+cat, inlineKeyboard{InlineKeyboard: rows})
	}()
}

// handlePresetCallback handles every rtp* callback. Returns false if data
// isn't one of ours.
func (b *TelegramBot) handlePresetCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	switch {
	case strings.HasPrefix(data, "rtp:"):
		b.openPresetCategoriesScreen(ctx, cb, strings.TrimPrefix(data, "rtp:"))
	case strings.HasPrefix(data, "rtpc:"):
		if id, idx, ok := parseRouteRef(data, "rtpc:"); ok {
			b.openPresetCategoryScreen(ctx, cb, id, idx)
		}
	case strings.HasPrefix(data, "rtps:"):
		if id, idx, ok := parseRouteRef(data, "rtps:"); ok {
			b.openPresetScreen(ctx, cb, id, idx)
		}
	case strings.HasPrefix(data, "rtpa:"):
		parts := strings.Split(strings.TrimPrefix(data, "rtpa:"), ":")
		if len(parts) != 3 {
			return true
		}
		id := parts[0]
		idx, err := strconv.Atoi(parts[1])
		if err != nil {
			return true
		}
		it, ok := b.presetItem(cb.Message.Chat.ID, id, idx)
		if !ok {
			b.editCB(ctx, cb, "меню устарело — открой 📦 Готовые списки заново", routesBackKB(id))
			return true
		}
		args := []string{it.name}
		if parts[2] == "i" {
			args = append(args, "ip")
		}
		pm, _ := b.presetSnapshot(cb.Message.Chat.ID, id)
		b.enqueuePresetAction(ctx, cb, id, pm.catIndex(it.category), ActionRoutesPresetAdd, args)
	case strings.HasPrefix(data, "rtpy:"):
		if id, idx, ok := parseRouteRef(data, "rtpy:"); ok {
			it, found := b.presetItem(cb.Message.Chat.ID, id, idx)
			if !found {
				b.editCB(ctx, cb, "меню устарело — открой 📦 Готовые списки заново", routesBackKB(id))
				return true
			}
			pm, _ := b.presetSnapshot(cb.Message.Chat.ID, id)
			b.enqueuePresetAction(ctx, cb, id, pm.catIndex(it.category), ActionRoutesPresetSync, []string{it.name})
		}
	default:
		return false
	}
	return true
}
