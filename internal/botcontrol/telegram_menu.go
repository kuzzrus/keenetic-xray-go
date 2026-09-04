package botcontrol

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// This file is the inline-keyboard UX: a main menu, a router list, and a
// per-router card whose buttons enqueue commands and edit the same
// message in place with the result. Callback data is a short "kind:arg"
// string routed by handleCallback; every screen is reachable by text
// command too (see dispatch), the keyboard is just faster.

func mainMenuText() string { return "Меню управления роутерами." }

func mainMenuKB() inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "📡 Роутеры", CallbackData: "routers"}},
		{{Text: "➕ Добавить роутер", CallbackData: "add"}},
		{{Text: "⬆️ Обновить сервер", CallbackData: "svup"}, {Text: "❔ Справка", CallbackData: "help"}},
	}}
}

func backKB(to string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{{{Text: "⬅️ Назад", CallbackData: to}}}}
}

func (b *TelegramBot) routersListKB() inlineKeyboard {
	rows := [][]inlineButton{}
	for _, r := range b.Store.Routers() {
		label := r.ID
		if r.Name != "" {
			label = r.Name
		}
		rows = append(rows, []inlineButton{{Text: routerDot(r.LastPollAt) + " " + label, CallbackData: "router:" + r.ID}})
	}
	rows = append(rows, []inlineButton{
		{Text: "➕ Добавить", CallbackData: "add"},
		{Text: "🏠 Меню", CallbackData: "menu"},
	})
	return inlineKeyboard{InlineKeyboard: rows}
}

func routerCardKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "📊 Статус", CallbackData: "act:status:" + id}, {Text: "🩺 Doctor", CallbackData: "act:doctor:" + id}},
		{{Text: "⬆️ primary", CallbackData: "act:sw_pri:" + id}, {Text: "⬇️ backup", CallbackData: "act:sw_bak:" + id}},
		{{Text: "🔗 Источники", CallbackData: "srcm:" + id}},
		{{Text: "🔄 Обновить подписку", CallbackData: "act:sub_refresh:" + id}},
		{{Text: "♻️ Рестарт демона", CallbackData: "act:restart:" + id}, {Text: "🔁 Обновить агент", CallbackData: "upd:" + id}},
		{{Text: "✏️ Переименовать", CallbackData: "rename:" + id}, {Text: "📦 Установка агента", CallbackData: "install:" + id}},
		{{Text: "🗑 Удалить роутер", CallbackData: "del:" + id}},
		{{Text: "🔄 Обновить", CallbackData: "router:" + id}, {Text: "⬅️ Роутеры", CallbackData: "routers"}, {Text: "🏠 Меню", CallbackData: "menu"}},
	}}
}

func deleteConfirmKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🗑 Да, удалить", CallbackData: "delyes:" + id}},
		{{Text: "↩️ Отмена", CallbackData: "router:" + id}},
	}}
}

func updateConfirmKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "🔁 Да, обновить агент", CallbackData: "updyes:" + id}},
		{{Text: "↩️ Отмена", CallbackData: "router:" + id}},
	}}
}

// triggerServerUpdate touches the file the systemd .path unit watches.
// The root oneshot it fires re-runs server-install.sh; the control-server
// process is restarted out from under this one, so there's no result to
// report back beyond "queued".
func (b *TelegramBot) triggerServerUpdate() string {
	if b.SelfUpdatePath == "" {
		return "самообновление сервера не настроено (нужен server-install.sh начиная с v0.4.4)"
	}
	if err := os.WriteFile(b.SelfUpdatePath, []byte("update\n"), 0o644); err != nil {
		return "не удалось запросить обновление: " + err.Error()
	}
	return "⬆️ обновление сервера запущено — переустановка и рестарт через несколько секунд.\nПосле него бот ответит на /menu уже новой версией."
}

func sourcesScreenText(id string) string {
	return "🔗 Источники " + id + "\n\n" +
		"Задай, откуда брать профиль для каждого слота — можно из разных ссылок или подписок.\n" +
		"Переключить основной/резервный среди уже загруженных профилей: /profile_list " + id + ", затем /sub_setprimary или /sub_setbackup."
}

func sourcesScreenKB(id string) inlineKeyboard {
	return inlineKeyboard{InlineKeyboard: [][]inlineButton{
		{{Text: "⬆️ Основная", CallbackData: "srcp:" + id}, {Text: "⬇️ Резервная", CallbackData: "srcb:" + id}},
		{{Text: "⬅️ Назад", CallbackData: "router:" + id}},
	}}
}

// callbackAction maps a router-card button name to a Store command
// action. Only parameterless commands are on the keyboard; the ones that
// need an argument (sub_seturl, sub_setprimary/backup) stay text-only.
func callbackAction(name string) string {
	switch name {
	case "status":
		return ActionStatus
	case "doctor":
		return ActionDoctor
	case "sw_pri":
		return ActionSwitchPrimary
	case "sw_bak":
		return ActionSwitchBackup
	case "sub_refresh":
		return ActionSubRefresh
	case "restart":
		return ActionDaemonRestart
	case "self_update":
		return ActionSelfUpdate
	}
	return ""
}

func (b *TelegramBot) sendMainMenu(ctx context.Context, chatID int64) {
	b.sendMessageKB(ctx, chatID, mainMenuText(), mainMenuKB())
}

func (b *TelegramBot) routerCardText(id string) string {
	for _, r := range b.Store.Routers() {
		if r.ID != id {
			continue
		}
		s := routerDot(r.LastPollAt) + " " + r.ID
		if r.Name != "" {
			s += " (" + r.Name + ")"
		}
		switch {
		case r.LastPollAt.IsZero():
			s += " — ещё не подключался"
		case routerOnline(r.LastPollAt):
			s += " — на связи, poll " + shortDur(time.Since(r.LastPollAt)) + " назад"
		default:
			s += " — молчит с " + r.LastPollAt.Format("2006-01-02 15:04")
		}
		if r.Pending > 0 {
			s += fmt.Sprintf(", в очереди: %d", r.Pending)
		}
		if r.LastStatus != "" {
			age := "только что"
			if d := time.Since(r.LastStatusAt); d > time.Minute {
				age = shortDur(d) + " назад"
			}
			s += "\n\n" + strings.TrimRight(r.LastStatus, "\n") + "\n\n(данные " + age + ")"
		} else {
			s += "\n\nснимок состояния ещё не пришёл"
		}
		return s
	}
	return "роутер " + id + " не найден"
}

// editCB replaces the callback's source message, falling back to a fresh
// message if the edit fails (e.g. the original is too old to edit).
func (b *TelegramBot) editCB(ctx context.Context, cb tgCallbackQuery, text string, kb inlineKeyboard) {
	if cb.Message == nil {
		return
	}
	if !b.editMessageText(ctx, cb.Message.Chat.ID, cb.Message.MessageID, text, kb) {
		b.sendMessageKB(ctx, cb.Message.Chat.ID, text, kb)
	}
}

func (b *TelegramBot) handleCallback(ctx context.Context, cb tgCallbackQuery) {
	if cb.Message == nil || !b.AllowedChats[cb.Message.Chat.ID] {
		b.answerCallback(ctx, cb.ID, "")
		return
	}
	b.answerCallback(ctx, cb.ID, "")

	data := cb.Data
	switch {
	case data == "menu":
		b.editCB(ctx, cb, mainMenuText(), mainMenuKB())
	case data == "help":
		b.editCB(ctx, cb, helpText, backKB("menu"))
	case data == "svup":
		b.editCB(ctx, cb, "Обновить серверную часть бота до последнего релиза?\nСервис перезапустится.", inlineKeyboard{InlineKeyboard: [][]inlineButton{
			{{Text: "⬆️ Да, обновить", CallbackData: "svupyes"}},
			{{Text: "↩️ Отмена", CallbackData: "menu"}},
		}})
	case data == "svupyes":
		b.editCB(ctx, cb, b.triggerServerUpdate(), backKB("menu"))
	case data == "routers":
		b.editCB(ctx, cb, b.listRouters(), b.routersListKB())
	case data == "add":
		b.startAddRouterWizard(ctx, cb.Message.Chat.ID)
	case strings.HasPrefix(data, "srcm:"):
		id := strings.TrimPrefix(data, "srcm:")
		if !b.Store.HasRouter(id) {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return
		}
		b.editCB(ctx, cb, sourcesScreenText(id), sourcesScreenKB(id))
	case strings.HasPrefix(data, "srcp:"):
		b.startSlotSourceWizard(ctx, cb.Message.Chat.ID, strings.TrimPrefix(data, "srcp:"), true)
	case strings.HasPrefix(data, "srcb:"):
		b.startSlotSourceWizard(ctx, cb.Message.Chat.ID, strings.TrimPrefix(data, "srcb:"), false)
	case strings.HasPrefix(data, "rename:"):
		b.startRenameWizard(ctx, cb.Message.Chat.ID, strings.TrimPrefix(data, "rename:"))
	case strings.HasPrefix(data, "router:"):
		id := strings.TrimPrefix(data, "router:")
		b.editCB(ctx, cb, b.routerCardText(id), routerCardKB(id))
	case strings.HasPrefix(data, "install:"):
		id := strings.TrimPrefix(data, "install:")
		tok, ok := b.Store.TokenFor(id)
		if !ok {
			b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
			return
		}
		// Leave the card in place; send the commands as their own
		// message so the <pre> block is separately copyable.
		b.sendConfigureHint(ctx, cb.Message.Chat.ID, id, tok)
	case strings.HasPrefix(data, "del:"):
		id := strings.TrimPrefix(data, "del:")
		b.editCB(ctx, cb, "Удалить роутер "+id+" из реестра?\nАгент на самом роутере не трогается.", deleteConfirmKB(id))
	case strings.HasPrefix(data, "delyes:"):
		id := strings.TrimPrefix(data, "delyes:")
		if err := b.Store.RemoveRouter(id); err != nil {
			b.editCB(ctx, cb, "не удалено: "+err.Error(), routerCardKB(id))
			return
		}
		b.editCB(ctx, cb, "роутер "+id+" удалён.\n\n"+b.listRouters(), b.routersListKB())
	case strings.HasPrefix(data, "upd:"):
		id := strings.TrimPrefix(data, "upd:")
		b.editCB(ctx, cb, "Обновить агент на "+id+"?\nПереустановит .ipk и перезапустит демон.", updateConfirmKB(id))
	case strings.HasPrefix(data, "updyes:"):
		b.handleActionCallback(ctx, cb, "act:self_update:"+strings.TrimPrefix(data, "updyes:"))
	case strings.HasPrefix(data, "act:"):
		b.handleActionCallback(ctx, cb, data)
	default:
		b.editCB(ctx, cb, "неизвестная кнопка", mainMenuKB())
	}
}

// handleActionCallback enqueues a router-card command, shows "queued" in
// place, then edits the same message again with the result when it
// arrives (or a not-answered note on timeout).
func (b *TelegramBot) handleActionCallback(ctx context.Context, cb tgCallbackQuery, data string) {
	parts := strings.SplitN(data, ":", 3)
	if len(parts) != 3 {
		b.editCB(ctx, cb, "плохая кнопка", mainMenuKB())
		return
	}
	name, id := parts[1], parts[2]
	action := callbackAction(name)
	if action == "" {
		b.editCB(ctx, cb, "не поддерживается: "+name, routerCardKB(id))
		return
	}
	if !b.Store.HasRouter(id) {
		b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
		return
	}
	cmdID, err := b.Store.Enqueue(id, action, nil)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), routerCardKB(id))
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	b.editMessageText(ctx, chatID, msgID, b.routerCardText(id)+"\n\n⏳ команда в очереди…", routerCardKB(id))
	go b.awaitActionResult(ctx, chatID, msgID, id, cmdID)
}

func (b *TelegramBot) awaitActionResult(ctx context.Context, chatID int64, msgID int, routerID, cmdID string) {
	result, ok := b.Store.AwaitResult(ctx, routerID, cmdID, b.resultTimeout())
	var extra string
	switch {
	case !ok:
		extra = "⌛ роутер не ответил — выполнится при следующем poll"
	case result.Err != "":
		extra = "⚠️ ошибка:\n" + result.Err
	default:
		extra = result.Output
	}
	b.editMessageText(ctx, chatID, msgID, b.routerCardText(routerID)+"\n\n"+extra, routerCardKB(routerID))
}
