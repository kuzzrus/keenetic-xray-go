package botcontrol

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
)

// The 🧩 Дополнения screen manages optional router-side components
// (unbound, nfqws2, conntrack, cron) through the addon_* actions, which
// on the router run internal/addons -- the same package `keenetic-xray
// addon …` uses. Opening the screen asks the router for addon_list (a
// TSV of id/title/installed/running/version/detail) and renders one
// button per component; the per-component screen offers install /
// remove / configure / status.

const addonsBlurb = "🧩 Дополнения %s\n\n" +
	"Необязательные компоненты рядом с keenetic-xray: локальный DNS (unbound), " +
	"обход DPI на прямом трафике (nfqws2), пакеты conntrack и cron. Ставятся и " +
	"настраиваются здесь же.\n\n%s"

// addonRow is one parsed line of ActionAddonList output.
type addonRow struct {
	id, title       string
	installed       bool
	running         string // "0" | "1" | "-"
	version, detail string
}

func parseAddonList(out string) []addonRow {
	var rows []addonRow
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 6 {
			continue
		}
		rows = append(rows, addonRow{
			id: f[0], title: f[1], installed: f[2] == "1",
			running: f[3], version: undash(f[4]), detail: undash(f[5]),
		})
	}
	return rows
}

// undash reverses addonList's "-" sentinel for an empty field.
func undash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

func addonsScreenKB(id string, rows []addonRow) inlineKeyboard {
	var kb [][]inlineButton
	for _, r := range rows {
		mark := "⬜"
		if r.installed {
			mark = "✅"
		}
		kb = append(kb, []inlineButton{{Text: mark + " " + r.title, CallbackData: "adn:" + id + ":" + r.id}})
	}
	kb = append(kb, []inlineButton{
		{Text: "🔄 Обновить", CallbackData: "adnm:" + id},
		{Text: "⬅️ Назад", CallbackData: "router:" + id},
	})
	return inlineKeyboard{InlineKeyboard: kb}
}

func addonsListText(rows []addonRow) string {
	if len(rows) == 0 {
		return "не удалось прочитать список"
	}
	var b strings.Builder
	for _, r := range rows {
		mark := "⬜"
		if r.installed {
			mark = "✅"
		}
		fmt.Fprintf(&b, "%s %s", mark, r.title)
		var tail []string
		if r.version != "" {
			tail = append(tail, r.version)
		}
		if r.installed && r.running != "-" {
			if r.running == "1" {
				tail = append(tail, "работает")
			} else {
				tail = append(tail, "остановлен")
			}
		}
		if r.detail != "" {
			tail = append(tail, r.detail)
		}
		if len(tail) > 0 {
			fmt.Fprintf(&b, "  · %s", strings.Join(tail, " · "))
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func (b *TelegramBot) openAddonsScreen(ctx context.Context, cb tgCallbackQuery, id string) {
	if !b.Store.HasRouter(id) {
		b.editCB(ctx, cb, "нет такого роутера: "+id, b.routersListKB())
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, ActionAddonList, nil)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), addonsScreenKB(id, nil))
		return
	}
	b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(addonsBlurb, id, "⏳ читаю…"), addonsScreenKB(id, nil))
	go func() {
		var rows []addonRow
		state := "⌛ роутер не ответил"
		if res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout()); ok {
			if res.Err != "" {
				state = "⚠️ " + res.Err
			} else {
				rows = parseAddonList(res.Output)
				state = addonsListText(rows)
			}
		}
		b.editMessageText(ctx, chatID, msgID, fmt.Sprintf(addonsBlurb, id, state), addonsScreenKB(id, rows))
	}()
}

func addonScreenKB(id, addonID string) inlineKeyboard {
	rows := [][]inlineButton{
		{
			{Text: "⬇️ Установить", CallbackData: "adni:" + id + ":" + addonID},
			{Text: "🗑 Удалить", CallbackData: "adnr:" + id + ":" + addonID},
		},
		{
			{Text: "⚙️ Настроить", CallbackData: "adnc:" + id + ":" + addonID},
			{Text: "📊 Статус", CallbackData: "adns:" + id + ":" + addonID},
		},
	}
	// unbound / dnscrypt: one-tap router-DNS wiring. adnx carries the
	// key=value to pass straight to addon_configure; the router side is
	// idempotent and reverts on its own when the component is removed.
	if addonID == "unbound" || addonID == "dnscrypt" {
		rows = append(rows, []inlineButton{
			{Text: "🔌 Сделать DNS роутера", CallbackData: "adnx:" + id + ":" + addonID + ":router-dns=on"},
			{Text: "🔙 Вернуть DNS роутеру", CallbackData: "adnx:" + id + ":" + addonID + ":router-dns=off"},
		})
	}
	rows = append(rows, []inlineButton{{Text: "⬅️ Дополнения", CallbackData: "adnm:" + id}})
	return inlineKeyboard{InlineKeyboard: rows}
}

func (b *TelegramBot) openAddonScreen(ctx context.Context, cb tgCallbackQuery, id, addonID string) {
	if _, ok := addons.Find(addonID); !ok {
		b.editCB(ctx, cb, "нет такого компонента", addonsScreenKB(id, nil))
		return
	}
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, ActionAddonShow, []string{addonID})
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), addonScreenKB(id, addonID))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "🧩 "+addonID+"\n\n⏳ …", addonScreenKB(id, addonID))
	go func() {
		txt := "⌛ роутер не ответил"
		if res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.resultTimeout()); ok {
			if res.Err != "" {
				txt = "⚠️ " + res.Err
			} else if s := strings.TrimSpace(res.Output); s != "" {
				txt = s
			}
		}
		b.editMessageText(ctx, chatID, msgID, txt, addonScreenKB(id, addonID))
	}()
}

// enqueueAddonAction runs one addon_* mutation and re-renders the
// component screen with fresh state.
func (b *TelegramBot) enqueueAddonAction(ctx context.Context, cb tgCallbackQuery, id, addonID, action string, args []string) {
	chatID, msgID := cb.Message.Chat.ID, cb.Message.MessageID
	cmdID, err := b.Store.Enqueue(id, action, args)
	if err != nil {
		b.editCB(ctx, cb, "не поставлено в очередь: "+err.Error(), addonScreenKB(id, addonID))
		return
	}
	b.editMessageText(ctx, chatID, msgID, "🧩 "+addonID+"\n\n⏳ выполняю…", addonScreenKB(id, addonID))
	go func() {
		head := "✅ готово"
		if res, ok := b.Store.AwaitResult(ctx, id, cmdID, b.longResultTimeout()); !ok {
			head = "⌛ роутер не ответил (opkg бывает долгим — проверь 🔄)"
		} else if res.Err != "" {
			head = "⚠️ " + res.Err
		} else if s := strings.TrimSpace(res.Output); s != "" {
			head = s
		}
		b.editMessageText(ctx, chatID, msgID, "🧩 "+addonID+"\n\n"+head, addonScreenKB(id, addonID))
	}()
}

// longResultTimeout is resultTimeout stretched for opkg-bound actions
// (install/remove can pull packages over a slow link).
func (b *TelegramBot) longResultTimeout() time.Duration {
	return b.resultTimeout() * 4
}

func (b *TelegramBot) startAddonConfigWizard(ctx context.Context, chatID int64, routerID, addonID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, "нет такого роутера: "+routerID)
		return
	}
	a, ok := addons.Find(addonID)
	if !ok {
		b.sendMessage(ctx, chatID, "нет такого компонента: "+addonID)
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizAddonConfig, routerID: routerID, addonID: addonID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "🧩 "+addonID+" — настройка.\n\n"+a.About()+
		"\n\nПришли пары key=value через пробел (например: mode=list tcp_ports=443,80).\nОтмена: /cancel")
}

// wizardAddonConfig sends the pasted key=value pairs as addon_configure.
func (b *TelegramBot) wizardAddonConfig(ctx context.Context, chatID int64, st *wizState, text string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		b.sendMessage(ctx, chatID, "нужно хотя бы одно key=value. Ещё раз или /cancel") // stays armed
		return
	}
	for _, f := range fields {
		if !strings.Contains(f, "=") {
			b.sendMessage(ctx, chatID, "«"+f+"» не похоже на key=value. Ещё раз или /cancel")
			return
		}
	}
	b.wizardClear(chatID)
	args := append([]string{st.addonID}, fields...)
	out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionAddonConfigure, args)
	b.sendMessage(ctx, chatID, b.stepResult(st.routerID, answered, errText, strings.TrimSpace(out)))
}

// handleAddonsCallback handles every adn* callback. Returns false if
// data isn't one of ours.
func (b *TelegramBot) handleAddonsCallback(ctx context.Context, cb tgCallbackQuery, data string) bool {
	switch {
	case strings.HasPrefix(data, "adnm:"):
		b.openAddonsScreen(ctx, cb, strings.TrimPrefix(data, "adnm:"))
	case strings.HasPrefix(data, "adni:"):
		id, aid, ok := strings.Cut(strings.TrimPrefix(data, "adni:"), ":")
		if !ok {
			return true
		}
		b.enqueueAddonAction(ctx, cb, id, aid, ActionAddonInstall, []string{aid})
	case strings.HasPrefix(data, "adnr:"):
		id, aid, ok := strings.Cut(strings.TrimPrefix(data, "adnr:"), ":")
		if !ok {
			return true
		}
		b.enqueueAddonAction(ctx, cb, id, aid, ActionAddonRemove, []string{aid})
	case strings.HasPrefix(data, "adns:"):
		id, aid, ok := strings.Cut(strings.TrimPrefix(data, "adns:"), ":")
		if !ok {
			return true
		}
		b.enqueueAddonAction(ctx, cb, id, aid, ActionAddonStatus, []string{aid})
	case strings.HasPrefix(data, "adnc:"):
		id, aid, ok := strings.Cut(strings.TrimPrefix(data, "adnc:"), ":")
		if !ok {
			return true
		}
		b.startAddonConfigWizard(ctx, cb.Message.Chat.ID, id, aid)
	case strings.HasPrefix(data, "adnx:"):
		// adnx:<router>:<addon>:<key=value> -- a one-tap configure.
		id, tail, ok := strings.Cut(strings.TrimPrefix(data, "adnx:"), ":")
		if !ok {
			return true
		}
		aid, kv, ok := strings.Cut(tail, ":")
		if !ok || !strings.Contains(kv, "=") {
			return true
		}
		b.enqueueAddonAction(ctx, cb, id, aid, ActionAddonConfigure, []string{aid, kv})
	case strings.HasPrefix(data, "adn:"):
		id, aid, ok := strings.Cut(strings.TrimPrefix(data, "adn:"), ":")
		if !ok {
			return true
		}
		b.openAddonScreen(ctx, cb, id, aid)
	default:
		return false
	}
	return true
}
