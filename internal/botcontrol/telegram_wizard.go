package botcontrol

import (
	"context"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// wizState is a per-chat multi-step text dialog: /add_router (id, then
// display name), /rename (one step), and the 🔗 Источники flow (paste a
// link or subscription URL for one slot). It exists so a menu button can
// prompt for input the same way a text command's arguments would.
type wizState struct {
	step     wizStep
	routerID string
	primary  bool // wizSlotSource: which slot the pasted source feeds
}

type wizStep int

const (
	wizRouterID wizStep = iota
	wizRouterName
	wizRenameName
	wizSlotSource
	wizPorts
	wizProxyIface
)

func (b *TelegramBot) startAddRouterWizard(ctx context.Context, chatID int64) {
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRouterID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Добавление роутера.\n\nВведите id (латиница, цифры, _ или -), например home.\nОтмена: /cancel")
}

func (b *TelegramBot) startRenameWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRenameName, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Новое имя для "+routerID+" (пустая строка — совпадёт с id).\nОтмена: /cancel")
}

// startSlotSourceWizard prompts for one slot's source -- a vless:// link
// or an http(s):// subscription URL, optionally followed by a selector
// (index or a name substring) for a multi-profile subscription. Applied
// via set_primary_source / set_backup_source, which merge the resolved
// profile, repoint the slot and rebind xray.
func (b *TelegramBot) startSlotSourceWizard(ctx context.Context, chatID int64, routerID string, primary bool) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	slot := "резервной"
	if primary {
		slot = "основной"
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizSlotSource, routerID: routerID, primary: primary}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID,
		"Источник для "+slot+" ("+routerID+"):\nвставь vless:// ссылку или http(s):// URL подписки.\n"+
			"Для подписки можно добавить селектор через пробел — номер профиля или часть названия.\nОтмена: /cancel")
}

// startPortsWizard prompts for new SOCKS/HTTP inbound port numbers.
// Unlike the CLI wizard, the control server has no direct view of the
// router's current config (a separate process, possibly a separate
// machine entirely) to show as defaults -- /status <router> or the
// card's own 📊 Статус ("xray: слушает :N") has that. Applied via
// set_ports, which validates both, saves, rebinds xray, and (if Proxy0
// is on) re-points its upstream to match.
func (b *TelegramBot) startPortsWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizPorts, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID,
		"Смена портов ("+routerID+").\nПришли два новых номера через пробел: SOCKS HTTP (например: 1080 1081).\n"+
			"Текущие видно в 📊 Статус.\nОтмена: /cancel")
}

// startProxyIfaceWizard prompts for the Keenetic Proxy interface name
// the daemon should drive (Proxy0, Proxy1, ...). Like the ports wizard it
// doesn't echo the current value -- the control server has no direct view
// of the router's config; 📊 Показать on the same screen has it. Applied
// via proxy0_config with an empty protocol slot (interface only).
func (b *TelegramBot) startProxyIfaceWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizProxyIface, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID,
		"Интерфейс Keenetic для ("+routerID+").\nПришли имя: Proxy0, Proxy1, Proxy2 …\n"+
			"Proxy0 — по умолчанию. Отмена: /cancel")
}

func (b *TelegramBot) wizardClear(chatID int64) {
	b.wizardMu.Lock()
	delete(b.wizards, chatID)
	b.wizardMu.Unlock()
}

// handleWizardText feeds one message line into a chat's active dialog.
// It returns true if the message was consumed by a dialog (so the normal
// command dispatch should be skipped). Any /command other than /cancel
// aborts the dialog and is left for dispatch to handle.
func (b *TelegramBot) handleWizardText(ctx context.Context, chatID int64, text string) bool {
	b.wizardMu.Lock()
	st, ok := b.wizards[chatID]
	b.wizardMu.Unlock()
	if !ok {
		return false
	}

	if strings.HasPrefix(text, "/") {
		b.wizardClear(chatID)
		if text == "/cancel" {
			b.sendMessage(ctx, chatID, "Отменено.")
			return true
		}
		return false // let dispatch run the command
	}

	switch st.step {
	case wizRouterID:
		if !ValidRouterID(text) {
			b.sendMessage(ctx, chatID, "id: латиница, цифры, _ или -, до 64 символов. Ещё раз или /cancel")
			return true
		}
		if b.Store.HasRouter(text) {
			b.sendMessage(ctx, chatID, fmt.Sprintf("роутер %q уже есть. Другой id или /cancel", text))
			return true
		}
		st.routerID = text
		st.step = wizRouterName
		b.sendMessage(ctx, chatID, "Имя для отображения (например: Дом). Пустая строка — совпадёт с id.")
		return true

	case wizRouterName:
		name := strings.TrimSpace(text)
		if name == "" {
			name = st.routerID
		}
		token, err := b.Store.AddRouter(st.routerID, name)
		b.wizardClear(chatID)
		if err != nil {
			b.sendMessage(ctx, chatID, fmt.Sprintf("не добавлено: %v", err))
			return true
		}
		b.sendConfigureHint(ctx, chatID, st.routerID, token)
		return true

	case wizRenameName:
		name := strings.TrimSpace(text)
		if name == "" {
			name = st.routerID
		}
		err := b.Store.RenameRouter(st.routerID, name)
		b.wizardClear(chatID)
		if err != nil {
			b.sendMessage(ctx, chatID, fmt.Sprintf("не переименовано: %v", err))
			return true
		}
		b.sendMessage(ctx, chatID, "✅ теперь: "+name)
		return true

	case wizSlotSource:
		b.wizardSetSlotSource(ctx, chatID, st, strings.TrimSpace(text))
		return true

	case wizPorts:
		b.wizardSetPorts(ctx, chatID, st, strings.TrimSpace(text))
		return true

	case wizProxyIface:
		b.wizardSetProxyIface(ctx, chatID, st, strings.TrimSpace(text))
		return true
	}

	b.wizardClear(chatID)
	return true
}

func (b *TelegramBot) wizardSetSlotSource(ctx context.Context, chatID int64, st *wizState, line string) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		b.sendMessage(ctx, chatID, "нужна vless:// ссылка или http(s):// URL. Ещё раз или /cancel")
		return
	}
	src := fields[0]
	if !strings.HasPrefix(src, "vless://") && !strings.HasPrefix(src, "http://") && !strings.HasPrefix(src, "https://") {
		b.sendMessage(ctx, chatID, "нужна vless:// ссылка или http(s):// URL. Ещё раз или /cancel") // stays armed
		return
	}
	args := []string{src}
	if len(fields) > 1 {
		args = append(args, strings.Join(fields[1:], " "))
	}

	b.wizardClear(chatID)
	action := ActionSetBackupSource
	if st.primary {
		action = ActionSetPrimarySource
	}
	out, answered, errText := b.enqueueAndWait(ctx, st.routerID, action, args)
	b.sendMessage(ctx, chatID, b.stepResult(st.routerID, answered, errText, "✅ "+strings.TrimSpace(out)))
}

func (b *TelegramBot) wizardSetPorts(ctx context.Context, chatID int64, st *wizState, line string) {
	fields := strings.Fields(line)
	if len(fields) != 2 {
		b.sendMessage(ctx, chatID, "нужно два числа через пробел: SOCKS HTTP. Ещё раз или /cancel") // stays armed
		return
	}

	b.wizardClear(chatID)
	out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionSetPorts, fields)
	b.sendMessage(ctx, chatID, b.stepResult(st.routerID, answered, errText, "✅ "+strings.TrimSpace(out)))
}

func (b *TelegramBot) wizardSetProxyIface(ctx context.Context, chatID int64, st *wizState, line string) {
	iface := strings.Fields(line)
	if len(iface) != 1 || !config.ValidProxyIface(iface[0]) {
		b.sendMessage(ctx, chatID, "нужно одно имя вида Proxy0 / Proxy1. Ещё раз или /cancel") // stays armed
		return
	}

	b.wizardClear(chatID)
	out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionProxy0Config, []string{"", iface[0]})
	b.sendMessage(ctx, chatID, b.stepResult(st.routerID, answered, errText, "✅ "+strings.TrimSpace(out)))
}

// stepResult phrases the outcome of one enqueueAndWait wizard step. The
// "no answer" case is split by whether the router looks online -- a
// command queued for an offline router will run on reconnect, so
// "попробуйте ещё раз" would be misleading.
func (b *TelegramBot) stepResult(routerID string, answered bool, errText, ok string) string {
	switch {
	case !answered && errText != "":
		return errText
	case !answered:
		return queuedNote(b.Store.LastPollAt(routerID))
	case errText != "":
		return "ошибка: " + errText
	default:
		return ok
	}
}
