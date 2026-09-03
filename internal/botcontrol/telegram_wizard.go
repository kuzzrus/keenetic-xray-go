package botcontrol

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// wizState is a per-chat multi-step text dialog. Two flows use it:
// /add_router (ask for an id, then a display name) and /setup (paste a
// source, then pick primary/backup by number). It exists so a menu
// button can prompt for input the same way a text command's arguments
// would.
type wizState struct {
	step     wizStep
	routerID string

	remarks    []string // /setup: profile remark per index, after the source step
	primaryIdx int      // /setup: chosen primary, pending the backup step
}

type wizStep int

const (
	wizRouterID wizStep = iota
	wizRouterName
	wizSetupSource
	wizSetupPrimary
	wizSetupBackup
)

func (b *TelegramBot) startAddRouterWizard(ctx context.Context, chatID int64) {
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRouterID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Добавление роутера.\n\nВведите id (латиница, цифры, _ или -), например home.\nОтмена: /cancel")
}

// cmdSetupStart handles `/setup <router>`; startSetupWizard is the shared
// body the menu button also calls.
func (b *TelegramBot) cmdSetupStart(ctx context.Context, chatID int64, args []string) {
	if len(args) < 1 || args[0] == "" {
		b.sendMessage(ctx, chatID, "формат: /setup <роутер>")
		return
	}
	b.startSetupWizard(ctx, chatID, args[0])
}

func (b *TelegramBot) startSetupWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizSetupSource, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Настройка "+routerID+".\n\nВставьте vless:// ссылку или URL подписки http(s)://\nОтмена: /cancel")
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

	case wizSetupSource:
		b.wizardSetupSource(ctx, chatID, st, strings.TrimSpace(text))
		return true

	case wizSetupPrimary:
		b.wizardSetupPickRole(ctx, chatID, st, text, true)
		return true

	case wizSetupBackup:
		b.wizardSetupPickRole(ctx, chatID, st, text, false)
		return true
	}

	b.wizardClear(chatID)
	return true
}

func (b *TelegramBot) wizardSetupSource(ctx context.Context, chatID int64, st *wizState, src string) {
	switch {
	case strings.HasPrefix(src, "vless://"):
		out, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionSetupLink, []string{src})
		b.wizardClear(chatID)
		b.sendMessage(ctx, chatID, wizResult(answered, errText, "✅ "+out))

	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		if _, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionSubSetURL, []string{src}); !answered || errText != "" {
			b.wizardClear(chatID)
			b.sendMessage(ctx, chatID, wizResult(answered, errText, ""))
			return
		}
		if _, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionSubRefresh, nil); !answered || errText != "" {
			b.wizardClear(chatID)
			b.sendMessage(ctx, chatID, wizResult(answered, errText, ""))
			return
		}
		listOut, answered, errText := b.enqueueAndWait(ctx, st.routerID, ActionProfileList, nil)
		if !answered || errText != "" {
			b.wizardClear(chatID)
			b.sendMessage(ctx, chatID, wizResult(answered, errText, ""))
			return
		}
		remarks := parseProfileList(listOut)
		if len(remarks) == 0 {
			b.wizardClear(chatID)
			b.sendMessage(ctx, chatID, "в подписке не нашлось профилей")
			return
		}
		if len(remarks) == 1 {
			b.enqueueAndWait(ctx, st.routerID, ActionSubSetPrimary, []string{"0"})
			b.enqueueAndWait(ctx, st.routerID, ActionSubSetBackup, []string{"0"})
			b.wizardClear(chatID)
			b.sendMessage(ctx, chatID, "✅ 1 профиль: "+remarks[0])
			return
		}
		st.remarks = remarks
		st.step = wizSetupPrimary
		b.sendMessage(ctx, chatID, numberedProfiles(remarks)+"\nНомер PRIMARY:")

	default:
		b.sendMessage(ctx, chatID, "нужна vless:// ссылка или http(s):// URL. Ещё раз или /cancel")
	}
}

func (b *TelegramBot) wizardSetupPickRole(ctx context.Context, chatID int64, st *wizState, text string, primary bool) {
	idx, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || idx < 0 || idx >= len(st.remarks) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нужен номер 0-%d. Ещё раз или /cancel", len(st.remarks)-1))
		return
	}

	action := ActionSubSetBackup
	if primary {
		action = ActionSubSetPrimary
	}
	_, answered, errText := b.enqueueAndWait(ctx, st.routerID, action, []string{strconv.Itoa(idx)})
	if !answered || errText != "" {
		b.wizardClear(chatID)
		b.sendMessage(ctx, chatID, wizResult(answered, errText, ""))
		return
	}

	if primary {
		st.primaryIdx = idx
		st.step = wizSetupBackup
		b.sendMessage(ctx, chatID, numberedProfiles(st.remarks)+"\nНомер BACKUP:")
		return
	}

	b.wizardClear(chatID)
	b.sendMessage(ctx, chatID, fmt.Sprintf("✅ настроено: primary=%s, backup=%s",
		st.remarks[st.primaryIdx], st.remarks[idx]))
}

// wizResult picks the message for a finished enqueueAndWait step.
func wizResult(answered bool, errText, ok string) string {
	switch {
	case !answered && errText != "":
		return errText
	case !answered:
		return "роутер не ответил — попробуйте /setup ещё раз"
	case errText != "":
		return "ошибка: " + errText
	default:
		return ok
	}
}

func numberedProfiles(remarks []string) string {
	var b strings.Builder
	for i, r := range remarks {
		fmt.Fprintf(&b, "%d: %s\n", i, r)
	}
	return strings.TrimRight(b.String(), "\n")
}
