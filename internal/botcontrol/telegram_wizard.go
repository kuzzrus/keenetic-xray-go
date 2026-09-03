package botcontrol

import (
	"context"
	"fmt"
	"strings"
)

// wizState is a per-chat multi-step text dialog: /add_router (id, then
// display name), /rename (one step), and the "🔗 Ссылка" flow (paste a
// subscription URL). It exists so a menu button can prompt for input the
// same way a text command's arguments would.
type wizState struct {
	step     wizStep
	routerID string
}

type wizStep int

const (
	wizRouterID wizStep = iota
	wizRouterName
	wizRenameName
	wizSourceURL
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

// startSourceWizard prompts for a new subscription URL. Applying it is
// sub_seturl + sub_refresh on the router, which now also rebinds xray --
// so a changed link takes effect without a manual daemon restart.
func (b *TelegramBot) startSourceWizard(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizSourceURL, routerID: routerID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Новый URL подписки (http(s)://) для "+routerID+".\nОтмена: /cancel")
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

	case wizSourceURL:
		b.wizardSetSource(ctx, chatID, st.routerID, strings.TrimSpace(text))
		return true
	}

	b.wizardClear(chatID)
	return true
}

func (b *TelegramBot) wizardSetSource(ctx context.Context, chatID int64, routerID, url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		b.sendMessage(ctx, chatID, "нужен URL http(s)://. Ещё раз или /cancel") // wizard stays armed
		return
	}
	b.wizardClear(chatID)
	if _, answered, errText := b.enqueueAndWait(ctx, routerID, ActionSubSetURL, []string{url}); !answered || errText != "" {
		b.sendMessage(ctx, chatID, wizResult(answered, errText, ""))
		return
	}
	out, answered, errText := b.enqueueAndWait(ctx, routerID, ActionSubRefresh, nil)
	b.sendMessage(ctx, chatID, wizResult(answered, errText,
		"✅ "+strings.TrimSpace(out)+"\nОсновной/резервный — кнопка 📋 Профили."))
}

// wizResult picks the message for a finished enqueueAndWait step.
func wizResult(answered bool, errText, ok string) string {
	switch {
	case !answered && errText != "":
		return errText
	case !answered:
		return "роутер не ответил — попробуйте ещё раз"
	case errText != "":
		return "ошибка: " + errText
	default:
		return ok
	}
}
