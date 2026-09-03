package botcontrol

import (
	"context"
	"fmt"
	"strings"
)

// wizState is a per-chat multi-step text dialog. The only flow today is
// /add_router (ask for an id, then a display name); it exists so that
// tapping "➕ Добавить роутер" in the menu can prompt for input the same
// way the text command's arguments would.
type wizState struct {
	step     wizStep
	routerID string
}

type wizStep int

const (
	wizRouterID wizStep = iota
	wizRouterName
)

func (b *TelegramBot) startAddRouterWizard(ctx context.Context, chatID int64) {
	b.wizardMu.Lock()
	b.wizards[chatID] = &wizState{step: wizRouterID}
	b.wizardMu.Unlock()
	b.sendMessage(ctx, chatID, "Добавление роутера.\n\nВведите id (латиница, цифры, _ или -), например home.\nОтмена: /cancel")
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
	}

	b.wizardClear(chatID)
	return true
}
