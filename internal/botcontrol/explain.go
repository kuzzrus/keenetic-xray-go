package botcontrol

import (
	"context"
	"fmt"
	"strings"
)

// explain answers ActionExplain (the bot's /why): why the name or address in
// args[0] goes through the tunnel or does not. The text comes from the daemon's
// own explainer (RouterHandler.Explain) -- the lists, the adaptive set and the
// resolver live on the router, not here -- so that the CLI and the bot say the
// same thing.
func (h *RouterHandler) explain(ctx context.Context, args []string) (string, error) {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		return "", fmt.Errorf("формат: /why <роутер> <имя|ip>")
	}
	if h.Explain == nil {
		return "", fmt.Errorf("этот агент не умеет объяснять маршрут — обновите приложение на роутере")
	}
	return h.Explain(ctx, args[0])
}
