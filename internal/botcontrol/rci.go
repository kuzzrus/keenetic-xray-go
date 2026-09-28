package botcontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// The 🔌 RCI screen: reading the router config over Keenetic's local
// JSON API instead of ndmc -- `keenetic-xray rci` from the bot. The agent
// runs inside the daemon, which owns the RCI client, so every change
// applies at once through keenetic.UseRCI, no reload.
//
// The token (KeeneticOS 5.2+) carries administrator rights on the
// router. It reaches the agent as a queued command's argument -- in the
// control server's queue.json (0600) only until the agent's next poll
// takes it -- and is never echoed back: the replies below only ever say
// whether one is set, and Handle's scrubSecrets masks it on the way out
// regardless.

// rciTokenHowTo is where the operator gets a token.
const rciTokenHowTo = "веб-интерфейс роутера → Пользователи и доступ → Токены доступа → Добавить токен"

// rciProbeTimeout bounds one live check of the RCI endpoint.
const rciProbeTimeout = 8 * time.Second

func (h *RouterHandler) rciShow(ctx context.Context) string {
	r := h.Config.RCI
	var b strings.Builder
	switch {
	case r.Enabled && keenetic.RCIActive():
		fmt.Fprintf(&b, "RCI: включён, конфиг роутера читается через %s (записи — ndmc)\n", r.BaseURL())
	case r.Enabled:
		fmt.Fprintf(&b, "RCI: включён в настройках, но %s сейчас не используется — последняя проверка не прошла, читаем через ndmc\n", r.BaseURL())
	default:
		b.WriteString("RCI: выключен — конфиг роутера читается через ndmc\n")
	}
	b.WriteString("токен: " + rciTokenState(r.Token) + "\n")
	pctx, cancel := context.WithTimeout(ctx, rciProbeTimeout)
	defer cancel()
	ver, err := keenetic.ProbeRCI(pctx, r.BaseURL(), r.Token)
	switch {
	case err == nil:
		fmt.Fprintf(&b, "проверка: отвечает (KeeneticOS %s)\n", ver)
	case errors.Is(err, keenetic.ErrRCIAuth):
		fmt.Fprintf(&b, "проверка: %v\nНужен токен: %s, затем 🔑 Ввести токен.\n", err, rciTokenHowTo)
	default:
		fmt.Fprintf(&b, "проверка: %v\n", err)
	}
	return b.String()
}

// rciTokenState says whether a token is set without showing any of it.
func rciTokenState(token string) string {
	if token == "" {
		return "не задан (нужен только на KeeneticOS 5.2+)"
	}
	return fmt.Sprintf("задан (%d символов)", len(token))
}

func (h *RouterHandler) rciOn(ctx context.Context) (string, error) {
	r := h.Config.RCI
	if _, err := keenetic.UseRCI(r.BaseURL(), r.Token); err != nil {
		if errors.Is(err, keenetic.ErrRCIAuth) {
			return "", fmt.Errorf("%v\nНужен токен: %s, затем 🔑 Ввести токен", err, rciTokenHowTo)
		}
		return "", err
	}
	h.Config.RCI.Enabled = true
	if err := h.Config.Save(h.ConfigPath); err != nil {
		_, _ = keenetic.UseRCI("", "") // what runs must match what's saved
		return "", err
	}
	return "✅ RCI включён: конфиг роутера читается через " + r.BaseURL() + ", записи — по-прежнему ndmc", nil
}

func (h *RouterHandler) rciOff() (string, error) {
	h.Config.RCI.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	_, _ = keenetic.UseRCI("", "")
	return "RCI выключен — конфиг роутера читается через ndmc", nil
}

// rciToken stores args[0] as the RCI token ("" removes it) and reports
// whether RCI accepts it -- switching the live client over when RCI mode
// is on.
func (h *RouterHandler) rciToken(ctx context.Context, args []string) (string, error) {
	var token string
	if len(args) > 0 {
		token = strings.TrimSpace(args[0])
	}
	if token != "" && !config.ValidRCIToken(token) {
		return "", fmt.Errorf("это не похоже на токен RCI: ожидается одна строка из латиницы, цифр и +/=_.- длиной от 16 символов")
	}
	h.Config.RCI.Token = token
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	var b strings.Builder
	if token == "" {
		b.WriteString("🧹 токен RCI удалён\n")
	} else {
		b.WriteString("🔑 токен RCI сохранён на роутере\n")
	}
	r := h.Config.RCI
	if r.Enabled {
		if _, err := keenetic.UseRCI(r.BaseURL(), token); err != nil {
			fmt.Fprintf(&b, "⚠️ RCI с ним не отвечает: %v — пока читаем через ndmc\n", err)
		} else {
			b.WriteString("✅ RCI отвечает, конфиг роутера читается через него\n")
		}
		return b.String(), nil
	}
	pctx, cancel := context.WithTimeout(ctx, rciProbeTimeout)
	defer cancel()
	if _, err := keenetic.ProbeRCI(pctx, r.BaseURL(), token); err != nil {
		fmt.Fprintf(&b, "проверка: %v\n", err)
	} else {
		b.WriteString("✅ RCI отвечает. Читать конфиг через него: ✅ Включить\n")
	}
	return b.String(), nil
}
