package botcontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

// l7sniOn mirrors cmd/keenetic-xray's own `transport l7sni on`: it makes sure
// what the capture needs is on the router (iptables, the NFLOG kernel modules,
// conntrack), then flips Config.L7SNI.Enabled and saves. Unlike adaptiveRouteOn,
// there's no live-apply path to try first -- l7SNIClassifyLoop
// (cmd/keenetic-xray/l7sni_linux.go) reads this flag once at its own
// startup and then blocks in a socket read for the rest of the
// process's life, so rebindXray's SIGHUP-first reload wouldn't actually
// start or stop capture either way. The CLI falls back to an
// interactive "restart now? y/n" prompt for the same reason; a bot
// button has no prompt to fall back on, so this restarts directly.
//
// The tools come first, and a missing one stops the switch: the button used to
// answer "включается, демон перезапускается…" and the capture then died on its
// first iptables call, with the reason only in the daemon's log.
func (h *RouterHandler) l7sniOn(ctx context.Context) (string, error) {
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — l7sni работает только на роутере Keenetic")
	}
	deps := h.ensureDeps(ctx, featuredeps.L7SNI)
	if err := deps.Err(); err != nil {
		return "", fmt.Errorf("L7 SNI не включён: %w", err)
	}
	h.Config.L7SNI.Enabled = true
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	notes := depsNotes(deps)
	if !h.Config.AdaptiveRoute.Enabled {
		notes += "\n⚠️ Адаптивная маршрутизация выключена: имена TLS/HTTP не используются и ничего не переправляется " +
			"(QUIC в режиме наблюдения считает и так). Включить — на экране 🎯 Адаптивная маршрутизация."
	}
	if err := h.restartDaemonDetached(); err != nil {
		notes += fmt.Sprintf("\n⚠️ автоматический перезапуск не удался (%v) — перезапустите вручную: ♻️ Рестарт демона", err)
	}
	return "L7 SNI включается, демон перезапускается…" + notes, nil
}

// l7sniOff mirrors cmd/keenetic-xray's own `transport l7sni off`:
// clearing the NFLOG-triggering iptables rules is best-effort, same
// reasoning as adaptiveRouteOff's own REDIRECT-clear -- a failure here
// shouldn't block turning the feature off in config, since a stale rule
// with nothing behind it (once the daemon restarts and stops opening
// the NFLOG socket) is at worst a no-op match, not an actively
// misbehaving one. The restart always happens regardless.
func (h *RouterHandler) l7sniOff(ctx context.Context) (string, error) {
	var warn string
	if keenetic.Available() {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := l7capture.ClearRules(cctx); err != nil {
			warn = fmt.Sprintf("\n⚠️ не удалось убрать NFLOG-правила: %v", err)
		}
		cancel()
	}
	h.Config.L7SNI.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if err := h.restartDaemonDetached(); err != nil {
		warn += fmt.Sprintf("\n⚠️ автоматический перезапуск не удался (%v) — перезапустите вручную: ♻️ Рестарт демона", err)
	}
	return "L7 SNI выключается, демон перезапускается…" + warn, nil
}

// l7sniQUIC sets the QUIC (UDP/443) mode of the L7 capture -- the bot side of
// `transport l7sni quic`. It restarts nothing: the capture re-reads the mode
// every couple of seconds, and the one thing it cannot do itself, the NFLOG
// rule for UDP/443, is placed (or removed) through ReconcileL7SNI right here
// instead of waiting for the daemon's next periodic reconcile. The config is
// saved from this handler's own copy like every other bot action, which is why
// the CLI sends the daemon a reload after `quic`: a copy that never heard of
// the new mode would write the old one back.
func (h *RouterHandler) l7sniQUIC(ctx context.Context, mode string) (string, error) {
	previous := h.Config.L7SNI.QUIC
	if mode == config.L7SNIQUICOff {
		h.Config.L7SNI.QUIC = "" // off is the default; keep the config file free of it
	} else {
		h.Config.L7SNI.QUIC = mode
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		// Not saved, so not chosen: left in memory it would be reported by
		// the next "show" although the capture (which reads the file) is
		// not running it, and written out by the next unrelated save.
		h.Config.L7SNI.QUIC = previous
		return "", err
	}
	out := l7sniQUICStatusRU(h.Config)
	if h.Config.EffectiveL7SNIQUIC() == config.L7SNIQUICAct {
		// only when "act" really is in effect: with l7sni or adaptive routing
		// off the status line says it observes, and nothing is redirected
		out += "\nБраузеры сами уходят на TCP, когда QUIC к адресу отбит; приложению без запасного пути на TCP QUIC к такому адресу не достанется."
	}
	if mode != config.L7SNIQUICOff && !h.Config.L7SNI.Enabled {
		return out + "\nВключи 🔍 L7 SNI — без него QUIC-перехват не работает.", nil
	}
	if !h.Config.L7SNI.Enabled {
		return out, nil // nothing was installed, so nothing to take away
	}
	if mode != config.L7SNIQUICOff && keenetic.Available() {
		// L7 SNI may have been switched on by a version that did not check
		// what it needs, or /opt may have been wiped since: say so here, in the
		// answer to the button, not in a log nobody reads.
		deps := h.ensureDeps(ctx, featuredeps.L7SNI)
		out += depsNotes(deps)
		if err := deps.Err(); err != nil {
			return out + fmt.Sprintf("\n⚠️ %v\nРежим сохранён — поставь недостающее и нажми кнопку ещё раз.", err), nil
		}
	}
	if h.ReconcileL7SNI == nil {
		return out + "\nПравило перехвата UDP/443 поставит демон при ближайшей сверке (раз в 2 минуты).", nil
	}
	rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := h.ReconcileL7SNI(rctx); err != nil {
		return out + fmt.Sprintf("\n⚠️ Правило перехвата UDP/443 поставить не удалось (%v) — режим сохранён, демон повторит попытку при ближайшей сверке (раз в 2 минуты).", err), nil
	}
	return out + "\nПравило перехвата UDP/443 приведено в соответствие; демон подхватит режим сам, перезапуск не нужен.", nil
}

// l7sniStats returns what the L7 capture has counted (the stats file the
// daemon publishes), rendered by the daemon's own code.
func (h *RouterHandler) l7sniStats() (string, error) {
	if h.L7SNIStatsText == nil {
		return "", errors.New("счётчики L7 недоступны: этот агент собран без них")
	}
	return h.L7SNIStatsText()
}

// l7sniShow is what the L7 screen opens with: where its three switches stand --
// adaptive routing (which L7 SNI feeds and which must be on for anything to be
// redirected), L7 SNI itself, the QUIC mode -- and, for the first one that is
// off, what to press. The screen used to be static text, and an operator who
// saw "QUIC-перехват: выкл" in the answer to a button had no way to tell a
// state from a button, nor which of the three buttons next to it turns it on.
func (h *RouterHandler) l7sniShow(ctx context.Context) string {
	cfg := h.Config
	var b strings.Builder
	b.WriteString("🎯 Адаптивная маршрутизация: " + onOffRU(cfg.AdaptiveRoute.Enabled))
	b.WriteString("\n🔍 L7 SNI: " + onOffRU(cfg.L7SNI.Enabled))
	b.WriteString("\n🔍 " + l7sniQUICStatusRU(cfg))
	switch {
	case !cfg.L7SNI.Enabled:
		b.WriteString("\n➡️ Нажми «🔍 L7 SNI вкл» (демон перезапустится): без него не работает ни TLS/HTTP, ни QUIC.")
	case cfg.L7SNI.QUICMode() == config.L7SNIQUICOff:
		b.WriteString("\n➡️ QUIC-перехват включается кнопками «👁 QUIC наблюдение» (только считает) или «⚡ QUIC действие» (переправляет).")
	}
	if !cfg.AdaptiveRoute.Enabled {
		b.WriteString("\n⚠️ Адаптивная маршрутизация выключена — включи её на экране выше (⬅️ Назад): без неё L7 SNI ничего не переправляет, только считает. Выключать её ради L7 не нужно.")
	}
	if cfg.L7SNI.Enabled && h.L7SNINames != nil {
		// What the capture matches names against -- the config's lists and the
		// router's own -- and, when that is nothing, why a running capture never
		// redirects. Worded by the daemon, like the CLI's, so the two agree.
		if line, none := h.L7SNINames(ctx); line != "" {
			mark := "ℹ️ "
			if none {
				mark = "⚠️ "
			}
			b.WriteString("\n" + mark + line)
		}
	}
	return b.String()
}

func onOffRU(on bool) string {
	if on {
		return "вкл"
	}
	return "выкл"
}

// l7sniQUICWordRU is the short name of a QUIC mode.
func l7sniQUICWordRU(mode string) string {
	switch mode {
	case config.L7SNIQUICObserve:
		return "наблюдение"
	case config.L7SNIQUICAct:
		return "действие"
	default:
		return "выкл"
	}
}

// l7sniQUICStatusRU says what the QUIC mode is and what it amounts to. The
// configured mode and the one the capture runs with can differ -- l7sni itself
// off silences it, and "act" with adaptive routing off only observes
// (config.Config.EffectiveL7SNIQUIC) -- and the line says so rather than
// leaving the operator to wonder why nothing happens.
func l7sniQUICStatusRU(cfg *config.Config) string {
	set, eff := cfg.L7SNI.QUICMode(), cfg.EffectiveL7SNIQUIC()
	line := "QUIC-перехват: " + l7sniQUICWordRU(set)
	switch {
	case set == config.L7SNIQUICOff:
		// A value that is not one of the three (a hand-edited "Observe" or
		// "on") reads as off; say so, or the missing counters look like a
		// capture problem.
		if raw := cfg.L7SNI.QUIC; raw != "" && raw != config.L7SNIQUICOff {
			return fmt.Sprintf("%s — в config.json записано %q, это не off/observe/act, читается как «выкл»", line, raw)
		}
		return line
	case !cfg.L7SNI.Enabled:
		return line + " — но L7 SNI выключен, поэтому не работает"
	case set != eff:
		return line + " — адаптивная маршрутизация выключена, поэтому работает как «" + l7sniQUICWordRU(eff) + "»"
	case eff == config.L7SNIQUICObserve:
		return line + " — считаем имена и ECH-расширения, ничего не переправляем (итоги — 📈 L7-счётчики)"
	default:
		return line + " — совпавшие с routes имена переправляются, как для TLS"
	}
}
