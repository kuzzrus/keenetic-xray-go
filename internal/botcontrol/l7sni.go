package botcontrol

import (
	"context"
	"fmt"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

// l7sniOn mirrors cmd/keenetic-xray's own `transport l7sni on`: it only
// ever flips Config.L7SNI.Enabled and saves. Unlike adaptiveRouteOn,
// there's no live-apply path to try first -- l7SNIClassifyLoop
// (cmd/keenetic-xray/l7sni_linux.go) reads this flag once at its own
// startup and then blocks in a socket read for the rest of the
// process's life, so rebindXray's SIGHUP-first reload wouldn't actually
// start or stop capture either way. The CLI falls back to an
// interactive "restart now? y/n" prompt for the same reason; a bot
// button has no prompt to fall back on, so this restarts directly.
func (h *RouterHandler) l7sniOn(ctx context.Context) (string, error) {
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — l7sni работает только на роутере Keenetic")
	}
	h.Config.L7SNI.Enabled = true
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	var warn string
	if err := h.restartDaemonDetached(); err != nil {
		warn = fmt.Sprintf("\n⚠️ автоматический перезапуск не удался (%v) — перезапустите вручную: ♻️ Рестарт демона", err)
	}
	return "L7 SNI включается, демон перезапускается…" + warn, nil
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
