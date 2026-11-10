package botcontrol

import (
	"context"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
)

// depsInstallTimeout is the execution budget of an action that may have to
// install a package. A cold `opkg update` plus an install over a slow link takes
// minutes, and the default command budget (DefaultCommandTimeout, 60 s) kills
// opkg halfway: the button then reports a timeout, the package is half there,
// and the next press starts over. Same trade as coreUpdateTimeout: the agent's
// loop is busy for the duration.
const depsInstallTimeout = featuredeps.Timeout

// installsPackages reports whether action may run opkg: the switches that
// ensure what they need before enabling a feature (adaptive routing, L7 SNI and
// its QUIC modes, the MSS clamp's iptables, the watchdog's cron) and the addon
// installer. The agent gives them depsInstallTimeout and the bot waits for
// their answer that much longer. Turning something off installs nothing.
func installsPackages(action string) bool {
	switch action {
	case ActionAdaptiveRouteOn, ActionL7SNIOn, ActionL7SNIQUICObserve, ActionL7SNIQUICAct,
		ActionSetMSS, ActionWatchdogEnable, ActionAddonInstall:
		return true
	}
	return false
}

// installResultTimeout is how long the bot waits for the answer to an action
// that installs packages: more than the agent's own budget for it, which in turn
// is more than a poll interval -- the answer cannot arrive sooner than the work
// ends. Ten times the ordinary wait, so a test that shortens ResultTimeout
// shortens this too.
func (b *TelegramBot) installResultTimeout() time.Duration { return b.resultTimeout() * 10 }

// waitFor is how long the bot waits for the router's answer to action.
func (b *TelegramBot) waitFor(action string) time.Duration {
	if installsPackages(action) {
		return b.installResultTimeout()
	}
	return b.resultTimeout()
}

// ensureDeps is featuredeps.Ensure, through the handler's hook when a test set
// one.
func (h *RouterHandler) ensureDeps(ctx context.Context, f featuredeps.Feature) featuredeps.Result {
	if h.EnsureDeps != nil {
		return h.EnsureDeps(ctx, f)
	}
	return featuredeps.Ensure(ctx, f)
}

// depsNotes renders what Ensure did as extra lines for a chat reply -- a "✅"
// line per package installed, a "⚠️" line per optional one that could not be --
// each starting with a newline, "" when it did nothing.
func depsNotes(res featuredeps.Result) string {
	var b strings.Builder
	for _, line := range res.Lines("✅ ", "⚠️ ") {
		b.WriteString("\n" + line)
	}
	return b.String()
}
