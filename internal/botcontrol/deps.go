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
// that installs packages: the router's own budget for it (depsInstallTimeout)
// plus a margin for the poll that fetches the command and the post that returns
// the result -- the answer cannot arrive sooner than the work ends. Never less
// than ten times the ordinary wait either, so a large ResultTimeout still scales.
// Not derived from ResultTimeout alone: an operator who shortens it to get a
// quicker "router did not answer" for ordinary buttons must not also cut the
// wait for an install that is still running.
func (b *TelegramBot) installResultTimeout() time.Duration {
	return max(b.resultTimeout()*10, depsInstallTimeout+installWaitMargin)
}

// installWaitMargin is the slack on top of depsInstallTimeout: one poll interval
// to fetch the command, one result post to return its answer, and some air.
const installWaitMargin = 30 * time.Second

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
