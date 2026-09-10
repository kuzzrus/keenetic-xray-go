package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// presetRefreshInterval is how often the daemon re-pulls the built-in
// routing-list presets from the repo. They change at most daily.
const presetRefreshInterval = 24 * time.Hour

// presetRefreshDelay lets the daemon settle (and any network come up)
// before the first pull.
const presetRefreshDelay = 90 * time.Second

// presetRefreshLoop keeps internal/presets' overlay in step with the
// repo, so a router picks up refreshed lists without a reinstall. Off
// when config sets presets_no_auto_update. Best-effort: a failed pull
// just leaves the last good copy (or the embed) in place.
//
// events, when non-nil, receives one Event per refresh that leaves any
// preset-bound route list newly drifted from what the operator's config
// says it should contain -- so 📦 Готовые списки changing upstream
// reaches the bot as a push, not just as something to notice next time
// the screen is opened. nil (agent disabled) just skips the send.
func presetRefreshLoop(ctx context.Context, logf func(string, ...any), events chan<- botcontrol.Event) {
	timer := time.NewTimer(presetRefreshDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		runPresetRefresh(ctx, logf, events)
		timer.Reset(presetRefreshInterval)
	}
}

func runPresetRefresh(ctx context.Context, logf func(string, ...any), events chan<- botcontrol.Event) {
	cfg, err := config.Load(configPath())
	if err != nil || cfg.PresetsNoAutoUpdate {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	res, err := presets.Refresh(rctx, cfg.PresetsSourceURL)
	if err != nil {
		logf("presets: обновление не удалось: %v", err)
		return
	}
	if res.Updated > 0 || res.Failed > 0 {
		logf("presets: %s", res.String())
	}

	// Checked every run, not just when Refresh itself reports changes:
	// on the first run after upgrading to this feature, a list can
	// already be drifting from an earlier day's pull that nobody was
	// ever told about -- that backlog should surface once too, not be
	// silently skipped because today's fetch happened to be a no-op.
	notes := presets.NewDrift(cfg)
	if len(notes) == 0 {
		return
	}
	if err := cfg.Save(configPath()); err != nil {
		logf("presets: could not persist notified-drift state: %v", err)
		return
	}
	logf("presets: %d %s changed upstream, notifying", len(notes), pluralLists(len(notes)))
	if events == nil {
		return
	}
	select {
	case events <- botcontrol.Event{Kind: "preset_drift", Text: presetDriftText(notes), Time: time.Now()}:
	case <-ctx.Done():
	}
}

func pluralLists(n int) string {
	if n == 1 {
		return "list"
	}
	return "lists"
}

// presetDriftText renders NewDrift's result as the message the operator
// sees in Telegram/CLI -- one line per changed list, plus how to act on
// it (the existing 📦 Готовые списки sync flow; this only notifies, it
// never re-syncs on its own -- same reasoning as everywhere else in this
// project that a list carrying live traffic is never silently swapped).
func presetDriftText(notes []presets.DriftNote) string {
	var b strings.Builder
	b.WriteString("📦 Готовые списки обновились:\n")
	for _, n := range notes {
		fmt.Fprintf(&b, "  • %s: +%d −%d\n", n.Name, n.Added, n.Removed)
	}
	b.WriteString("Синхронизировать: 📦 Готовые списки → список → 🔄 Синхронизировать (или /routes <router> preset sync <имя>)")
	return b.String()
}

// cmdRoutesPresetUpdate is `keenetic-xray routes preset update` -- pull
// the latest lists from the repo now instead of waiting for the daily
// loop. Handy right after an agent update, or for testing.
func cmdRoutesPresetUpdate(cfg *config.Config) error {
	presets.SetOverlay(presetsOverlayDir())
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	res, err := presets.Refresh(ctx, cfg.PresetsSourceURL)
	if err != nil {
		return err
	}
	fmt.Println("готовые списки: " + res.String())
	for _, n := range res.Notes {
		fmt.Println("  " + n)
	}
	return nil
}
