package main

import (
	"context"
	"fmt"
	"time"

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
func presetRefreshLoop(ctx context.Context, logf func(string, ...any)) {
	timer := time.NewTimer(presetRefreshDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		runPresetRefresh(ctx, logf)
		timer.Reset(presetRefreshInterval)
	}
}

func runPresetRefresh(ctx context.Context, logf func(string, ...any)) {
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
