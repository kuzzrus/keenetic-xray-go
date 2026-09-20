package main

import (
	"context"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/health"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// startQualitySweep launches the periodic all-profiles health sweep when
// it's enabled (failover.quality_sweep_minutes > 0). A no-op otherwise.
// The sweep runs its own scratch xray on PretestPort+1 -- never the live
// or recovery-pretest instance -- so it can't disturb traffic.
func startQualitySweep(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	if !cfg.Failover.QualitySweepEnabled() {
		return
	}
	port := cfg.Failover.PretestPort + 1
	switch port {
	case cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort, cfg.Failover.PretestPort:
		logf("quality sweep: нет свободного порта рядом с pretest (%d) — опрос выключен", cfg.Failover.PretestPort)
		return
	}
	if port < 1 || port > 65535 {
		logf("quality sweep: порт %d вне диапазона — опрос выключен", port)
		return
	}

	sw := &health.Sweeper{
		XrayBinary: xrayBinaryPath(),
		ConfigPath: qualitySweepConfigPath(),
		StatePath:  qualityStatePath(),
		Port:       port,
		XHTTPMode:  cfg.XHTTPMode,
		Probe: xrayctl.ProbeOptions{
			URL:          cfg.Failover.HealthCheckURL,
			FallbackURLs: cfg.Failover.HealthCheckFallbackURLs,
			Timeout:      8 * time.Second,
		},
		Log: logf,
	}
	every := time.Duration(cfg.Failover.QualitySweepMinutes) * time.Minute
	logf("quality sweep: включён, интервал %s, порт %d", every, port)
	// startupProfiles is captured here, synchronously, rather than closed
	// over as cfg.Profiles inside the goroutine below: cfg is the same
	// *config.Config the daemon and (when enabled) the bot handler hold,
	// and reading cfg.Profiles from this goroutine on every config.Load
	// failure would race a concurrent bot-triggered mutation or
	// Daemon.ReloadConfig (CFG-01). A startup snapshot is fine here --
	// this only ever backs the rare "couldn't reload from disk" fallback.
	startupProfiles := cfg.Profiles
	go sw.Run(ctx, func() []config.Profile {
		fresh, err := config.Load(configPath())
		if err != nil {
			return startupProfiles
		}
		return fresh.Profiles
	}, every)
}
