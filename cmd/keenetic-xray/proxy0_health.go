package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// proxy0HealthRetryAfter is how long reconcile leaves the health check
// alone after an attempt to install it failed. An attempt that gets past
// the initial read writes several ndmc commands and a `system
// configuration save` -- a flash write -- so a failure that persists (a
// firmware whose `show ping-check` the parser misreads, say) must not
// repeat on every reconcileInterval tick. Daemon startup and the CLI
// always try regardless.
const proxy0HealthRetryAfter = time.Hour

// proxy0HealthState is what the daemon remembers between reconcile ticks
// about installing the check. Shared by the startup path and the
// reconcile goroutine, hence the mutex.
type proxy0HealthState struct {
	mu          sync.Mutex
	osOK        bool      // firmware already confirmed new enough, skip `show version`
	unsupported bool      // KeeneticOS < 4.0: no `mode tls`, never try again this run
	failedAt    time.Time // last failed attempt, for proxy0HealthRetryAfter
}

var proxy0Health proxy0HealthState

// due reports whether reconcile should attempt the check at now.
func (s *proxy0HealthState) due(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsupported {
		return false
	}
	return s.failedAt.IsZero() || now.Sub(s.failedAt) >= proxy0HealthRetryAfter
}

func (s *proxy0HealthState) setFailed(at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedAt = at
}

// firmwareOK reports whether this firmware can run the TLS check,
// asking the router only until the answer is known. ok is true when it
// can, or when the version could not be read at all -- keenetic.
// EnsureProxy0HealthCheck is itself safe on firmware without tls, so an
// unreadable version is no reason to give up. first is true exactly once,
// on the call that found the firmware too old, so the caller logs it once.
func (s *proxy0HealthState) firmwareOK(ctx context.Context) (ok, first bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.unsupported:
		return false, false
	case s.osOK:
		return true, false
	}
	atLeast, err := keenetic.OSAtLeast(ctx, 4, 0)
	if err != nil {
		return true, false
	}
	if !atLeast {
		s.unsupported = true
		return false, true
	}
	s.osOK = true
	return true, false
}

// applyProxy0HealthCheck brings the Keenetic-side health check on the
// Proxy interface in line with cfg: installed and bound by default,
// removed when proxy0.disable_health_check is set. Quiet whenever nothing
// changes, since reconcile calls it every tick. fromReconcile honours
// proxy0HealthRetryAfter after a failure; startup and the CLI always try.
// See keenetic.HealthCheckProfile for what the check does and why.
func applyProxy0HealthCheck(ctx context.Context, cfg *config.Config, logf func(string, ...any), fromReconcile bool) {
	if !cfg.Proxy0.Enabled {
		return
	}
	iface := cfg.Proxy0.IfaceName()

	if cfg.Proxy0.DisableHealthCheck {
		removed, err := keenetic.RemoveHealthCheck(ctx)
		switch {
		case err != nil:
			logf("proxy0: could not remove the health check (disabled in config): %v", err)
		case removed:
			logf("proxy0: health check removed (disabled in config) -- listed traffic through %s has no ISP fallback while xray is down", iface)
		}
		return
	}

	now := time.Now()
	if fromReconcile && !proxy0Health.due(now) {
		return
	}
	if ok, first := proxy0Health.firmwareOK(ctx); !ok {
		if first {
			logf("proxy0: KeeneticOS older than 4.0 has no TLS ping-check -- listed traffic through %s can't fall back to the ISP while xray is down", iface)
		}
		return
	}
	changed, err := keenetic.EnsureProxy0HealthCheck(ctx, iface)
	if err != nil {
		proxy0Health.setFailed(now)
		logf("proxy0: health check not installed: %v (next try in %s, or on restart)", err, proxy0HealthRetryAfter)
		return
	}
	proxy0Health.setFailed(time.Time{})
	if changed {
		logf("proxy0: health check %q (%s) bound to %s -- listed traffic falls back to the ISP while xray is down",
			keenetic.HealthCheckProfile, keenetic.HealthCheckSummary(), iface)
	}
}

// purgeProxy0 is prerm --purge's share of the Proxy interface. Nothing
// used to touch it there, so after a purge it stayed up pointing at an
// inbound that no longer existed -- and every route the operator still
// sent through it black-holed. It goes down first; the health check is
// removed only once it is, because the check is exactly what keeps a
// Proxy interface that is still up from black-holing. Never leave one up
// without the other.
func purgeProxy0(ctx context.Context) {
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Println("warning: could not read the config, leaving the Proxy interface and its health check as they are:", err)
		return
	}
	if cfg.Proxy0.Enabled {
		if err := keenetic.DisableProxy0(ctx, cfg.Proxy0.Interface); err != nil {
			fmt.Printf("warning: could not bring %s down, keeping its health check so it can still fall back to the ISP: %v\n",
				cfg.Proxy0.IfaceName(), err)
			return
		}
	}
	if _, err := keenetic.RemoveHealthCheck(ctx); err != nil {
		fmt.Println("warning: could not remove the Proxy health check:", err)
	}
}

// checkProxy0Health is doctor's line for the health check.
func checkProxy0Health(cfg *config.Config, check func(bool, string)) {
	iface := cfg.Proxy0.IfaceName()
	if cfg.Proxy0.DisableHealthCheck {
		check(true, fmt.Sprintf("%s health check disabled in config -- listed traffic has no ISP fallback while xray is down", iface))
		return
	}
	if !keenetic.Available() {
		return // checkProxy0 already reported this
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	check(proxy0HealthLine(ctx, iface))
}

// proxy0HealthLine renders the check's live state as doctor's (ok, msg)
// pair; `proxy0 show` prints the same message.
func proxy0HealthLine(ctx context.Context, iface string) (bool, string) {
	hc, ok, err := keenetic.Proxy0HealthCheck(ctx)
	if err != nil {
		return false, fmt.Sprintf("%s health check: could not read `show ping-check`: %v", iface, err)
	}
	b := hc.BoundTo(iface)
	if !ok || b == nil {
		return false, fmt.Sprintf("%s has no health check -- without it listed traffic black-holes while xray is down; restart the daemon or run: keenetic-xray proxy0 set", iface)
	}
	if hc.Mode != "tls" {
		return false, fmt.Sprintf("%s health check %q is in %s mode, which can't see a dead xray -- restart the daemon to fix it", iface, hc.Name, hc.Mode)
	}
	layer, _ := keenetic.ProxyIPLayer(ctx, iface)
	if b.Status == "pass" {
		return true, fmt.Sprintf("%s health check (%s %s:%d): pass, ipv4 %s", iface, hc.Mode, hc.Host, hc.Port, layer)
	}
	return false, fmt.Sprintf("%s health check (%s %s:%d): %s, ipv4 %s -- xray unreachable through %s, so listed traffic is going straight to the ISP (normal for ~30s after a restart)",
		iface, hc.Mode, hc.Host, hc.Port, b.Status, layer, iface)
}
