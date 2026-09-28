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
// alone after the router refused part of it. An attempt that gets past
// the initial reads writes several ndmc commands and a `system
// configuration save` -- a flash write -- so a failure that will only
// repeat (a firmware whose `show ping-check` the parser misreads, say)
// must not run on every reconcileInterval tick. Daemon startup and the
// CLI always try regardless.
const proxy0HealthRetryAfter = time.Hour

// proxy0HealthRetryMin and proxy0HealthRetryMax pace the retries after a
// failure the router may get over by itself (keenetic.Transient): 5s,
// 10s, 20s, 40s, then once a minute until it takes. Every failure used to
// wait the full hour (2026-09-27 external review, BOOT-05) -- and the
// likeliest time for a transient one is boot, with ndm busy and several
// startup steps saving at once, when Proxy0 needs its ISP fallback most.
// Vars so tests can shrink them.
var (
	proxy0HealthRetryMin = 5 * time.Second
	proxy0HealthRetryMax = time.Minute
)

// proxy0HealthAttemptTimeout bounds one attempt: a few reads, a few
// writes and a save, each normally well under a second. Every attempt
// gets its own -- it used to share one with the Proxy0 configuration
// before it, and a slow configuration left it nothing.
const proxy0HealthAttemptTimeout = 30 * time.Second

// proxy0HealthState is what the daemon remembers between attempts at
// installing the check. Shared by the startup path, the reconcile
// goroutine and the retrier, hence the mutex.
type proxy0HealthState struct {
	mu          sync.Mutex
	osOK        bool      // firmware already confirmed new enough, skip `show version`
	unsupported bool      // KeeneticOS < 4.0: no `mode tls`, never try again this run
	failedAt    time.Time // last attempt the router refused, for proxy0HealthRetryAfter
	retrying    bool      // retryProxy0HealthCheck is running; reconcile keeps out of its way
	unsaved     bool      // an attempt changed the check and may not have saved it
	lastErr     string    // last failure logged: a retry failing the same way stays quiet
}

var proxy0Health proxy0HealthState

// due reports whether reconcile should attempt the check at now.
func (s *proxy0HealthState) due(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unsupported || s.retrying {
		return false
	}
	return s.failedAt.IsZero() || now.Sub(s.failedAt) >= proxy0HealthRetryAfter
}

// failed records a failed attempt and logs it, unless the last one
// failed the same way. changed is EnsureProxy0HealthCheck's: the router
// may be left with the check in place but unsaved, and the next attempt
// then finds nothing to change -- so it has to save regardless. Reports
// whether to retry soon; otherwise reconcile waits proxy0HealthRetryAfter.
func (s *proxy0HealthState) failed(now time.Time, err error, changed bool, logf func(string, ...any)) (retrySoon bool) {
	retrySoon = keenetic.Transient(err)
	s.mu.Lock()
	if changed {
		s.unsaved = true
	}
	s.failedAt = now
	if retrySoon {
		s.failedAt = time.Time{}
	}
	repeat := s.lastErr == err.Error()
	s.lastErr = err.Error()
	s.mu.Unlock()
	switch {
	case repeat:
	case retrySoon:
		logf("proxy0: health check not installed yet: %v (retrying shortly)", err)
	default:
		logf("proxy0: health check not installed: %v (next try in %s, or on restart)", err, proxy0HealthRetryAfter)
	}
	return retrySoon
}

// succeeded clears what failed recorded, reporting whether the last
// attempt had failed.
func (s *proxy0HealthState) succeeded() (recovered bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recovered = s.lastErr != ""
	s.failedAt, s.unsaved, s.lastErr = time.Time{}, false, ""
	return recovered
}

func (s *proxy0HealthState) needsSave() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unsaved
}

// startRetry runs retry in the background unless a retrier already
// runs; due keeps reconcile out of its way meanwhile.
func (s *proxy0HealthState) startRetry(retry func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.retrying {
		return
	}
	s.retrying = true
	go func() {
		defer func() {
			s.mu.Lock()
			s.retrying = false
			s.mu.Unlock()
		}()
		retry()
	}()
}

// retryProxy0HealthCheck repeats attempt -- after proxy0HealthRetryMin,
// doubling up to proxy0HealthRetryMax, then at that pace -- for as long
// as it asks to be retried soon and ctx lives. An attempt that succeeds,
// or fails in a way that won't go away by itself, ends it; reconcile
// takes over from there.
func retryProxy0HealthCheck(ctx context.Context, attempt func(context.Context) (retrySoon bool)) {
	for wait := proxy0HealthRetryMin; ; wait = min(wait*2, proxy0HealthRetryMax) {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if !attempt(ctx) {
			return
		}
	}
}

// ensureProxy0HealthCheck is one daemon attempt, followed by quick
// retries in the background if it failed in a way the router may get
// over by itself. Each retry reloads the config, so a change made in the
// meantime -- `proxy0 set --health-check=off`, say -- is respected.
func ensureProxy0HealthCheck(ctx context.Context, cfg *config.Config, logf func(string, ...any), fromReconcile bool) {
	if !applyProxy0HealthCheck(ctx, cfg, logf, fromReconcile) {
		return
	}
	proxy0Health.startRetry(func() {
		retryProxy0HealthCheck(ctx, func(ctx context.Context) bool {
			fresh, err := config.Load(configPath())
			if err != nil {
				return true
			}
			return applyProxy0HealthCheck(ctx, fresh, logf, false)
		})
	})
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

// proxy0InUse reports whether the Proxy interface cfg names exists on the
// router and points at this project's inbound -- the condition under
// which a dead xray black-holes whatever is routed through it, and so
// the condition for needing the health check.
//
// Deliberately not cfg.Proxy0.Enabled. That flag only says whether the
// daemon manages the upstream, and the setup wizard's WG-transport and
// "leave Keenetic alone" choices, `install.sh --no-proxy0` and `proxy0
// off` all clear it without the interface necessarily going away.
// Confirmed on a real router (2026-09-27): proxy0.enabled false, Proxy0
// up at 192.168.1.1:10081 with twenty object-groups routed through it --
// exactly the setup that took the network down when the USB failed to
// mount, and one the first version of this check would have skipped.
func proxy0InUse(ctx context.Context, cfg *config.Config) (bool, error) {
	_, port, ok, err := keenetic.Proxy0Upstream(ctx, cfg.Proxy0.Interface)
	if err != nil {
		return false, err
	}
	return ok && port == cfg.Proxy0Port(), nil
}

// proxy0PointsHere is proxy0InUse as the daemon's failover hook
// (Daemon.SetProxyInUse): bounded, and false off a Keenetic router. It
// runs on the failover goroutine, so it must not hang.
func proxy0PointsHere(ctx context.Context, cfg *config.Config) (bool, error) {
	if !keenetic.Available() {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return proxy0InUse(ctx, cfg)
}

// applyProxy0HealthCheck brings the Keenetic-side health check on the
// Proxy interface in line with cfg: installed and bound whenever the
// interface is in use (proxy0InUse), removed when
// proxy0.disable_health_check is set. Quiet whenever nothing changes,
// since reconcile calls it every tick. fromReconcile honours the backoff
// after a failure; startup and the CLI always try. One attempt, under
// its own proxy0HealthAttemptTimeout; reports whether it failed in a way
// worth retrying soon (see ensureProxy0HealthCheck, which does). See
// keenetic.HealthCheckProfile for what the check does and why.
func applyProxy0HealthCheck(ctx context.Context, cfg *config.Config, logf func(string, ...any), fromReconcile bool) (retrySoon bool) {
	iface := cfg.Proxy0.IfaceName()
	ctx, cancel := context.WithTimeout(ctx, proxy0HealthAttemptTimeout)
	defer cancel()

	if cfg.Proxy0.DisableHealthCheck {
		removed, err := keenetic.RemoveHealthCheck(ctx)
		switch {
		case err != nil:
			logf("proxy0: could not remove the health check (disabled in config): %v", err)
		case removed:
			logf("proxy0: health check removed (disabled in config) -- listed traffic through %s has no ISP fallback while xray is down", iface)
		}
		return false
	}

	now := time.Now()
	if fromReconcile && !proxy0Health.due(now) {
		return false
	}
	inUse, err := proxy0InUse(ctx, cfg)
	if err != nil {
		return proxy0Health.failed(now, fmt.Errorf("reading %s: %w", iface, err), false, logf)
	}
	if !inUse {
		return false
	}
	if ok, first := proxy0Health.firmwareOK(ctx); !ok {
		if first {
			logf("proxy0: KeeneticOS older than 4.0 has no TLS ping-check -- listed traffic through %s can't fall back to the ISP while xray is down", iface)
		}
		return false
	}
	changed, err := keenetic.EnsureProxy0HealthCheck(ctx, iface)
	saved := false
	if err == nil && !changed && proxy0Health.needsSave() {
		err, saved = keenetic.SaveConfig(ctx), true
	}
	if err != nil {
		return proxy0Health.failed(now, err, changed, logf)
	}
	recovered := proxy0Health.succeeded()
	switch {
	case changed:
		logf("proxy0: health check %q (%s) bound to %s -- listed traffic falls back to the ISP while xray is down",
			keenetic.HealthCheckProfile, keenetic.HealthCheckSummary(), iface)
	case saved:
		logf("proxy0: health check %q on %s saved -- it survives a reboot now", keenetic.HealthCheckProfile, iface)
	case recovered:
		logf("proxy0: health check %q on %s is in place", keenetic.HealthCheckProfile, iface)
	}
	return false
}

// purgeProxy0 is prerm --purge's share of the Proxy interface. Nothing
// used to touch it there, so after a purge it stayed up pointing at an
// inbound that no longer existed -- and every route the operator still
// sent through it black-holed. It goes down first when it is ours (by
// proxy0InUse, not proxy0.enabled -- same reasoning), and the health
// check is removed only after that, because the check is exactly what
// keeps a Proxy interface that is still up from black-holing. Never
// leave one up without the other.
func purgeProxy0(ctx context.Context) {
	cfg, err := config.Load(configPath())
	if err != nil {
		fmt.Println("warning: could not read the config, leaving the Proxy interface and its health check as they are:", err)
		return
	}
	inUse, err := proxy0InUse(ctx, cfg)
	if err != nil {
		fmt.Println("warning: could not read the Proxy interface, leaving it and its health check as they are:", err)
		return
	}
	if inUse {
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

// checkProxy0Health is doctor's line for the health check. Silent when
// the Proxy interface is not in use -- there is nothing to protect.
func checkProxy0Health(cfg *config.Config, check func(bool, string)) {
	if !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if inUse, err := proxy0InUse(ctx, cfg); err != nil || !inUse {
		return
	}
	check(proxy0HealthLine(ctx, cfg))
}

// proxy0HealthLine renders the check's live state as doctor's (ok, msg)
// pair; `proxy0 show` prints the same message. Assumes the interface is
// in use.
func proxy0HealthLine(ctx context.Context, cfg *config.Config) (bool, string) {
	iface := cfg.Proxy0.IfaceName()
	if cfg.Proxy0.DisableHealthCheck {
		return true, fmt.Sprintf("%s health check disabled in config -- listed traffic has no ISP fallback while xray is down", iface)
	}
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
