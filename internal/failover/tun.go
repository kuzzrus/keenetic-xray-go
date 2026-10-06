package failover

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// The TUN inbound lives inside the production xray process -- one pass for
// every packet, no second process, and the same outbound the SOCKS and WG
// inbounds use. The price is that an inbound xray cannot bring up (the
// device is busy, /dev/net/tun is gone, the installed core is too old to
// know the protocol) makes xray exit on startup, and the supervisor, which
// restarts it with backoff for as long as it keeps dying, turns that into a
// crash loop that takes SOCKS, HTTP, the WG transport and the failover
// probes down with it. Nothing about an optional transport is worth that,
// so there is a breaker: production crashing tunCrashLimit times within
// tunCrashWindow of a config that carried the inbound gets the inbound
// taken out again, and it stays out for tunRetryAfter (or until the
// operator changes the transport, or the daemon restarts).
const (
	tunCrashLimit  = 3
	tunCrashWindow = 90 * time.Second
	tunRetryAfter  = 30 * time.Minute
)

// tunDevicePresent reports whether the kernel device ndm made for the
// OpkgTun interface exists. A var so tests can stand in for /sys.
//
// It matters because an inbound naming a device that is not there does not
// fail: TUNSETIFF creates a fresh, transient one, which nothing routes
// into and ndm knows nothing about -- a transport that looks up and carries
// nothing. The inbound is only written once ndm's own device exists.
var tunDevicePresent = func(dev string) bool {
	_, err := os.Stat("/sys/class/net/" + dev)
	return err == nil
}

// tunInboundOpts builds the xray `tun` inbound options from the TUN
// transport config, or nil when it is off, when the interface isn't pinned
// yet or its kernel device isn't there, or while the breaker keeps it out.
// The pretest instance never gets one.
func (a *realActions) tunInboundOpts() *config.TunInboundOptions {
	t := a.cfg.TunTransport
	if !t.Enabled {
		return nil
	}
	dev := t.DeviceName()
	if dev == "" || !tunDevicePresent(dev) {
		return nil
	}
	if at := a.tunTrippedAt.Load(); at != 0 && time.Since(time.Unix(0, at)) < tunRetryAfter {
		return nil
	}
	return &config.TunInboundOptions{Name: dev, MTU: t.TunMTU()}
}

// noteTunWritten records that a production config was just written, with or
// without the TUN inbound. Starting a fresh crash count here is what ties
// "xray crashed" to "right after this config".
func (a *realActions) noteTunWritten(live bool) {
	a.tunLive.Store(live)
	a.tunWrittenAt.Store(time.Now().UnixNano())
	a.tunCrashes.Store(0)
	if live {
		a.tunTrippedAt.Store(0) // the retry window is over, or it never started
	}
}

// noteTunCrash is the breaker. Called from the production Supervisor's
// goroutine on every crash-triggered restart (via noteXrayCrash), so it
// must return at once: taking the inbound out restarts production, and
// Supervisor.Stop waits for the very goroutine that is calling here.
func (d *Daemon) noteTunCrash() {
	a := d.actions
	if !a.tunLive.Load() || time.Since(time.Unix(0, a.tunWrittenAt.Load())) > tunCrashWindow {
		return // crashes long after the write are xray's own business
	}
	if int(a.tunCrashes.Add(1)) < tunCrashLimit {
		return
	}
	if !a.tunTrippedAt.CompareAndSwap(0, time.Now().UnixNano()) {
		return
	}
	go d.dropTunInbound()
}

// dropTunInbound regenerates the production config without the inbound --
// tunInboundOpts now answers nil -- and tells the operator.
func (d *Daemon) dropTunInbound() {
	detail := fmt.Sprintf("xray падал %d раза подряд сразу после добавления TUN-inbound — снял его, прокси работает без TUN-транспорта (повторю через %s; сразу — transport tun off, потом on)",
		tunCrashLimit, shortWindow(tunRetryAfter))
	fmt.Printf("failover: %s\n", detail)
	d.emit(Event{At: time.Now(), Kind: EventTunSuspended, Detail: detail})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d.do(ctx, func(ctx context.Context) {
		if d.cfg.Primary() != nil {
			_ = d.actions.SwitchLiveTo(ctx, d.actions.liveRole)
		}
	})
}

// TunInboundLive reports whether the production config last written carries
// the TUN inbound. Safe to call from any goroutine.
func (d *Daemon) TunInboundLive() bool { return d.actions.tunLive.Load() }

// RefreshTunInbound regenerates the production config on the role it is
// already on when the TUN inbound it should carry is not the one it has:
// the OpkgTun device appeared after xray started without the inbound (boot
// order, the interface re-created by the reconcile loop, the breaker's
// retry window running out), or it went away from under a running one. A
// no-op unless production is running and the two disagree. Reports whether
// it restarted xray.
func (d *Daemon) RefreshTunInbound(ctx context.Context) bool {
	var changed bool
	d.do(ctx, func(ctx context.Context) {
		if !d.actions.prod.Running() {
			return
		}
		if (d.actions.tunInboundOpts() != nil) == d.actions.tunLive.Load() {
			return
		}
		changed = d.actions.SwitchLiveTo(ctx, d.actions.liveRole) == nil
	})
	return changed
}
