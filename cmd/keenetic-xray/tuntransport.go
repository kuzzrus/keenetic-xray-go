package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// transportTun is `keenetic-xray transport tun {show|on|off}` -- a Keenetic
// OpkgTun interface backed by xray's own `tun` inbound, the third way
// selected traffic reaches the tunnel next to Proxy0 and the WG transport.
// What sets it apart: the interface only has carrier while xray holds the
// device, and Keenetic withdraws every `auto` route through it within about
// a second of that ending -- so listed traffic falls back to the ISP by
// itself while xray is down, no health check needed.
func transportTun(cfg *config.Config, args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		printTransport(cfg)
		if keenetic.Available() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if live, err := keenetic.ShowTunTransport(ctx, cfg.TunTransport.Iface); err == nil && live != "" {
				fmt.Println("---\n" + live)
				if cfg.TunTransport.Enabled && cfg.TunTransport.Iface != "" {
					if l, err := keenetic.TunLinkState(ctx, cfg.TunTransport.Iface); err == nil && !l.CarrierUp() {
						fmt.Println("xray не держит устройство: демон не запущен, или tun-inbound снят (см. логи демона)")
					}
				}
			}
		}
		return nil
	case "on":
		return tunTransportOn(cfg)
	case "off":
		return tunTransportOff(cfg)
	default:
		return fmt.Errorf("usage: keenetic-xray transport tun {show|on|off}")
	}
}

func tunTransportOn(cfg *config.Config) error {
	if err := tunTransportApply(cfg); err != nil {
		return err
	}
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

// tunTransportApply stands up the OpkgTun interface and saves the config,
// but does NOT touch the daemon -- the setup wizard calls this so it can
// apply the daemon change once at the end instead of twice.
func tunTransportApply(cfg *config.Config) error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — TUN-транспорт работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Before the router is touched: an xray-core from before the `tun`
	// inbound existed would refuse the whole production config.
	if err := checkXrayKnowsTun(ctx, cfg.TunTransport.TunMTU()); err != nil {
		return err
	}

	if cfg.TunTransport.Iface == "" {
		iface, err := keenetic.FreeOpkgTunIface(ctx)
		if err != nil {
			return err
		}
		cfg.TunTransport.Iface = iface
		fmt.Printf("выбран свободный интерфейс: %s\n", iface)
	}
	spec := tunSpec(cfg)
	fmt.Printf("настраиваю %s (устройство %s) …\n", spec.Iface, keenetic.TunDeviceName(spec.Iface))
	if err := keenetic.ApplyTunTransport(ctx, spec); err != nil {
		return err
	}

	cfg.TunTransport.Enabled = true
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("TUN-транспорт включён: %s (MTU %d); xray подхватит устройство, когда демон перечитает конфиг\n", spec.Iface, spec.MTU)
	fmt.Printf("заворачивай трафик: keenetic-xray routes set <список> --iface=%s (или политикой Keenetic)\n", spec.Iface)
	fmt.Println("пока xray не работает, маршруты в этот интерфейс сами снимаются и трафик идёт напрямую")
	return nil
}

// tunProbeDevice is the device name the support check puts in its config:
// one that can be no ndm interface and no operator's, so the check can never
// reach a real device. (xray opens the device in Handler.Start, which
// `-test` never reaches -- this is for a future core that does it earlier.)
const tunProbeDevice = "kxtunprobe"

// checkXrayKnowsTun asks the installed xray-core to build a config holding
// only a `tun` inbound (`xray run -test`: nothing is started, no device is
// opened).
func checkXrayKnowsTun(ctx context.Context, mtu int) error {
	data, err := config.TunSupportProbeConfig(config.TunInboundOptions{Name: tunProbeDevice, MTU: mtu})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "keenetic-xray-tun-probe-*.json")
	if err != nil {
		return fmt.Errorf("временный файл для проверки xray: %w", err)
	}
	defer os.Remove(f.Name())
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("временный файл для проверки xray: %w", werr)
	}
	if err := xrayctl.ValidateConfig(ctx, xrayBinaryPath(), f.Name(), nil); err != nil {
		return fmt.Errorf("установленный xray-core не принимает tun-inbound (нужна свежая сборка, v26.x): %w", err)
	}
	return nil
}

// checkTunTransport is doctor's block for the TUN transport: silent while
// it's off or off a router. Carrier is the one thing the CLI can read of the
// daemon's xray -- it is up exactly while xray holds the device, i.e. while
// the running xray carries the tun inbound.
func checkTunTransport(cfg *config.Config, check func(bool, string)) {
	t := cfg.TunTransport
	if !t.Enabled || !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if t.Iface == "" {
		check(false, "tun-transport is on but no OpkgTun interface is created -- run: keenetic-xray transport tun on")
		return
	}
	ok, why, err := keenetic.TunTransportIntact(ctx, t.Iface)
	switch {
	case err != nil:
		check(false, fmt.Sprintf("tun-transport %s: could not read it: %v", t.Iface, err))
		return
	case !ok:
		check(false, fmt.Sprintf("tun-transport %s: %s -- the daemon rebuilds it within 2 minutes, or: keenetic-xray transport tun on", t.Iface, why))
		return
	}
	check(true, fmt.Sprintf("tun-transport %s in place (device %s)", t.Iface, t.DeviceName()))
	if l, err := keenetic.TunLinkState(ctx, t.Iface); err == nil {
		check(l.CarrierUp(), fmt.Sprintf("xray holds %s -- without it listed traffic goes straight to the ISP (by design; the daemon logs why the tun inbound is missing)", t.DeviceName()))
	}
	if c, ok := keenetic.ReadTunCounts(t.DeviceName()); ok {
		fmt.Printf("[info]  %s: %s\n", t.DeviceName(), c.Summary())
	}
}

// tunTransportOff takes the interface down in the order that never pulls
// the device out from under xray: the config first (so the daemon restarts
// xray without the inbound), then a wait for xray to let go, then the
// interface itself.
func tunTransportOff(cfg *config.Config) error {
	iface := cfg.TunTransport.Iface
	if lists := tunRouteLists(cfg, iface); len(lists) > 0 {
		fmt.Printf("внимание: списки маршрутов %s смотрят на %s — после снятия интерфейса они не будут работать; перенацель их (routes set <список> --iface=...)\n",
			strings.Join(lists, ", "), iface)
	}
	cfg.TunTransport.Enabled = false
	// Pinned only while enabled: the next `on` picks the lowest free one
	// again, so an interface the operator makes by hand in the meantime
	// is never in the way.
	cfg.TunTransport.Iface = ""
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	applyDaemonChange(bufio.NewReader(os.Stdin), true)

	if keenetic.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if iface != "" {
			waitTunCarrierGone(ctx, iface, 20*time.Second)
		}
		if err := keenetic.ClearTunTransport(ctx); err != nil {
			fmt.Printf("предупреждение: не удалось убрать интерфейс: %v\n", err)
		}
	}
	fmt.Println("TUN-транспорт выключен (интерфейс снят; xray перестраивается без tun-inbound)")
	return nil
}

// waitTunCarrierGone waits until nothing holds the TUN device any more --
// xray was restarted without the inbound, or is not running at all -- up
// to limit. Removing the interface anyway after that is the right call:
// the operator asked for it off.
func waitTunCarrierGone(ctx context.Context, iface string, limit time.Duration) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		l, err := keenetic.TunLinkState(ctx, iface)
		if err != nil || !l.CarrierUp() {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// tunRouteLists names the route lists that target iface.
func tunRouteLists(cfg *config.Config, iface string) []string {
	if iface == "" {
		return nil
	}
	var names []string
	for _, l := range cfg.Routing.Lists {
		if l.Interface == iface {
			names = append(names, l.Name)
		}
	}
	return names
}

func tunSpec(cfg *config.Config) keenetic.TunTransportSpec {
	t := cfg.TunTransport
	return keenetic.TunTransportSpec{Iface: t.Iface, Address: t.TunAddr(), MTU: t.TunMTU()}
}

// ensureTunTransport brings the OpkgTun interface back when it is missing,
// down, or lost its device -- best-effort and non-fatal, like every other
// router-side step the daemon takes at startup and on each reconcile tick
// (see reconcileTunTransport). An interface that is in place is left
// alone, with no flash write. The healthy path is a running-config and a
// `show interface` read.
func ensureTunTransport(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	iface := cfg.TunTransport.Iface
	ok, why, err := keenetic.TunTransportIntact(ctx, iface)
	if err != nil {
		logf("tun-transport: could not read %s: %v", iface, err)
		return
	}
	if ok {
		return
	}
	logf("tun-transport: %s needs rebuilding: %s", iface, why)
	if err := keenetic.ApplyTunTransport(ctx, tunSpec(cfg)); err != nil {
		logf("tun-transport: apply failed: %v", err)
		return
	}
	logf("tun-transport: %s re-asserted (device %s)", iface, keenetic.TunDeviceName(iface))
}
