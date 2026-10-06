package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
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
	case "mtu":
		return tunTransportMTU(cfg, args[1:])
	default:
		return fmt.Errorf("usage: keenetic-xray transport tun {show|on|off|mtu [<1280..1500>|auto]}")
	}
}

// tunMTUMin / tunMTUMax bound `transport tun mtu`: the same range
// config.TunTransportConfig.validate accepts.
const (
	tunMTUMin = 1280
	tunMTUMax = 1500
)

// tunTransportMTU is `transport tun mtu [<1280..1500>|auto]`: show or set the
// MTU of the OpkgTun interface and of xray's tun inbound. They always follow
// the one setting -- xray sets the device's MTU itself every time it starts,
// so the interface (`ip mtu`, which also drives the MSS clamp NDM applies to
// forwarded SYNs) and the inbound must never disagree. A bigger MTU means
// fewer packets for the userspace stack to chew through, which is what limits
// the throughput (docs/routing.md). `auto` is the default (1280).
func tunTransportMTU(cfg *config.Config, args []string) error {
	usage := fmt.Errorf("usage: keenetic-xray transport tun mtu [<%d..%d>|auto]", tunMTUMin, tunMTUMax)
	if len(args) == 0 {
		note := ""
		if cfg.TunTransport.MTU == 0 {
			note = " (по умолчанию)"
		}
		fmt.Printf("MTU TUN-транспорта: %d%s; допустимо %d..%d\n", cfg.TunTransport.TunMTU(), note, tunMTUMin, tunMTUMax)
		return nil
	}
	if len(args) != 1 {
		return usage
	}
	v := 0
	if a := strings.ToLower(args[0]); a != "auto" && a != "default" {
		n, err := strconv.Atoi(a)
		if err != nil || n < tunMTUMin || n > tunMTUMax {
			return usage
		}
		v = n
	}
	cfg.TunTransport.MTU = v

	live := cfg.TunTransport.Enabled && cfg.TunTransport.Iface != "" && keenetic.Available()
	if live {
		// The interface first: its `ip mtu` moves now, xray's follows when
		// the daemon restarts it with the new config a moment later.
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := keenetic.ApplyTunTransport(ctx, tunSpec(cfg)); err != nil {
			return err
		}
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("MTU TUN-транспорта: %d\n", cfg.TunTransport.TunMTU())
	if !live {
		fmt.Println("сохранено — применится, когда TUN-транспорт будет включён")
		return nil
	}
	fmt.Println("xray перезапускается с новым MTU (на пару секунд прокси недоступен)")
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
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

// checkXrayKnowsTun asks the installed xray-core whether it knows the `tun`
// inbound (xrayctl.CheckTunSupport: `xray run -test`, nothing started, no
// device opened).
func checkXrayKnowsTun(ctx context.Context, mtu int) error {
	if err := xrayctl.CheckTunSupport(ctx, xrayBinaryPath(), mtu); err != nil {
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
			keenetic.WaitTunCarrierGone(ctx, iface, 20*time.Second)
		}
		if err := keenetic.ClearTunTransport(ctx); err != nil {
			fmt.Printf("предупреждение: не удалось убрать интерфейс: %v\n", err)
		}
	}
	fmt.Println("TUN-транспорт выключен (интерфейс снят; xray перестраивается без tun-inbound)")
	return nil
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
	// While the gate holds the interface down on purpose, being down is not
	// drift and must not be "repaired" -- that would reopen a closed gate.
	check := keenetic.TunTransportIntact
	if tunGate != nil && tunGate.Closed() {
		check = keenetic.TunTransportPresent
	}
	ok, why, err := check(ctx, iface)
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
