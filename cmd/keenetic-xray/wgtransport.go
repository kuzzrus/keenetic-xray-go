package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// transportWG is `keenetic-xray transport wg {show|on|off}` -- the
// in-router WireGuard carrier from Keenetic into the local xray
// `wireguard` inbound, an alternative router->xray hop to Proxy0/SOCKS.
func transportWG(cfg *config.Config, args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		printTransport(cfg)
		if keenetic.Available() && cfg.WGTransport.Iface != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if live, err := keenetic.ShowWGTransport(ctx, cfg.WGTransport.Iface); err == nil && live != "" {
				fmt.Println("---\n" + live)
			}
		}
		return nil
	case "on":
		return wgTransportOn(cfg)
	case "off":
		return wgTransportOff(cfg)
	default:
		return fmt.Errorf("usage: keenetic-xray transport wg {show|on|off}")
	}
}

func wgTransportOn(cfg *config.Config) error {
	if err := wgTransportApply(cfg); err != nil {
		return err
	}
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

// wgTransportApply reconciles the in-router WG transport and saves the
// config, but does NOT touch the daemon -- the setup wizard calls this
// so it can apply the daemon change once at the end instead of twice.
func wgTransportApply(cfg *config.Config) error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — WG-транспорт работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if _, err := cfg.WGTransport.EnsureKeys(); err != nil {
		return err
	}

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		return fmt.Errorf("определение LAN IP роутера: %w (задай proxy0 --lan-ip=)", err)
	}

	if cfg.WGTransport.Iface == "" {
		iface, err := keenetic.FreeWireguardIface(ctx)
		if err != nil {
			return err
		}
		cfg.WGTransport.Iface = iface
		fmt.Printf("выбран свободный интерфейс: %s\n", iface)
	}

	spec := wgSpec(cfg, ip)
	fmt.Printf("настраиваю %s → xray wg-inbound %s …\n", spec.Iface, spec.Endpoint)
	kpub, err := keenetic.ApplyWGTransport(ctx, spec)
	if err != nil {
		return err
	}

	cfg.WGTransport.Enabled = true
	cfg.WGTransport.KeeneticPublicKey = kpub
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("WG-транспорт включён: %s (MTU %d), xray слушает :%d\n", spec.Iface, spec.MTU, cfg.WGTransport.WGPort())
	fmt.Printf("заворачивай трафик: keenetic-xray routes set <список> --iface=%s (или политикой Keenetic)\n", spec.Iface)
	return nil
}

func wgTransportOff(cfg *config.Config) error {
	if keenetic.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := keenetic.ClearWGTransport(ctx); err != nil {
			fmt.Printf("предупреждение: не удалось убрать интерфейс: %v\n", err)
		}
	}
	cfg.WGTransport.Enabled = false
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("WG-транспорт выключен (интерфейс снят; xray перестраивается без wg-inbound)")
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

func wgSpec(cfg *config.Config, lanIP string) keenetic.WGTransportSpec {
	w := cfg.WGTransport
	return keenetic.WGTransportSpec{
		Iface:      w.Iface,
		Address:    w.WGAddr(),
		MTU:        w.WGMTU(),
		PeerPubKey: w.XrayPublicKey,
		PeerPSK:    w.PSK,
		Endpoint:   net.JoinHostPort(lanIP, strconv.Itoa(w.WGPort())),
		Keepalive:  25,
	}
}

// applyWGTransportAtStartup re-asserts the Keenetic WireGuard interface
// when the daemon starts, so a firmware event that dropped or
// regenerated it self-heals -- same best-effort, non-fatal pattern as
// applyProxy0AtStartup / applyRoutesAtStartup. If the router generated a
// fresh keypair, the new public key is persisted so the next xray config
// render picks it up.
func applyWGTransportAtStartup(cfg *config.Config, logf func(string, ...any)) {
	if !cfg.WGTransport.Enabled || cfg.WGTransport.Iface == "" || !keenetic.Available() {
		return
	}
	if _, err := cfg.WGTransport.EnsureKeys(); err != nil {
		logf("wg-transport: key generation failed: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		logf("wg-transport: LAN IP detection failed: %v", err)
		return
	}
	kpub, err := keenetic.ApplyWGTransport(ctx, wgSpec(cfg, ip))
	if err != nil {
		logf("wg-transport: apply failed: %v", err)
		return
	}
	if kpub != cfg.WGTransport.KeeneticPublicKey {
		cfg.WGTransport.KeeneticPublicKey = kpub
		if err := cfg.Save(configPath()); err != nil {
			logf("wg-transport: could not persist the new Keenetic key: %v", err)
			return
		}
		logf("wg-transport: %s re-keyed by firmware, config updated", cfg.WGTransport.Iface)
	}
	logf("wg-transport: %s -> xray :%d", cfg.WGTransport.Iface, cfg.WGTransport.WGPort())
}
