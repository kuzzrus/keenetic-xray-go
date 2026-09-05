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
)

// cmdProxy0 points Keenetic's Proxy interface at the local Xray inbound
// so LAN traffic can be policy-routed through the proxy from the router
// UI -- otherwise that's a manual router-side step. It detects the router
// LAN IP itself (never a loopback address) and verifies the change stuck.
func cmdProxy0(args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	switch action {
	case "show":
		return proxy0Show(cfg)
	case "set", "on":
		return proxy0Set(cfg, args[1:])
	case "off", "disable":
		return proxy0Off(cfg)
	default:
		return fmt.Errorf("usage: keenetic-xray proxy0 {show|set [--lan-ip=192.168.x.1] [--protocol=socks5|http] [--interface=Proxy0]|off}")
	}
}

func proxy0Show(cfg *config.Config) error {
	fmt.Printf("proxy0.enabled: %v\n", cfg.Proxy0.Enabled)
	if !keenetic.Available() {
		fmt.Println("ndmc: not found (not a Keenetic router?)")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP); err == nil {
		fmt.Printf("router LAN IP: %s\n", ip)
	} else {
		fmt.Printf("router LAN IP: unknown (%v)\n", err)
	}

	iface := cfg.Proxy0.IfaceName()
	fmt.Printf("protocol: %s (inbound port %d)\n", cfg.Proxy0.ProtoName(), cfg.Proxy0Port())
	fmt.Printf("interface: %s\n", iface)
	host, port, ok, err := keenetic.Proxy0Upstream(ctx, cfg.Proxy0.Interface)
	if err != nil {
		return fmt.Errorf("reading %s upstream: %w", iface, err)
	}
	if ok {
		fmt.Printf("%s upstream: %s:%d\n", iface, host, port)
	} else {
		fmt.Printf("%s upstream: not set\n", iface)
	}
	return nil
}

func proxy0Set(cfg *config.Config, args []string) error {
	override := cfg.Proxy0.LANIP
	old := cfg.Proxy0
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--lan-ip="):
			override = strings.TrimPrefix(a, "--lan-ip=")
		case strings.HasPrefix(a, "--protocol="):
			cfg.Proxy0.Protocol = strings.TrimPrefix(a, "--protocol=")
		case strings.HasPrefix(a, "--interface="):
			cfg.Proxy0.Interface = strings.TrimPrefix(a, "--interface=")
		default:
			return fmt.Errorf("unknown argument %q (want --lan-ip=, --protocol=socks5|http, --interface=Proxy0)", a)
		}
	}
	switch cfg.Proxy0.Protocol {
	case "", "socks5", "http":
	default:
		return fmt.Errorf("--protocol %q: want socks5 or http", cfg.Proxy0.Protocol)
	}
	if !config.ValidProxyIface(cfg.Proxy0.Interface) {
		return fmt.Errorf("--interface %q: want a name like Proxy0 or Proxy1", cfg.Proxy0.Interface)
	}

	if !keenetic.Available() {
		return fmt.Errorf("ndmc not found -- this command only works on a Keenetic router")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, override)
	if err != nil {
		return fmt.Errorf("detecting the router LAN IP: %w (pass --lan-ip=192.168.x.1)", err)
	}
	port := cfg.Proxy0Port()
	if port <= 0 {
		return fmt.Errorf("no inbound port configured for proxy0.protocol %q", cfg.Proxy0.Protocol)
	}

	// A changed interface leaves the old one still pointing at the local
	// inbound -- bring it down first so traffic isn't split across both.
	if old.Interface != cfg.Proxy0.Interface && cfg.Proxy0.Enabled {
		if err := keenetic.DisableProxy0(ctx, old.Interface); err != nil {
			fmt.Printf("warning: could not bring the previous interface %s down: %v\n", old.IfaceName(), err)
		} else {
			fmt.Printf("%s brought down (interface changed to %s)\n", old.IfaceName(), cfg.Proxy0.IfaceName())
		}
	}

	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: port,
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		return err
	}

	cfg.Proxy0.Enabled = true
	if override != "" {
		cfg.Proxy0.LANIP = override
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("%s (%s) -> %s:%d\n", cfg.Proxy0.IfaceName(), cfg.Proxy0.ProtoName(), ip, port)
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

func proxy0Off(cfg *config.Config) error {
	if keenetic.Available() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := keenetic.DisableProxy0(ctx, cfg.Proxy0.Interface); err != nil {
			return err
		}
	}
	cfg.Proxy0.Enabled = false
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("proxy0 disabled (the interface was brought down; xray rebinds to loopback once applied)")
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

// applyProxy0AtStartup is called by the daemon: if Proxy0 is enabled,
// (re)assert the upstream so a firmware event that dropped it self-heals.
// Best-effort -- failures are logged, not fatal.
func applyProxy0AtStartup(cfg *config.Config, logf func(string, ...any)) {
	if !cfg.Proxy0.Enabled || !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		logf("proxy0: LAN IP detection failed: %v", err)
		return
	}
	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: cfg.Proxy0Port(),
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		logf("proxy0: configure failed: %v", err)
		return
	}
	logf("proxy0: %s -> %s:%d", cfg.Proxy0.IfaceName(), ip, cfg.Proxy0Port())
}
