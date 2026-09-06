package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// cmdTransport tweaks how the VLESS tunnel's transport behaves.
//
//   - `mode` is the xhttp `mode` global override (Config.XHTTPMode):
//     share links commonly ship `mode=auto`, which negotiates per
//     connection and is often slow; forcing `stream-up` / `stream-one`
//     can help. The share link's own `extra` blob (xmux, sc* tuning) is
//     always passed through -- see config.Profile.XHTTPExtra.
//   - `mss` clamps the TCP MSS of connections forwarded through the
//     Proxy0 interface (Config.Proxy0.MSSClamp). Without it a LAN client
//     negotiates ~1460 against the router's 1500 MTU, those full-size
//     segments don't fit the Proxy0 -> xray -> xhttp/reality tunnel, and
//     large transfers (video) stall ~20s on retransmit -- a PMTU black
//     hole. Only takes effect while Proxy0 is on.
func cmdTransport(args []string) error {
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
		printTransport(cfg)
		return nil
	case "mode":
		if len(args) != 2 || !config.ValidXHTTPMode(args[1]) {
			return fmt.Errorf("usage: keenetic-xray transport mode {auto|packet-up|stream-up|stream-one}")
		}
		cfg.XHTTPMode = args[1]
	case "mode-clear":
		cfg.XHTTPMode = ""
	case "mss":
		if len(args) != 2 {
			return fmt.Errorf("usage: keenetic-xray transport mss {<1200..1452>|auto|off}")
		}
		v, err := config.ParseMSSClampArg(args[1])
		if err != nil {
			return err
		}
		cfg.Proxy0.MSSClamp = v
		if err := cfg.Save(configPath()); err != nil {
			return err
		}
		printTransport(cfg)
		if !cfg.Proxy0.Enabled {
			fmt.Println("proxy0 выключен — клампинг применится при включении")
			return nil
		}
		applyMSSClamp(cfg, func(f string, a ...any) { fmt.Printf(f+"\n", a...) })
		return nil
	default:
		return fmt.Errorf("usage: keenetic-xray transport {show|mode <mode>|mode-clear|mss <1200..1452|auto|off>}")
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	printTransport(cfg)
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}

func printTransport(cfg *config.Config) {
	m := cfg.XHTTPMode
	if m == "" {
		m = "(из ссылки)"
	}
	fmt.Printf("xhttp mode: %s\n", m)
	mss := cfg.Proxy0.MSSClampText()
	if cfg.Proxy0.MSSClampValue() > 0 && !cfg.Proxy0.Enabled {
		mss += " (не активен — proxy0 выключен)"
	}
	fmt.Printf("MSS-клампинг (Proxy0): %s\n", mss)
}
