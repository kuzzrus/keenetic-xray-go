package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// cmdTransport tweaks how the VLESS tunnel's transport is rendered into
// the xray config. Right now that's just the xhttp `mode` global
// override (Config.XHTTPMode): share links commonly ship `mode=auto`,
// which negotiates per connection and is often slow; forcing
// `stream-up` / `stream-one` can help. The share link's own `extra`
// blob (xmux, sc* tuning) is always passed through -- see
// config.Profile.XHTTPExtra -- and needs no setting here.
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
		m := cfg.XHTTPMode
		if m == "" {
			m = "(из ссылки)"
		}
		fmt.Printf("xhttp mode: %s\n", m)
		return nil
	case "mode":
		if len(args) != 2 || !config.ValidXHTTPMode(args[1]) {
			return fmt.Errorf("usage: keenetic-xray transport mode {auto|packet-up|stream-up|stream-one}")
		}
		cfg.XHTTPMode = args[1]
	case "mode-clear":
		cfg.XHTTPMode = ""
	default:
		return fmt.Errorf("usage: keenetic-xray transport {show|mode <mode>|mode-clear}")
	}

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	shown := cfg.XHTTPMode
	if shown == "" {
		shown = "(из ссылки)"
	}
	fmt.Printf("xhttp mode: %s\n", shown)
	applyDaemonChange(bufio.NewReader(os.Stdin), true)
	return nil
}
