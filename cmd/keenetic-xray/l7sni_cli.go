package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// transportL7SNI is `keenetic-xray transport l7sni {show|on|off}` --
// toggles L7 hostname detection (see config.L7SNIConfig's own doc
// comment). Unlike AdaptiveRoute.Enabled, this genuinely needs a full
// daemon restart to take effect either way: l7SNIClassifyLoop
// (cmd/keenetic-xray/l7sni_linux.go) checks cfg.L7SNI.Enabled once at
// its own startup, then blocks on Capture.Read() for the rest of the
// process's life -- unlike adaptiveRouteClassifyLoop's own tick-based
// loop, there's no per-tick config re-read that could notice a change
// live, so applyDaemonChange's usual "try a SIGHUP live-reload first"
// path would be actively misleading here (a successful SIGHUP reloads
// the failover daemon's own config, not this feature) -- go straight to
// offering a real restart instead.
func transportL7SNI(cfg *config.Config, args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		if cfg.L7SNI.Enabled {
			fmt.Println("l7sni: вкл")
		} else {
			fmt.Println("l7sni: выкл")
		}
		return nil
	case "on":
		if !keenetic.Available() {
			return fmt.Errorf("ndmc не найден — l7sni работает только на роутере Keenetic")
		}
		cfg.L7SNI.Enabled = true
	case "off":
		cfg.L7SNI.Enabled = false
	default:
		return fmt.Errorf("usage: keenetic-xray transport l7sni {show|on|off}")
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("l7sni: сохранено — нужен перезапуск демона, чтобы применилось")
	offerDaemonRestart(bufio.NewReader(os.Stdin))
	return nil
}
