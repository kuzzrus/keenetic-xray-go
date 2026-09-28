package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// cmdLogs prints the tail of the daemon's own rolling log
// (daemonLogPath). Same file the bot's 📜 Логи / daemon_log action
// reads. `keenetic-xray logs [N]` -- N lines, default 200.
// `keenetic-xray logs access on|off` toggles xray's per-connection log.
func cmdLogs(args []string) error {
	if len(args) > 0 && args[0] == "access" {
		return logsAccess(args[1:])
	}
	n := 200
	if len(args) > 0 {
		v, err := strconv.Atoi(args[0])
		if err != nil || v <= 0 {
			return fmt.Errorf("usage: keenetic-xray logs [N]  (N = number of lines, default 200) | logs access {on|off}")
		}
		n = v
	}
	out, err := applog.Tail(daemonLogPath(), n)
	if err != nil {
		return err
	}
	if out == "" {
		fmt.Println("(лог пуст или ещё не создан -- демон пишет его при работе)")
		return nil
	}
	fmt.Println(out)
	return nil
}

// logsAccess is `keenetic-xray logs access [on|off]`: xray's own
// per-connection log in daemon.log, off by default -- see
// config.XrayConfigOptions.AccessLog. Applies live: the daemon reloads
// and regenerates xray's config.
func logsAccess(args []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if len(args) == 0 {
		state := "выключен"
		if cfg.XrayAccessLog {
			state = "включён"
		}
		fmt.Printf("журнал соединений xray: %s\n", state)
		return nil
	}
	switch args[0] {
	case "on":
		cfg.XrayAccessLog = true
	case "off":
		cfg.XrayAccessLog = false
	default:
		return fmt.Errorf("usage: keenetic-xray logs access {on|off}")
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	if cfg.XrayAccessLog {
		fmt.Println("журнал соединений xray включён: каждое соединение -- строка в daemon.log. Для отладки; потом: keenetic-xray logs access off")
	} else {
		fmt.Println("журнал соединений xray выключен")
	}
	applyDaemonChange(bufio.NewReader(os.Stdin), false)
	return nil
}
