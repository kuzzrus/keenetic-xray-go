package main

import (
	"fmt"
	"strconv"

	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
)

// cmdLogs prints the tail of the daemon's own rolling log
// (daemonLogPath). Same file the bot's 📜 Логи / daemon_log action
// reads. `keenetic-xray logs [N]` -- N lines, default 200.
func cmdLogs(args []string) error {
	n := 200
	if len(args) > 0 {
		v, err := strconv.Atoi(args[0])
		if err != nil || v <= 0 {
			return fmt.Errorf("usage: keenetic-xray logs [N]  (N = number of lines, default 200)")
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
