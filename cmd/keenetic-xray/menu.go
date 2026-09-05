package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// cmdMenu is the interactive SSH control panel for running the router
// without the Telegram bot: a numbered menu that dispatches to the same
// subcommands (status, doctor, subscription, setup, proxy0) plus a daemon
// restart and a log tail. Everything it does is also a direct subcommand;
// the menu is just the discoverable front door on the router shell.
func cmdMenu(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("menu takes no arguments")
	}
	return runMenu(os.Stdin, os.Stdout)
}

const menuText = `keenetic-xray

  1) Статус
  2) Проверка (doctor)
  3) Список профилей
  4) Обновить подписку
  5) Настройка / сменить источник
  6) Proxy0 (проброс LAN через прокси)
  7) Перезапустить демон
  8) Логи (хвост)
  0) Выход`

func runMenu(stdin io.Reader, out io.Writer) error {
	in := bufio.NewReader(stdin)
	for {
		fmt.Fprintln(out, menuText)
		fmt.Fprint(out, "> ")
		line, err := in.ReadString('\n')
		if line == "" && err != nil {
			fmt.Fprintln(out)
			return nil // EOF -> quit
		}

		choice := strings.TrimSpace(line)
		if choice == "" {
			fmt.Fprintln(out)
			continue // bare Enter -> just redraw the menu
		}

		switch choice {
		case "1":
			runAndReport(out, func() error { return cmdStatus(nil) })
		case "2":
			runAndReport(out, func() error { return cmdDoctor(nil) })
		case "3":
			runAndReport(out, func() error { return cmdProfile([]string{"list"}) })
		case "4":
			runAndReport(out, func() error { return cmdSubscription([]string{"refresh"}) })
		case "5":
			runAndReport(out, func() error { return cmdSetup(nil) })
		case "6":
			menuProxy0(in, out)
		case "7":
			menuRestartDaemon(out)
		case "8":
			menuTailLogs(out)
		case "0", "q", "quit", "exit":
			return nil
		default:
			fmt.Fprintln(out, "неизвестный пункт")
		}
		fmt.Fprintln(out)
	}
}

func runAndReport(out io.Writer, fn func() error) {
	if err := fn(); err != nil {
		fmt.Fprintln(out, "ошибка:", err)
	}
}

func menuProxy0(in *bufio.Reader, out io.Writer) {
	fmt.Fprint(out, "  a) показать   b) включить   c) выключить\n  > ")
	line, _ := in.ReadString('\n')
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "a", "show", "":
		runAndReport(out, func() error { return cmdProxy0([]string{"show"}) })
	case "b", "on", "set":
		runAndReport(out, func() error { return cmdProxy0([]string{"set"}) })
	case "c", "off":
		runAndReport(out, func() error { return cmdProxy0([]string{"off"}) })
	default:
		fmt.Fprintln(out, "неизвестный пункт")
	}
}

// menuRestartDaemon applies any pending config change: signalDaemonReload
// first (live, no restart -- see applyDaemonChange in daemonctl.go), and
// only falls back to a full init.d restart if that's not possible.
// Skips the Y/n offerDaemonRestart asks -- picking this menu item is the
// confirmation. initScript is defined in daemonctl.go.
func menuRestartDaemon(out io.Writer) {
	if signalDaemonReload() {
		fmt.Fprintln(out, "применено на лету (без перезапуска)")
		return
	}
	if fi, err := os.Stat(initScript); err != nil || fi.IsDir() {
		fmt.Fprintln(out, "init-скрипт не найден -- запусти демон вручную: keenetic-xray daemon")
		return
	}
	cmd := exec.Command(initScript, "restart")
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(out, "не удалось перезапустить (%v) -- вручную: %s restart\n", err, initScript)
	}
}

func menuTailLogs(out io.Writer) {
	c := exec.Command("sh", "-c", "tail -n 40 "+logDir()+"/*.log 2>/dev/null")
	c.Stdout, c.Stderr = out, out
	if err := c.Run(); err != nil {
		fmt.Fprintln(out, "нет логов в", logDir())
	}
}
