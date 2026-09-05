// Command keenetic-xray is the single entry point for the installer, daemon,
// CLI, setup wizard, and control-server agent — dispatched by subcommand.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keenetic-xray:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError("")
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version":
		fmt.Println(version.String())
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "setup":
		return cmdSetup(rest)
	case "menu":
		return cmdMenu(rest)
	case "daemon":
		return cmdDaemon(rest)
	case "profile":
		return cmdProfile(rest)
	case "subscription":
		return cmdSubscription(rest)
	case "status":
		return cmdStatus(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "variant":
		return cmdVariant(rest)
	case "agent":
		return cmdAgent(rest)
	case "proxy0":
		return cmdProxy0(rest)
	case "failover":
		return cmdFailover(rest)
	case "watchdog":
		return cmdWatchdog(rest)
	case "internal":
		return cmdInternal(rest)
	default:
		return usageError(cmd)
	}
}

func usageError(cmd string) error {
	printUsage()
	if cmd == "" {
		return fmt.Errorf("no command given")
	}
	return fmt.Errorf("unknown command %q", cmd)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage: keenetic-xray <command> [args]

commands:
  version                                          print version and exit
  setup                                             interactive first-run configuration menu
  menu                                              interactive control panel (manage the router over SSH, no bot)
  daemon                                            run the failover daemon in the foreground
  profile {add <vless-uri>|list|remove <index>}
  subscription {set-url <url>|refresh|list|set-primary <i>|set-backup <i>}
  status                                            show configured profiles and variant
  doctor                                            run diagnostic checks
  variant {show|set mini|set full}
  agent {configure <url> <router-id> <fingerprint> <token>|enable|disable|status}
  proxy0 {show|set [--lan-ip=192.168.x.1]|off}   point Keenetic's Proxy0 at the local inbound
  failover {show|set <key> <value>}              tune health-check thresholds (applies live)
  watchdog {show|enable|disable|log}              cron entry that restarts the daemon if it's not running`)
}

func cmdDaemon(args []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	d := failover.NewDaemon(failover.Paths{
		XrayBinary:       xrayBinaryPath(),
		ProductionConfig: productionConfigPath(),
		PretestConfig:    pretestConfigPath(),
	}, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("shutting down...")
		cancel()
	}()

	// Best-effort: a CLI command (setup, subscription, proxy0, failover
	// set) that just saved a config change signals this pidfile's owner
	// with SIGHUP to apply it live (see ReloadConfig below) instead of
	// needing a full daemon restart. Not writing it just means those
	// commands fall back to the old "restart to apply" guidance.
	if cleanup, err := writeDaemonPIDFile(); err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not write pidfile, live config reload from the CLI won't be available:", err)
	} else {
		defer cleanup()
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			fresh, err := config.Load(configPath())
			if err != nil {
				fmt.Fprintln(os.Stderr, "reload: loading config:", err)
				continue
			}
			if d.ReloadConfig(ctx, fresh) {
				fmt.Println("reload: applied")
			} else {
				fmt.Fprintln(os.Stderr, "reload: daemon not ready yet")
			}
		}
	}()

	if p, b := cfg.Primary(), cfg.Backup(); p != nil && b != nil {
		fmt.Printf("starting failover daemon (primary=%s, backup=%s)\n", p.Remark, b.Remark)
	}

	applyProxy0AtStartup(cfg, func(format string, a ...any) { fmt.Printf(format+"\n", a...) })

	if cfg.Agent.Enabled {
		opts, err := loadAgentOptions(cfg)
		if err != nil {
			return fmt.Errorf("agent is enabled but misconfigured: %w", err)
		}
		opts.Events = botcontrol.FailoverEvents(ctx, d.Events())
		handler := &botcontrol.RouterHandler{
			Daemon: d, Config: cfg, ConfigPath: configPath(),
			XrayBinary: xrayBinaryPath(), OptPath: optPath(),
			InitScript:  initScript,
			CronFile:    cronFilePath(),
			WatchdogLog: watchdogLogPath(),
		}
		opts.StatusFunc = func(ctx context.Context) string {
			out, _ := handler.Handle(ctx, botcontrol.Command{Action: botcontrol.ActionStatus})
			return out
		}
		go func() {
			if err := botcontrol.Run(ctx, opts, handler); err != nil && ctx.Err() == nil {
				fmt.Fprintln(os.Stderr, "agent stopped:", err)
			}
		}()
		fmt.Println("bot-control agent enabled, polling", opts.ControlServerURL)
	}

	if err := d.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}
