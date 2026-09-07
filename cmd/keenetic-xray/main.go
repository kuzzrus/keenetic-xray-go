// Command keenetic-xray is the single entry point for the installer, daemon,
// CLI, setup wizard, and control-server agent — dispatched by subcommand.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
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
	case "logs":
		return cmdLogs(rest)
	case "routes":
		return cmdRoutes(rest)
	case "dns":
		return cmdDNS(rest)
	case "transport":
		return cmdTransport(rest)
	case "addon", "addons":
		return cmdAddon(rest)
	case "rci":
		return cmdRCI(rest)
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
  watchdog {show|enable|disable|log}              cron entry that restarts the daemon if it's not running
  logs [N]                                        last N lines of the daemon's rolling log (default 200)
  routes {list|show [name]|new <name> [entries…]|add <name> <entries…>|del <name> <entries…>|rm <name>|enable|disable <name>|set <name> [--iface=] [--exclusive]|apply}
                                                  KeeneticOS 5.0+ DNS-based routing: send named lists of domains/subnets through Proxy0
  transport {show|mode auto|packet-up|stream-up|stream-one|mode-clear|mss <1200..1452|auto|off>|wg {show|on|off}}
                                                  xhttp mode override; forwarded-TCP MSS clamp on the Proxy0 path (PMTU fix); or an in-router WireGuard hop into xray
  addon {list|show <id>|status <id>|install <id>|remove <id>|configure <id> <k=v>…}
                                                  optional router-side components: unbound (local DNS), nfqws2 (DPI bypass), conntrack, cron
  rci {show|probe [url]|enable [url]|disable}     read the router config over the local RCI JSON API instead of ndmc (hedge for ndmc-sandboxed firmware)`)
}

func cmdDaemon(args []string) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	// The daemon keeps its own rolling log (and xray-core's stderr) so
	// `keenetic-xray logs` / the bot's 📜 Логи can show recent activity
	// without SSH. Best-effort: a directory it can't create just means
	// stdout only.
	var dlog *applog.Writer
	if w, e := applog.New(daemonLogPath(), 0); e == nil {
		dlog = w
		defer dlog.Close()
	} else {
		fmt.Fprintln(os.Stderr, "warning: daemon log file unavailable:", e)
	}

	d := failover.NewDaemon(failover.Paths{
		XrayBinary:       xrayBinaryPath(),
		ProductionConfig: productionConfigPath(),
		PretestConfig:    pretestConfigPath(),
		XrayStderr:       applog.Tee(dlog),
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
			// Pick up an rci enable/disable done via the CLI without a restart.
			if fresh.RCI.Enabled {
				if _, e := keenetic.UseRCI(fresh.RCI.BaseURL()); e != nil {
					fmt.Fprintln(os.Stderr, "reload: rci:", e)
				}
			} else {
				_, _ = keenetic.UseRCI("")
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

	logw := io.MultiWriter(os.Stdout, applog.Tee(dlog))
	logf := func(format string, a ...any) {
		fmt.Fprintf(logw, time.Now().Format("15:04:05")+" "+format+"\n", a...)
	}
	presets.SetOverlay(presetsOverlayDir())
	if cfg.RCI.Enabled {
		if url, err := keenetic.UseRCI(cfg.RCI.BaseURL()); err != nil {
			logf("rci: %v — читаю конфиг через ndmc", err)
		} else {
			logf("rci: конфиг роутера читаю через %s (записи — ndmc)", url)
		}
	}
	applyProxy0AtStartup(cfg, logf)
	applyRoutesAtStartup(cfg, logf)
	applyWGTransportAtStartup(cfg, logf)
	applyMSSClamp(cfg, logf)
	applyDNSAtStartup(cfg, logf)
	go routerReconcileLoop(ctx, logf)
	go presetRefreshLoop(ctx, logf)
	watchReconcileSignal(ctx, func() { reconcileOnce(ctx, logf) }) // SIGUSR1 from the netfilter.d hook

	if cfg.Agent.Enabled {
		opts, err := loadAgentOptions(cfg)
		if err != nil {
			return fmt.Errorf("agent is enabled but misconfigured: %w", err)
		}
		opts.Events = botcontrol.WatchStuckPrimary(ctx, d.Snapshot,
			cfg.Failover.PrimaryStuckWarnAfter(),
			botcontrol.FailoverEvents(ctx, d.Events()))
		handler := &botcontrol.RouterHandler{
			Daemon: d, Config: cfg, ConfigPath: configPath(),
			XrayBinary: xrayBinaryPath(), OptPath: optPath(),
			InitScript:     initScript,
			CronFile:       cronFilePath(),
			WatchdogScript: watchdogScriptPath(),
			WatchdogLog:    watchdogLogPath(),
			DaemonLog:      daemonLogPath(),
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
