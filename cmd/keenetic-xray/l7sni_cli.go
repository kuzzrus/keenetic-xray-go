package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

const l7sniUsage = "usage: keenetic-xray transport l7sni {show|on|off|quic {off|observe|act}|stats}"

// transportL7SNI is `keenetic-xray transport l7sni {show|on|off|quic <mode>|
// stats}` -- toggles L7 hostname detection (see config.L7SNIConfig's own doc
// comment). on/off genuinely need a full daemon restart to take effect:
// l7SNIClassifyLoop (cmd/keenetic-xray/l7sni_linux.go) checks
// cfg.L7SNI.Enabled once at its own startup, then blocks on Capture.Read()
// for the rest of the process's life -- unlike adaptiveRouteClassifyLoop's
// own tick-based loop, there's no per-tick config re-read that could notice a
// change live, so applyDaemonChange's usual "try a SIGHUP live-reload first"
// path would be actively misleading here (a successful SIGHUP reloads the
// failover daemon's own config, not this feature) -- go straight to offering
// a real restart instead. The QUIC mode is the exception: the capture loop
// does re-read it every few seconds.
func transportL7SNI(cfg *config.Config, args []string) error {
	action := "show"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "show":
		printL7SNIState(os.Stdout, cfg)
		return nil
	case "stats":
		return printL7SNIStats(os.Stdout, time.Now())
	case "quic":
		return transportL7SNIQUIC(cfg, args[1:])
	case "on":
		if !keenetic.Available() {
			return fmt.Errorf("ndmc не найден — l7sni работает только на роутере Keenetic")
		}
		if err := l7sniEnable(cfg); err != nil {
			return err
		}
	case "off":
		cfg.L7SNI.Enabled = false
		// Found live the same day for adaptive-routing (#181): "off"
		// leaving its own dataplane in place meant it silently kept
		// doing its job until a restart, and even then a stale iptables
		// rule has no TTL of its own the way an ipset entry does -- it
		// would just sit there logging to NFLOG forever otherwise.
		// Best-effort, matching adaptiveRouteOff's own precedent: a
		// failure here shouldn't block turning the feature off in
		// config.
		if keenetic.Available() {
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := l7capture.ClearRules(cctx); err != nil {
				fmt.Printf("предупреждение: не удалось убрать NFLOG-правила: %v\n", err)
			}
			cancel()
		}
	default:
		return errors.New(l7sniUsage)
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println("l7sni: сохранено — нужен перезапуск демона, чтобы применилось")
	if cfg.L7SNI.Enabled && !cfg.AdaptiveRoute.Enabled {
		fmt.Println(l7sniNeedsAdaptiveNote)
	}
	if line, none := l7sniNamesNow(cfg); none {
		fmt.Println("ℹ️ " + line)
	}
	offerDaemonRestart(bufio.NewReader(os.Stdin))
	return nil
}

// l7sniNeedsAdaptiveNote is said when L7 SNI is on and adaptive routing is
// not: TLS and HTTP names are only looked at to feed adaptive routing's address
// set, so with it off they are ignored altogether, and a QUIC "act" only
// observes. Switching adaptive routing on is a routing change, not a package
// to install, so it is pointed at rather than done.
const l7sniNeedsAdaptiveNote = "⚠️ адаптивная маршрутизация выключена: имена TLS/HTTP не используются и ничего не переправляется " +
	"(QUIC в режиме наблюдения считает и так). Включить: keenetic-xray transport adaptive on"

// l7sniEnable switches L7 SNI on in cfg -- after making sure what its capture
// needs is on the router. The capture used to be left to find out for itself:
// without iptables it died on its first rule, with a line in the daemon's log
// and no second attempt. Not saving the setting when a tool is missing is the
// point: an L7 SNI that is "on" but cannot start only looks like it works.
func l7sniEnable(cfg *config.Config) error {
	if err := ensureFeatureDeps(featuredeps.L7SNI); err != nil {
		return fmt.Errorf("L7 SNI не включён: %w", err)
	}
	cfg.L7SNI.Enabled = true
	return nil
}

// transportL7SNIQUIC is `transport l7sni quic {off|observe|act}`. Nothing
// here needs a daemon restart: the capture loop re-reads the mode every
// couple of seconds, and the one thing it cannot do itself -- the NFLOG rule
// for UDP/443 -- is placed (or removed) right here through the same
// reconcileL7SNI the daemon runs every few minutes.
//
// What the capture does not make unnecessary is the usual reload
// (applyDaemonChange, a SIGHUP): the daemon and the bot inside it each hold
// their own copy of the config and write it back whole whenever they save
// anything else, so a copy that never heard of the new mode would put the old
// one back with the next button press.
func transportL7SNIQUIC(cfg *config.Config, args []string) error {
	if len(args) != 1 {
		return errors.New(l7sniUsage)
	}
	mode := strings.ToLower(strings.TrimSpace(args[0]))
	switch mode {
	case config.L7SNIQUICOff:
		cfg.L7SNI.QUIC = "" // off is the default; keep the config file free of it
	case config.L7SNIQUICObserve, config.L7SNIQUICAct:
		cfg.L7SNI.QUIC = mode
	default:
		return errors.New(l7sniUsage)
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Println(l7sniQUICLine(cfg))
	for _, hint := range l7sniQUICHints(cfg) {
		fmt.Println("  " + hint)
	}
	if line, none := l7sniQUICNamesWarning(cfg); none {
		fmt.Println("  " + line)
	}
	applyDaemonChange(bufio.NewReader(os.Stdin), true)

	if cfg.L7SNI.Enabled && keenetic.Available() {
		var err error
		if cfg.L7SNI.QUICMode() != config.L7SNIQUICOff {
			// The tools may be missing here too: L7 SNI can have been switched
			// on by a version that did not check, or /opt can have been wiped
			// since. Turning the mode off installs nothing.
			if err = ensureFeatureDeps(featuredeps.L7SNI); err != nil {
				fmt.Println("предупреждение: " + err.Error())
			}
		}
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			err = reconcileL7SNIHook(ctx, cfg, func(format string, a ...any) { fmt.Printf(format+"\n", a...) })
		}
		fmt.Println(l7sniQUICApplyMessage(err))
	}
	return nil
}

// l7sniQUICApplyMessage is the last line of `quic <mode>`: whether the NFLOG
// rule for UDP/443 is now in line with the saved mode. The mode is saved
// either way; a rule that could not be placed now is retried by the daemon's
// own reconcile.
func l7sniQUICApplyMessage(err error) string {
	if err != nil {
		return "предупреждение: правило перехвата UDP/443 поставить не удалось (причина выше) — режим сохранён, демон повторит попытку при ближайшей сверке (раз в 2 минуты)"
	}
	return "правило перехвата UDP/443 приведено в соответствие; если демон запущен, он подхватит режим сам (до нескольких секунд), перезапуск не нужен"
}

// printL7SNIState is `transport l7sni show`.
func printL7SNIState(w io.Writer, cfg *config.Config) {
	if cfg.L7SNI.Enabled {
		fmt.Fprintln(w, "l7sni: вкл")
	} else {
		fmt.Fprintln(w, "l7sni: выкл")
	}
	fmt.Fprintln(w, l7sniQUICLine(cfg))
	for _, hint := range l7sniQUICHints(cfg) {
		fmt.Fprintln(w, "  "+hint)
	}
	if line, _ := l7sniNamesNow(cfg); line != "" {
		fmt.Fprintln(w, "  "+line)
	}
}

// l7sniQUICWord is the short name of a QUIC mode.
func l7sniQUICWord(mode string) string {
	switch mode {
	case config.L7SNIQUICObserve:
		return "наблюдение"
	case config.L7SNIQUICAct:
		return "действие"
	default:
		return "выкл"
	}
}

// l7sniQUICLine says what the QUIC mode is and what it amounts to. The
// configured mode and the one the capture runs with can differ -- l7sni
// itself off silences it, and "act" with adaptive routing off only observes
// (Config.EffectiveL7SNIQUIC) -- and the line says so rather than leaving the
// operator to wonder why nothing happens.
func l7sniQUICLine(cfg *config.Config) string {
	set, eff := cfg.L7SNI.QUICMode(), cfg.EffectiveL7SNIQUIC()
	line := "QUIC (UDP/443): " + l7sniQUICWord(set)
	switch {
	case set == config.L7SNIQUICOff:
		// A value that is not one of the three (a hand-edited "Observe" or
		// "on") reads as off; say so, or the missing counters look like a
		// capture problem.
		if raw := cfg.L7SNI.QUIC; raw != "" && raw != config.L7SNIQUICOff {
			return fmt.Sprintf("%s — в config.json записано %q, это не off/observe/act, читается как «выкл»", line, raw)
		}
		return line
	case !cfg.L7SNI.Enabled:
		return line + " — но l7sni выключен, поэтому не работает"
	case set != eff:
		return line + " — адаптивная маршрутизация выключена, поэтому работает как «" + l7sniQUICWord(eff) + "»"
	}
	switch eff {
	case config.L7SNIQUICObserve:
		return line + " — разбираем начало соединений и считаем имена, ничего не переправляем"
	default:
		return line + " — имя из списка маршрутов переправляется так же, как для TLS"
	}
}

// l7sniQUICHints lists what would make the chosen mode more useful, one line
// each; nothing for a mode that is off.
//
// They follow the mode the capture really runs with (l7sniQUICLine has just
// said which that is), not the one that was asked for: first what has to be
// switched on for the chosen mode to work at all, then what the running mode
// does. An "act" that only observes must not warn about what redirecting does
// to an app, and a capture that is not running has no counters to point at.
func l7sniQUICHints(cfg *config.Config) []string {
	set, eff := cfg.L7SNI.QUICMode(), cfg.EffectiveL7SNIQUIC()
	if set == config.L7SNIQUICOff {
		return nil
	}
	var out []string
	if !cfg.L7SNI.Enabled {
		out = append(out, "включить определение имён: keenetic-xray transport l7sni on")
	}
	if set == config.L7SNIQUICAct && !cfg.AdaptiveRoute.Enabled {
		out = append(out, "включить адаптивную маршрутизацию (иначе совпавшие имена не переправляются): keenetic-xray transport adaptive on")
	}
	if eff == config.L7SNIQUICAct {
		out = append(out, "браузеры сами уходят на TCP, когда QUIC к адресу отбит; приложение без запасного пути на TCP останется без QUIC к этому адресу")
	}
	if eff != config.L7SNIQUICOff {
		out = append(out, "что насчиталось: keenetic-xray transport l7sni stats")
	}
	return out
}

// l7sniQUICNamesWarning is the "nothing to redirect" warning for the QUIC
// command: only an "act" that really acts has anything to say about it (observe
// counts, and needs no list), and only when there is nothing to match against.
func l7sniQUICNamesWarning(cfg *config.Config) (line string, none bool) {
	if cfg.EffectiveL7SNIQUIC() != config.L7SNIQUICAct {
		return "", false
	}
	return l7sniNamesNow(cfg)
}

// l7sniNamesNow is the sentence about what the capture matches against, for a
// command run by hand: it may read the router's lists itself (a second or so),
// which the daemon's own callers avoid by their cache. Empty while L7 SNI is off.
func l7sniNamesNow(cfg *config.Config) (line string, none bool) {
	ctx, cancel := context.WithTimeout(context.Background(), l7sniRouterReadTimeout+5*time.Second)
	defer cancel()
	return l7sniNamesLine(ctx, cfg)
}

// noL7SNIStatsMessage is what a missing stats file means to the operator.
const noL7SNIStatsMessage = "l7sni: статистики пока нет — l7sni выключен, демон только что запущен или ещё ничего не перехватил (файл обновляется раз в ~10 с)"

// printL7SNIStats is `transport l7sni stats`: what the daemon's capture has
// counted since it started, read from the file it publishes.
func printL7SNIStats(w io.Writer, now time.Time) error {
	f, err := readL7SNIStats(l7sniStatsPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Fprintln(w, noL7SNIStatsMessage)
			printL7SNICaptureCheck(w, nil)
			return nil
		}
		return fmt.Errorf("не удалось прочитать статистику l7sni: %w", err)
	}
	renderL7SNIStats(w, f, now)
	printL7SNICaptureCheck(w, f)
	return nil
}

// printL7SNICaptureCheck adds what the kernel says about the capture's rules
// (see l7sniCaptureCheck) under the counters.
func printL7SNICaptureCheck(w io.Writer, f *l7sniStatsFile) {
	if check := l7sniCaptureCheck(f); check != "" {
		fmt.Fprintln(w, check)
	}
}

// writeL7SNICounters is the stats without the list of most-seen names, for
// the places that get pasted or relayed: the diag bundle and the bot's chat
// (router -> control server -> Telegram). That list is the household's
// browsing history -- every site any client opened, not only the ones on a
// routes list -- and the stats file is private for exactly that reason; the
// counters say what is needed to judge the capture, the names stay on the
// CLI. The error is readL7SNIStats's, so a caller can tell a missing file.
func writeL7SNICounters(w io.Writer, now time.Time) error {
	f, err := readL7SNIStats(l7sniStatsPath())
	if err != nil {
		return err
	}
	f.Top = nil
	renderL7SNIStats(w, f, now)
	fmt.Fprintln(w, "(самые частые имена здесь не показываются — это история посещений; они есть в `transport l7sni stats` по SSH)")
	printL7SNICaptureCheck(w, f)
	return nil
}

// l7sniStatsText is the counters as a string, for the bot.
func l7sniStatsText(now time.Time) (string, error) {
	var b strings.Builder
	if err := writeL7SNICounters(&b, now); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No statistics yet is exactly when the rules' own counters are
			// worth most: they say whether anything reaches the capture at all.
			if check := l7sniCaptureCheck(nil); check != "" {
				return noL7SNIStatsMessage + "\n\n" + check, nil
			}
			return noL7SNIStatsMessage, nil
		}
		return "", fmt.Errorf("не удалось прочитать статистику l7sni: %w", err)
	}
	return b.String(), nil
}

// reconcileL7SNIFromDisk is reconcileL7SNI against the config as it is on
// disk right now -- for the bot, which has just saved a new QUIC mode and
// wants the NFLOG rule to follow it at once.
func reconcileL7SNIFromDisk(ctx context.Context, logf func(string, ...any)) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	return reconcileL7SNIHook(ctx, cfg, logf)
}

// reconcileL7SNIHook is reconcileL7SNI, as a variable so the commands that call
// it can be tested without a router's iptables behind them.
var reconcileL7SNIHook = reconcileL7SNI
