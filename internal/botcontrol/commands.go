package botcontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
)

// RouterHandler implements Handler against a live failover.Daemon and
// the *config.Config it shares with it (both run in the same process --
// see the `daemon` subcommand). Mutating commands persist to ConfigPath
// so changes survive a restart; read-only commands don't write anything.
// Every command here is a thin wrapper over the same internal/config,
// internal/subscription, and internal/failover calls the CLI itself
// uses -- this is deliberately not a second implementation of any of
// that logic.
type RouterHandler struct {
	Daemon     *failover.Daemon
	Config     *config.Config
	ConfigPath string

	// XrayBinary and OptPath enrich status/doctor with the xray-core
	// version and free-disk lines. Empty -> that line is skipped. Set by
	// cmdDaemon from the same path helpers the CLI uses.
	XrayBinary string
	OptPath    string

	// ensureCoreFn is the xray-core installer, injectable so tests don't
	// need a real binary to smoke-test. nil -> xraycore.Ensure.
	ensureCoreFn func(context.Context, xraycore.Options) (string, error)

	// InitScript is the daemon's init.d script, exec'd by the
	// daemon_restart action. Empty -> that action returns an error.
	InitScript string

	// InstallURL is the install.sh the self_update action re-runs.
	// Empty -> defaultInstallURL.
	InstallURL string

	// CronFile, WatchdogScript and WatchdogLog back the watchdog_*
	// actions -- same path helpers cmd/keenetic-xray uses
	// (cronFilePath/watchdogScriptPath/watchdogLogPath). WatchdogScript
	// is where install.SetWatchdogCron writes the tiny script the cron
	// entry runs (kept out of the crontab line itself so busybox crond
	// doesn't echo it to syslog every tick). Empty CronFile or
	// WatchdogScript -> the enable/disable actions return an error
	// rather than operating on some surprising default path.
	CronFile       string
	WatchdogScript string
	WatchdogLog    string
}

const defaultInstallURL = "https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh"

// Handle implements Handler. It scrubs known secrets out of both the
// output and any error before they leave the router for the control
// server (and from there, the chat).
func (h *RouterHandler) Handle(ctx context.Context, cmd Command) (string, error) {
	out, err := h.handle(ctx, cmd)
	out = h.scrubSecrets(out)
	if err != nil {
		err = errors.New(h.scrubSecrets(err.Error()))
	}
	return out, err
}

// scrubSecrets removes values that must never reach the chat: right now
// the subscription URL, since many providers carry an access token in
// its path or query and a failed refresh surfaces the URL verbatim in a
// *url.Error. The router is the only place the raw value is known, so
// this happens here at the boundary, not in the bot.
func (h *RouterHandler) scrubSecrets(s string) string {
	if s == "" || h.Config == nil {
		return s
	}
	redact := func(u string) {
		if u != "" {
			s = strings.ReplaceAll(s, u, "<источник-URL>")
		}
	}
	if h.Config.Subscription != nil {
		redact(h.Config.Subscription.URL)
	}
	if h.Config.PrimarySource != nil {
		redact(h.Config.PrimarySource.URL)
	}
	if h.Config.BackupSource != nil {
		redact(h.Config.BackupSource.URL)
	}
	return s
}

func (h *RouterHandler) handle(ctx context.Context, cmd Command) (string, error) {
	switch cmd.Action {
	case ActionStatus:
		return h.status(ctx), nil
	case ActionDoctor:
		return h.doctor(ctx), nil
	case ActionSwitchPrimary:
		return h.switchTo(ctx, failover.RolePrimary)
	case ActionSwitchBackup:
		return h.switchTo(ctx, failover.RoleBackup)
	case ActionProfileList, ActionSubList:
		return h.profileList(), nil
	case ActionSubSetURL:
		return h.subSetURL(cmd.Args)
	case ActionSubRefresh:
		return h.subRefresh(ctx)
	case ActionSubSetPrimary:
		return h.subSetRole(ctx, cmd.Args, true)
	case ActionSubSetBackup:
		return h.subSetRole(ctx, cmd.Args, false)
	case ActionSetPrimarySource:
		return h.setSlotSource(ctx, true, cmd.Args)
	case ActionSetBackupSource:
		return h.setSlotSource(ctx, false, cmd.Args)
	case ActionProxy0Show:
		return h.proxy0Show(ctx), nil
	case ActionProxy0On:
		return h.proxy0Set(ctx)
	case ActionProxy0Off:
		return h.proxy0Off(ctx)
	case ActionProxy0Config:
		return h.proxy0Config(ctx, cmd.Args)
	case ActionDaemonRestart:
		return h.daemonRestart()
	case ActionEnsureCore:
		return h.ensureCore(ctx)
	case ActionUpdateCore:
		return h.updateCore(ctx, cmd.Args)
	case ActionSelfUpdate:
		return h.selfUpdate()
	case ActionFailoverShow:
		return h.Config.Failover.TunablesText(), nil
	case ActionFailoverSet:
		return h.setFailoverTunable(ctx, cmd.Args)
	case ActionWatchdogShow:
		return h.watchdogShow()
	case ActionWatchdogEnable:
		return h.watchdogEnable()
	case ActionWatchdogDisable:
		return h.watchdogDisable()
	case ActionWatchdogLog:
		return h.watchdogLog()
	case ActionSetPorts:
		return h.setPorts(ctx, cmd.Args)
	default:
		return "", fmt.Errorf("unknown action %q", cmd.Action)
	}
}

func (h *RouterHandler) status(ctx context.Context) string {
	var b strings.Builder
	fmt.Fprintf(&b, "agent: %s\n", version.String())
	fmt.Fprintf(&b, "variant: %s\n", h.Config.Variant)
	if h.XrayBinary != "" {
		if v, err := xraycore.Version(h.XrayBinary); err == nil {
			if i := strings.Index(v, " ("); i > 0 {
				v = v[:i] // "Xray 26.3.27 (Xray, ...)" -> "Xray 26.3.27"
			}
			fmt.Fprintf(&b, "xray-core: %s\n", v)
		}
	}

	if snap, ran := h.Daemon.Snapshot(ctx); !ran {
		b.WriteString("failover: демон не отвечает\n")
	} else {
		fmt.Fprintf(&b, "failover: %s (в эфире: %s)\n", snap.State, h.roleRemark(snap.LiveRole))
		if up := time.Since(snap.StartedAt); up > 0 {
			fmt.Fprintf(&b, "uptime: %s\n", shortDur(up))
		}
		if n := len(snap.Transitions); n > 0 {
			last := snap.Transitions[n-1]
			fmt.Fprintf(&b, "последнее переключение: %s назад — %s\n",
				shortDur(time.Since(last.At)), describeTransition(last))
		}
		if drops := countPrimaryDrops(snap.Transitions, time.Now().Add(-time.Hour)); drops >= 2 {
			fmt.Fprintf(&b, "⚠️ primary нестабилен: %d переключений за час\n", drops)
		}
	}

	if p := h.Config.Primary(); p != nil {
		fmt.Fprintf(&b, "primary: %s (%s:%d)\n", p.Remark, p.Address, p.Port)
	}
	if bk := h.Config.Backup(); bk != nil {
		fmt.Fprintf(&b, "backup: %s (%s:%d)\n", bk.Remark, bk.Address, bk.Port)
	}
	if len(h.Config.Profiles) > 1 && h.Config.PrimaryIndex == h.Config.BackupIndex {
		b.WriteString("⚠️ primary и backup — один профиль, failover не сработает\n")
	}

	sp := h.Config.Failover.SOCKSPort
	if portListening(sp) {
		fmt.Fprintf(&b, "xray: слушает :%d\n", sp)
	} else {
		fmt.Fprintf(&b, "xray: НЕ слушает :%d ⚠️\n", sp)
	}

	if h.Config.Proxy0.Enabled {
		b.WriteString("proxy0: вкл")
		if keenetic.Available() {
			if host, port, ok, err := keenetic.Proxy0Upstream(ctx, h.Config.Proxy0.Interface); err == nil && ok {
				fmt.Fprintf(&b, " → %s:%d", host, port)
			}
		}
		b.WriteByte('\n')
	} else {
		b.WriteString("proxy0: выкл\n")
	}

	if s := h.Config.Subscription; s != nil && s.URL != "" {
		if s.LastFetchedAt.IsZero() {
			fmt.Fprintf(&b, "подписка: %d профилей, ещё не обновлялась\n", len(h.Config.Profiles))
		} else {
			fmt.Fprintf(&b, "подписка: %d профилей, обновлена %s назад\n",
				len(h.Config.Profiles), shortDur(time.Since(s.LastFetchedAt)))
		}
	}

	return b.String()
}

// doctor mirrors `keenetic-xray doctor` as chat text: pass/fail lines
// plus an info line, and a trailing count instead of a process exit code.
func (h *RouterHandler) doctor(ctx context.Context) string {
	var b strings.Builder
	fail := 0
	check := func(ok bool, msg string) {
		if ok {
			fmt.Fprintf(&b, "✅ %s\n", msg)
		} else {
			fmt.Fprintf(&b, "❌ %s\n", msg)
			fail++
		}
	}

	check(len(h.Config.Profiles) > 0, "есть хотя бы один профиль")
	check(h.Config.Primary() != nil, "выбран primary")
	check(h.Config.Backup() != nil, "выбран backup")
	if err := h.Config.Validate(); err != nil {
		check(false, "конфиг валиден: "+err.Error())
	} else {
		check(true, "конфиг валиден")
	}

	if h.XrayBinary != "" {
		if v, err := xraycore.Version(h.XrayBinary); err != nil {
			check(false, "xray-core запускается: "+err.Error())
		} else {
			check(true, v)
		}
	}

	sp := h.Config.Failover.SOCKSPort
	check(portListening(sp), fmt.Sprintf("xray слушает :%d", sp))

	if h.Config.Proxy0.Enabled && keenetic.Available() {
		host, port, ok, err := keenetic.Proxy0Upstream(ctx, h.Config.Proxy0.Interface)
		switch {
		case err != nil:
			check(false, "proxy0 upstream: "+err.Error())
		case !ok:
			check(false, "proxy0 включён, но upstream не задан")
		default:
			check(port == h.Config.Proxy0Port(),
				fmt.Sprintf("proxy0 upstream %s:%d совпадает с портом %d", host, port, h.Config.Proxy0Port()))
		}
	}

	if h.OptPath != "" {
		if free, err := diskspace.FreeBytes(h.OptPath); err == nil {
			fmt.Fprintf(&b, "ℹ️ свободно на %s: %d МБ\n", h.OptPath, free/1024/1024)
		}
	}

	if h.Daemon != nil {
		if snap, ok := h.Daemon.Snapshot(ctx); ok {
			if s := probeSummary(snap.Probes, time.Now()); s != "" {
				fmt.Fprintf(&b, "ℹ️ %s\n", s)
			}
		}
	}

	if fail == 0 {
		b.WriteString("\nвсе проверки пройдены")
	} else {
		fmt.Fprintf(&b, "\nпроблем: %d", fail)
	}
	return b.String()
}

// roleRemark is the Remark of the profile in the given failover role, or
// a placeholder when it isn't configured.
func (h *RouterHandler) roleRemark(role failover.Role) string {
	p := h.Config.Primary()
	if role == failover.RoleBackup {
		p = h.Config.Backup()
	}
	if p == nil {
		return "?"
	}
	return p.Remark
}

// portListening reports whether something accepts TCP on 127.0.0.1:port.
// When Proxy0 is on, xray binds 0.0.0.0, which loopback still reaches.
func portListening(port int) bool {
	if port <= 0 {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// shortDur renders a duration compactly: "45s", "12m", "3h12m", "6d4h".
func shortDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 24*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) % 60; m != 0 {
			return fmt.Sprintf("%dh%dm", h, m)
		}
		return strconv.Itoa(h) + "h"
	default:
		days := int(d.Hours()) / 24
		if h := int(d.Hours()) % 24; h != 0 {
			return fmt.Sprintf("%dd%dh", days, h)
		}
		return strconv.Itoa(days) + "d"
	}
}

// probeSummary condenses the recent health-check history into a few
// lines for `doctor`: the ok/fail split, failures grouped by class with
// how long ago the last of each was, and the latency of successful
// checks. Empty string when there's no history yet.
func probeSummary(probes []failover.ProbeResult, now time.Time) string {
	if len(probes) == 0 {
		return ""
	}
	ok := 0
	var reasons []string           // insertion order
	cnt := map[string]int{}        // reason -> count
	last := map[string]time.Time{} // reason -> most recent At
	var latSum time.Duration
	var latMax time.Duration
	latN := 0
	for _, p := range probes {
		if p.OK {
			ok++
			latSum += p.Latency
			latN++
			if p.Latency > latMax {
				latMax = p.Latency
			}
			continue
		}
		r := p.Reason
		if r == "" {
			r = "ошибка"
		}
		if _, seen := cnt[r]; !seen {
			reasons = append(reasons, r)
		}
		cnt[r]++
		if p.At.After(last[r]) {
			last[r] = p.At
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "health-check (%d посл.): %d ✅ / %d ❌", len(probes), ok, len(probes)-ok)
	if len(reasons) > 0 {
		parts := make([]string, 0, len(reasons))
		for _, r := range reasons {
			parts = append(parts, fmt.Sprintf("%s ×%d (посл. %s назад)", r, cnt[r], shortDur(now.Sub(last[r]))))
		}
		fmt.Fprintf(&b, "\n  ❌ %s", strings.Join(parts, ", "))
	}
	if latN > 0 {
		fmt.Fprintf(&b, "\n  ⏱ %dмс средн / %dмс макс", latSum.Milliseconds()/int64(latN), latMax.Milliseconds())
	}
	return b.String()
}

// countPrimaryDrops counts how many times the daemon left primary
// (ActivePrimary -> Cooldown) within the given window -- the "how often
// is it flapping" number for `status`.
func countPrimaryDrops(transitions []failover.Transition, since time.Time) int {
	n := 0
	for _, t := range transitions {
		if t.At.After(since) && t.From == failover.StateActivePrimary && t.To == failover.StateCooldown {
			n++
		}
	}
	return n
}

// describeTransition glosses a state change in one Russian phrase.
func describeTransition(t failover.Transition) string {
	switch {
	case t.To == failover.StateActiveBackup && t.From == failover.StateConfirmingRecovery:
		return "откат на backup — primary не удержался"
	case t.To == failover.StateActiveBackup:
		return "переключение на backup"
	case t.To == failover.StateConfirmingRecovery:
		return "переключился на primary, проверяю"
	case t.To == failover.StateActivePrimary:
		return "возврат на primary"
	case t.To == failover.StateTestingRecovery:
		return "проверка восстановления primary"
	case t.To == failover.StateCooldown && t.From == failover.StateActivePrimary:
		return "primary недоступен — уход на backup"
	case t.To == failover.StateCooldown && t.From == failover.StateConfirmingRecovery:
		return "primary восстановился"
	case t.To == failover.StateCooldown:
		return "пауза после переключения"
	default:
		return t.From.String() + " → " + t.To.String()
	}
}

func (h *RouterHandler) switchTo(ctx context.Context, role failover.Role) (string, error) {
	if err := h.Daemon.ForceSwitch(ctx, role); err != nil {
		return "", err
	}
	return fmt.Sprintf("switched to %s", role), nil
}

// rebindXray makes a config change take effect. If the daemon is in its
// Run loop it re-applies the current live role (xray regenerates its
// production config and restarts -- no full daemon restart, Proxy0 left
// alone). If the daemon is idling (it starts idle until primary AND
// backup are set) and the config now has both slots, it kicks a detached
// init.d restart so the daemon actually starts serving -- otherwise a
// setup done entirely from the bot would leave the daemon idle until a
// manual restart.
func (h *RouterHandler) rebindXray(ctx context.Context) {
	if h.Daemon == nil {
		return
	}
	// h.Config is the exact *config.Config the Daemon already holds
	// (wired once in cmd/keenetic-xray's cmdDaemon), so this reloads the
	// daemon's own state from itself -- refreshing the two fields only
	// computed at startup (realActions.socks, Machine's tunable counts)
	// in addition to re-applying the current live role, unlike a bare
	// ForceSwitch. Matters here specifically because a bot action can
	// change the SOCKS/HTTP port (setPorts) or a failover tunable
	// (setFailoverTunable used to skip this and restart the whole
	// daemon instead) -- either would otherwise leave realActions.socks
	// stale, so future health-check probes would dial the *old* port.
	if _, ok := h.Daemon.Snapshot(ctx); ok {
		_ = h.Daemon.ReloadConfig(ctx, h.Config)
		return
	}
	if h.Config.Primary() != nil && h.Config.Backup() != nil {
		_ = h.restartDaemonDetached()
	}
}

// restartDaemonDetached spawns a detached "sleep 2; <InitScript> restart"
// so the caller's own command result can be posted to the control server
// before the init script SIGTERMs this process. Best-effort beyond that:
// the restart itself is fire-and-forget once spawned.
func (h *RouterHandler) restartDaemonDetached() error {
	if h.InitScript == "" {
		return fmt.Errorf("init-скрипт не задан")
	}
	c := exec.Command("sh", "-c", "sleep 2; "+h.InitScript+" restart")
	if err := c.Start(); err != nil {
		return fmt.Errorf("запуск перезапуска: %w", err)
	}
	go func() { _ = c.Wait() }() // reap the shell if we outlive the sleep
	return nil
}

func (h *RouterHandler) proxy0Show(ctx context.Context) string {
	on := "выкл"
	if h.Config.Proxy0.Enabled {
		on = "вкл"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "proxy0: %s\n", on)
	if !keenetic.Available() {
		b.WriteString("ndmc недоступен (не роутер Keenetic?)")
		return b.String()
	}
	if ip, err := keenetic.LANIP(ctx, h.Config.Proxy0.LANIP); err == nil {
		fmt.Fprintf(&b, "LAN IP роутера: %s\n", ip)
	}
	host, port, ok, err := keenetic.Proxy0Upstream(ctx, h.Config.Proxy0.Interface)
	switch {
	case err != nil:
		fmt.Fprintf(&b, "upstream: ошибка чтения (%v)", err)
	case ok:
		fmt.Fprintf(&b, "upstream: %s:%d", host, port)
	default:
		b.WriteString("upstream: не задан")
	}
	return b.String()
}

func (h *RouterHandler) proxy0Set(ctx context.Context) (string, error) {
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден -- работает только на роутере Keenetic")
	}
	ip, err := keenetic.LANIP(ctx, h.Config.Proxy0.LANIP)
	if err != nil {
		return "", fmt.Errorf("определение LAN IP роутера: %w", err)
	}
	port := h.Config.Proxy0Port()
	if port <= 0 {
		return "", fmt.Errorf("не настроен порт для proxy0.protocol %q", h.Config.Proxy0.Protocol)
	}
	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    h.Config.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: port,
		Protocol:     h.Config.Proxy0.Protocol,
	}); err != nil {
		return "", err
	}
	h.Config.Proxy0.Enabled = true
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return fmt.Sprintf("proxy0 включён → %s:%d. Назначьте устройства/политики на Proxy0 в UI Keenetic.", ip, port), nil
}

func (h *RouterHandler) proxy0Off(ctx context.Context) (string, error) {
	if keenetic.Available() {
		if err := keenetic.DisableProxy0(ctx, h.Config.Proxy0.Interface); err != nil {
			return "", err
		}
	}
	h.Config.Proxy0.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return "proxy0 выключен (xray снова слушает loopback после rebind)", nil
}

// proxy0Config changes which local protocol (socks5/http) and which
// Keenetic Proxy interface (Proxy0, Proxy1, ...) the daemon points at
// the local inbound. Both xray inbounds always listen regardless -- this
// only moves the Keenetic side. args[0]=protocol, args[1]=interface;
// an empty string in either position keeps the current value. When
// Proxy0 is already on the change is applied immediately (the previous
// interface is brought down first if it changed); otherwise it's just
// saved for the next enable.
func (h *RouterHandler) proxy0Config(ctx context.Context, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("usage: proxy0_config <protocol|\"\"> <interface|\"\">")
	}
	proto, iface := args[0], args[1]
	if proto == "" && iface == "" {
		return "", fmt.Errorf("нечего менять: укажи протокол и/или интерфейс")
	}
	switch proto {
	case "", "socks5", "http":
	default:
		return "", fmt.Errorf("протокол %q: нужно socks5 или http", proto)
	}
	if !config.ValidProxyIface(iface) {
		return "", fmt.Errorf("интерфейс %q: нужно имя вида Proxy0 или Proxy1", iface)
	}

	old := h.Config.Proxy0
	if proto != "" {
		h.Config.Proxy0.Protocol = proto
	}
	if iface != "" {
		h.Config.Proxy0.Interface = iface
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}

	summary := fmt.Sprintf("proxy0: %s через %s (порт %d)",
		h.Config.Proxy0.ProtoName(), h.Config.Proxy0.IfaceName(), h.Config.Proxy0Port())
	if !h.Config.Proxy0.Enabled {
		return summary + "\nсохранено — применится при включении proxy0", nil
	}

	if h.Config.Proxy0.Interface != old.Interface && keenetic.Available() {
		if err := keenetic.DisableProxy0(ctx, old.Interface); err != nil {
			summary += fmt.Sprintf("\n⚠️ прежний интерфейс %s не опущен: %v", old.IfaceName(), err)
		}
	}
	out, err := h.proxy0Set(ctx)
	if err != nil {
		return "", err
	}
	return summary + "\n" + out, nil
}

// daemonRestart spawns a detached "restart after a short delay" so this
// process can post the command result before the init script SIGTERMs
// it. The replacement daemon reconnects on its own and emits daemon_start.
func (h *RouterHandler) daemonRestart() (string, error) {
	if err := h.restartDaemonDetached(); err != nil {
		return "", err
	}
	return "перезапуск демона через 2с…", nil
}

// setFailoverTunable adjusts one health-check/failover knob and applies
// it live via rebindXray (Daemon.ReloadConfig refreshes Machine's own
// copy of these counts -- they used to be fixed at construction, which
// is why this needed a full daemon restart before).
func (h *RouterHandler) setFailoverTunable(ctx context.Context, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("usage: set <key> <value>")
	}
	if err := h.Config.Failover.SetTunable(args[0], args[1]); err != nil {
		return "", err
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return fmt.Sprintf("%s = %s.", args[0], args[1]), nil
}

// watchdogShow reports both halves of "is this actually working": the
// cron entry (WatchdogEnabled) and a cron daemon actually being there to
// run it (CronRunning) -- an enabled entry with no cron daemon behind it
// is silently inert, which is exactly the gap this closes.
func (h *RouterHandler) watchdogShow() (string, error) {
	if h.CronFile == "" {
		return "", fmt.Errorf("вотчдог не настроен для этого агента")
	}
	enabled, err := install.WatchdogEnabled(h.CronFile)
	if err != nil {
		return "", err
	}
	cron := "работает"
	if !install.CronRunning() {
		cron = "НЕ запущен — запись ниже не сработает, пока его нет"
	}
	return fmt.Sprintf("вотчдог: %v (проверка каждые %s через %s)\ncron: %s",
		enabled, install.WatchdogSchedule, h.InitScript, cron), nil
}

// watchdogEnable makes sure a cron daemon exists first (installing the
// Entware `cron` package via opkg if needed), then writes the entry --
// "enable" is a single button-press action rather than requiring cron
// to already be present, same sequence `keenetic-xray watchdog enable`
// runs over SSH.
func (h *RouterHandler) watchdogEnable() (string, error) {
	if h.CronFile == "" || h.WatchdogScript == "" || h.InitScript == "" {
		return "", fmt.Errorf("вотчдог не настроен для этого агента")
	}
	if err := install.EnsureCron(); err != nil {
		return "", fmt.Errorf("cron недоступен и не установился: %w", err)
	}
	if err := install.SetWatchdogCron(h.CronFile, h.WatchdogScript, h.InitScript, h.WatchdogLog, true); err != nil {
		return "", err
	}
	return "вотчдог включён (cron подтверждён работающим)", nil
}

func (h *RouterHandler) watchdogDisable() (string, error) {
	if h.CronFile == "" || h.WatchdogScript == "" {
		return "", fmt.Errorf("вотчдог не настроен для этого агента")
	}
	if err := install.SetWatchdogCron(h.CronFile, h.WatchdogScript, h.InitScript, h.WatchdogLog, false); err != nil {
		return "", err
	}
	return "вотчдог выключен", nil
}

// watchdogLog returns the tail of WatchdogLog -- restart events only,
// not routine ticks (see install.SetWatchdogCron), so an empty result
// means the watchdog has never had to intervene.
func (h *RouterHandler) watchdogLog() (string, error) {
	const maxLines = 40
	if h.WatchdogLog == "" {
		return "", fmt.Errorf("вотчдог не настроен для этого агента")
	}
	data, err := os.ReadFile(h.WatchdogLog)
	if err != nil {
		if os.IsNotExist(err) {
			return "перезапусков не зафиксировано", nil
		}
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 0 || (len(lines) == 1 && lines[0] == "") {
		return "перезапусков не зафиксировано", nil
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n"), nil
}

// setPorts changes the local SOCKS/HTTP inbound ports (config.Failover
// .SOCKSPort/HTTPPort) and applies live via rebindXray -- which, since
// ReloadConfig refreshes realActions.socks, is what makes this safe:
// without that refresh a changed SOCKS port would leave future
// health-check probes dialing the *old* one. Same validation as the
// setup wizard's own port prompt (internal/config doesn't enforce this
// itself, since 0 is a legitimate "inbound disabled" value elsewhere).
//
// If Proxy0 is already enabled, also re-points its Keenetic-side
// upstream binding (proxy0Set, which recomputes Config.Proxy0Port --
// now reflecting the port just saved) -- otherwise LAN traffic routed
// through Proxy0 would keep hitting the port it was last pointed at.
// That step is best-effort: its failure is reported alongside the
// success of the port change itself, not as an overall failure, since
// the port change already took effect regardless.
func (h *RouterHandler) setPorts(ctx context.Context, args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("usage: set_ports <socks-port> <http-port>")
	}
	socksPort, err := strconv.Atoi(args[0])
	if err != nil || socksPort < 1 || socksPort > 65535 {
		return "", fmt.Errorf("некорректный SOCKS-порт %q (1-65535)", args[0])
	}
	httpPort, err := strconv.Atoi(args[1])
	if err != nil || httpPort < 1 || httpPort > 65535 {
		return "", fmt.Errorf("некорректный HTTP-порт %q (1-65535)", args[1])
	}
	if socksPort == httpPort {
		return "", fmt.Errorf("SOCKS и HTTP порты должны различаться")
	}

	h.Config.Failover.SOCKSPort = socksPort
	h.Config.Failover.HTTPPort = httpPort
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)

	msg := fmt.Sprintf("SOCKS: %d, HTTP: %d", socksPort, httpPort)
	if h.Config.Proxy0.Enabled {
		if _, err := h.proxy0Set(ctx); err != nil {
			return msg + fmt.Sprintf(" (⚠️ proxy0 не перенастроен: %v — выполните proxy0 on ещё раз)", err), nil
		}
		msg += " (proxy0 перенаправлен на новый порт)"
	}
	return msg, nil
}

// selfUpdate re-runs install.sh (whole keenetic-xray package: new .ipk,
// opkg install, postinst, daemon restart). Detached with a short delay
// so this process can post the result before opkg replaces the binary
// under it.
func (h *RouterHandler) selfUpdate() (string, error) {
	url := h.InstallURL
	if url == "" {
		url = defaultInstallURL
	}
	c := exec.Command("sh", "-c", "sleep 2; curl -fsSL "+url+" | sh")
	if err := c.Start(); err != nil {
		return "", fmt.Errorf("запуск обновления: %w", err)
	}
	go func() { _ = c.Wait() }()
	return "обновление агента запущено — переустановка .ipk и рестарт демона через ~2с", nil
}

// ensureCore retries the xray-core install (vendored build, opkg
// fallback). Bounded at 5 min; it holds the agent's poll loop while it
// runs, acceptable for a personal single-router setup. This is the
// "there's no working core" repair path -- it leaves an already-runnable
// binary alone; updateCore is the "replace a working one" path.
func (h *RouterHandler) ensureCore(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	src, err := h.ensureCore0(cctx, xraycore.Options{
		Dest: h.XrayBinary, Tag: h.Config.XrayCoreTag,
	})
	if err != nil {
		return "", err
	}
	if v, verr := xraycore.Version(h.XrayBinary); verr == nil {
		return fmt.Sprintf("xray-core готов (%s): %s", src, v), nil
	}
	return fmt.Sprintf("xray-core установлен (%s)", src), nil
}

// ensureCore0 is xraycore.Ensure unless a test has swapped ensureCoreFn.
func (h *RouterHandler) ensureCore0(ctx context.Context, opts xraycore.Options) (string, error) {
	if h.ensureCoreFn != nil {
		return h.ensureCoreFn(ctx, opts)
	}
	return xraycore.Ensure(ctx, opts)
}

// xrayCoreTag resolves the effective vendored tag for this router.
func (h *RouterHandler) xrayCoreTag() string {
	if h.Config.XrayCoreTag != "" {
		return h.Config.XrayCoreTag
	}
	return xraycore.DefaultTag
}

// updateCore force-replaces the xray-core binary and rebinds xray onto
// it. args[0]: "" reinstalls the currently pinned tag; "stable" clears
// the pin back to xraycore.DefaultTag; a "vN.N.N" tag switches this
// router onto it (persisted in config.XrayCoreTag so a later
// self_update keeps it). Vendored-only -- a missing asset errors rather
// than silently substituting whatever xray-core the Entware feed has;
// and because xraycore.Ensure smoke-tests the download in a temp file
// before swapping it in, a bad fetch leaves the running core untouched.
func (h *RouterHandler) updateCore(ctx context.Context, args []string) (string, error) {
	if h.XrayBinary == "" {
		return "", fmt.Errorf("путь к xray не задан для этого агента")
	}
	want := h.Config.XrayCoreTag
	if len(args) > 0 && args[0] != "" {
		switch a := strings.TrimSpace(args[0]); a {
		case "stable", xraycore.DefaultTag:
			want = ""
		default:
			if !config.ValidXrayCoreTag(a) {
				return "", fmt.Errorf("тег %q: нужен вид v26.7.28 или \"stable\"", args[0])
			}
			want = a
		}
	}

	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	src, err := h.ensureCore0(cctx, xraycore.Options{
		Dest: h.XrayBinary, Tag: want, Force: true, Prefer: "vendored",
	})
	if err != nil {
		return "", err // config untouched -- don't record a switch that didn't happen
	}

	if want != h.Config.XrayCoreTag {
		h.Config.XrayCoreTag = want
		if err := h.Config.Save(h.ConfigPath); err != nil {
			return "", err
		}
	}
	h.rebindXray(ctx) // the supervised xray is still the old binary until this

	shown := h.xrayCoreTag()
	if v, verr := xraycore.Version(h.XrayBinary); verr == nil {
		return fmt.Sprintf("xray-core обновлён (%s, пин %s): %s", src, shown, v), nil
	}
	return fmt.Sprintf("xray-core обновлён (%s, пин %s)", src, shown), nil
}

func (h *RouterHandler) profileList() string {
	if len(h.Config.Profiles) == 0 {
		return "no profiles configured"
	}
	var b strings.Builder
	for i, p := range h.Config.Profiles {
		marker := ""
		if i == h.Config.PrimaryIndex {
			marker += " [primary]"
		}
		if i == h.Config.BackupIndex {
			marker += " [backup]"
		}
		fmt.Fprintf(&b, "%d: %s -- %s:%d%s\n", i, p.Remark, p.Address, p.Port, marker)
	}
	return b.String()
}

// setSlotSource points one failover slot at its own source -- a raw
// vless:// link or an http(s):// subscription (with an optional selector
// for a multi-profile one). The resolved profile is merged into the pool
// and the slot index repointed; the source is remembered per slot.
func (h *RouterHandler) setSlotSource(ctx context.Context, primary bool, args []string) (string, error) {
	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return "", fmt.Errorf("нужна vless:// ссылка или http(s):// URL")
	}
	src := strings.TrimSpace(args[0])
	selector := ""
	if len(args) > 1 {
		selector = strings.TrimSpace(args[1])
	}

	prof, err := h.resolveSource(ctx, src, selector)
	if err != nil {
		return "", err
	}
	idx := h.Config.UpsertProfile(prof)
	slot := &config.SlotSource{URL: src, Selector: selector}

	// Never touch the *other* slot's index here: an earlier version
	// mirrored this profile into an empty other slot "so the daemon can
	// run", which quietly overwrote a primary/backup that was merely
	// unset for some unrelated reason (e.g. a subscription refresh that
	// couldn't re-match it) with a copy of whatever was just set --
	// live-reproduced as primary and backup silently ending up on the
	// identical profile. Each slot's source is independent, same as the
	// reference installer's per-slot files: setting one only ever warns
	// about the other, never mutates it.
	word, other := "backup", "primary"
	otherSet := h.slotSet(h.Config.PrimaryIndex)
	if primary {
		word, other = "primary", "backup"
		otherSet = h.slotSet(h.Config.BackupIndex)
		h.Config.PrimaryIndex = idx
		h.Config.PrimarySource = slot
	} else {
		h.Config.BackupIndex = idx
		h.Config.BackupSource = slot
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)

	msg := fmt.Sprintf("%s ← %s", word, prof.Remark)
	if !otherSet {
		msg += fmt.Sprintf(" (⚠️ %s не задан — демон простаивает, пока не зададите и его)", other)
	}
	return msg, nil
}

func (h *RouterHandler) slotSet(idx int) bool {
	return idx >= 0 && idx < len(h.Config.Profiles)
}

// resolveSource turns a link or subscription URL (+ selector) into one
// profile.
func (h *RouterHandler) resolveSource(ctx context.Context, src, selector string) (config.Profile, error) {
	switch {
	case strings.HasPrefix(src, "vless://"):
		return config.ParseVLESSURI(src)
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		res, err := subscription.Refresh(ctx, src, "", "")
		if err != nil {
			return config.Profile{}, err
		}
		return pickProfile(res.Profiles, selector)
	default:
		return config.Profile{}, fmt.Errorf("нужна vless:// ссылка или http(s):// URL")
	}
}

// pickProfile selects one profile from a subscription's list by selector:
// "" / "first" -> [0]; an integer -> that index; otherwise a unique
// case-insensitive Remark substring.
func pickProfile(ps []config.Profile, selector string) (config.Profile, error) {
	if len(ps) == 0 {
		return config.Profile{}, fmt.Errorf("в подписке нет профилей")
	}
	if selector == "" || strings.EqualFold(selector, "first") {
		return ps[0], nil
	}
	if n, err := strconv.Atoi(selector); err == nil {
		if n < 0 || n >= len(ps) {
			return config.Profile{}, fmt.Errorf("индекс %d вне диапазона (%d профилей)", n, len(ps))
		}
		return ps[n], nil
	}
	match, matches := config.Profile{}, 0
	for _, p := range ps {
		if strings.Contains(strings.ToLower(p.Remark), strings.ToLower(selector)) {
			match, matches = p, matches+1
		}
	}
	switch matches {
	case 1:
		return match, nil
	case 0:
		return config.Profile{}, fmt.Errorf("нет профиля с %q в названии", selector)
	default:
		return config.Profile{}, fmt.Errorf("под %q подходит %d профилей — уточни селектор", selector, matches)
	}
}

func (h *RouterHandler) subSetURL(args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("usage: sub_seturl <url>")
	}
	h.Config.Subscription = &config.Subscription{URL: args[0]}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	return "subscription URL set; run sub_refresh to fetch it", nil
}

func (h *RouterHandler) subRefresh(ctx context.Context) (string, error) {
	if h.Config.Subscription == nil || h.Config.Subscription.URL == "" {
		return "", fmt.Errorf("no subscription URL set -- run sub_seturl first")
	}

	var primaryKey, backupKey string
	if p := h.Config.Primary(); p != nil {
		primaryKey = p.Remark
	}
	if b := h.Config.Backup(); b != nil {
		backupKey = b.Remark
	}

	result, err := subscription.Refresh(ctx, h.Config.Subscription.URL, primaryKey, backupKey)
	if err != nil {
		return "", err
	}

	warnings := subscription.ApplyResult(h.Config, result)
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx) // profiles may have changed -- restart xray on them now

	var b strings.Builder
	fmt.Fprintf(&b, "refreshed: %d profiles\n", len(result.Profiles))
	for _, w := range warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String(), nil
}

func (h *RouterHandler) subSetRole(ctx context.Context, args []string, primary bool) (string, error) {
	word := "backup"
	if primary {
		word = "primary"
	}
	if len(args) != 1 {
		return "", fmt.Errorf("usage: sub_set%s <index>", word)
	}
	idx, err := strconv.Atoi(args[0])
	if err != nil {
		return "", fmt.Errorf("invalid index %q: %w", args[0], err)
	}
	if idx < 0 || idx >= len(h.Config.Profiles) {
		return "", fmt.Errorf("index %d out of range (%d profiles)", idx, len(h.Config.Profiles))
	}

	if primary {
		h.Config.PrimaryIndex = idx
		if h.Config.Subscription != nil {
			h.Config.Subscription.PrimaryKey = h.Config.Profiles[idx].Remark
		}
	} else {
		h.Config.BackupIndex = idx
		if h.Config.Subscription != nil {
			h.Config.Subscription.BackupKey = h.Config.Profiles[idx].Remark
		}
	}

	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx) // the live slot may now point at a different profile

	return fmt.Sprintf("%s set to profile %d (%s)", word, idx, h.Config.Profiles[idx].Remark), nil
}
