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

	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/health"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/selfupdate"
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

	// DaemonLog is the daemon's own rolling log file (applog), tailed by
	// the daemon_log action. Empty -> that action returns an error.
	DaemonLog string

	// QualityStatePath is the all-profiles quality-sweep result file
	// (health.State). Empty or absent -> status just omits that block.
	QualityStatePath string

	// SelfUpdateMarker is where selfUpdate drops its rollback marker
	// (selfupdate.Marker) before re-running install.sh. Empty -> no
	// rollback point is recorded (the update still runs).
	SelfUpdateMarker string
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
	// The WG-transport pre-shared / secret keys can land in a failed
	// ndmc command echoed back in an error.
	for _, k := range []string{h.Config.WGTransport.PSK, h.Config.WGTransport.XraySecretKey} {
		if k != "" {
			s = strings.ReplaceAll(s, k, "<wg-ключ>")
		}
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
	case ActionSetMSS:
		return h.setMSS(ctx, cmd.Args)
	case ActionWGTransportShow:
		return h.wgTransportShow(ctx)
	case ActionWGTransportOn:
		return h.wgTransportOn(ctx)
	case ActionWGTransportOff:
		return h.wgTransportOff(ctx)
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
	case ActionDaemonLog:
		return h.daemonLog(cmd.Args)
	case ActionSetPorts:
		return h.setPorts(ctx, cmd.Args)
	case ActionRoutesList:
		return h.routesListText(), nil
	case ActionRoutesShow:
		return h.routesShow(ctx, cmd.Args)
	case ActionRoutesManual:
		return h.routesManual(ctx)
	case ActionRoutesAdd:
		return h.routesAdd(ctx, cmd.Args)
	case ActionRoutesDel:
		return h.routesDel(ctx, cmd.Args)
	case ActionRoutesRemoveList:
		return h.routesRemoveList(ctx, cmd.Args)
	case ActionRoutesToggle:
		return h.routesToggle(ctx, cmd.Args)
	case ActionRoutesSetIface:
		return h.routesSetIface(ctx, cmd.Args)
	case ActionRoutesNames:
		return h.routesNames(), nil
	case ActionRoutesPresetList:
		return h.routesPresetList(), nil
	case ActionRoutesPresetAdd:
		return h.routesPresetAdd(ctx, cmd.Args)
	case ActionRoutesPresetSync:
		return h.routesPresetSync(ctx, cmd.Args)
	case ActionRoutesPresetUpdate:
		return h.routesPresetUpdate(ctx)
	case ActionDNSShow:
		return h.dnsShow(ctx)
	case ActionDNSTest:
		return h.dnsTest(ctx, cmd.Args)
	case ActionDNSPreset:
		return h.dnsPreset(ctx, cmd.Args)
	case ActionDNSSet:
		return h.dnsSet(ctx, cmd.Args)
	case ActionDNSOff:
		return h.dnsOff(ctx)
	case ActionAddonList:
		return h.addonList(ctx)
	case ActionAddonShow:
		return h.addonShow(ctx, cmd.Args)
	case ActionAddonStatus:
		return h.addonStatus(ctx, cmd.Args)
	case ActionAddonInstall:
		return h.addonInstall(ctx, cmd.Args)
	case ActionAddonRemove:
		return h.addonRemove(ctx, cmd.Args)
	case ActionAddonConfigure:
		return h.addonConfigure(ctx, cmd.Args)
	case ActionDiag:
		return h.diag(ctx)
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

	// xray listens on both local inbounds at once; show each with its
	// state so a Proxy0 pointed at the "wrong" one is obvious.
	fmt.Fprintf(&b, "xray: %s", portState(h.Config.Failover.SOCKSPort, "socks5"))
	if hp := h.Config.Failover.HTTPPort; hp != 0 {
		fmt.Fprintf(&b, ", %s", portState(hp, "http"))
	}
	b.WriteByte('\n')

	// Router -> xray transports. Proxy0 and the WG transport can both be
	// on at once, so render whichever are configured.
	if h.Config.Proxy0.Enabled {
		fmt.Fprintf(&b, "proxy0: вкл → %s/%s", h.Config.Proxy0.IfaceName(), h.Config.Proxy0.ProtoName())
		if keenetic.Available() {
			if host, port, ok, err := keenetic.Proxy0Upstream(ctx, h.Config.Proxy0.Interface); err == nil && ok {
				fmt.Fprintf(&b, " → %s:%d", host, port)
			}
		}
		b.WriteByte('\n')
	} else {
		b.WriteString("proxy0: выкл\n")
	}
	if w := h.Config.WGTransport; w.Enabled {
		fmt.Fprintf(&b, "wg-транспорт: вкл → %s :%d", w.Iface, w.WGPort())
		if keenetic.Available() && w.Iface != "" {
			if keenetic.WGInterfaceUp(ctx, w.Iface) {
				b.WriteString(" (поднят)")
			} else {
				b.WriteString(" (не поднят ⚠️)")
			}
		}
		b.WriteByte('\n')
	}

	if s := h.Config.Subscription; s != nil && s.URL != "" {
		if s.LastFetchedAt.IsZero() {
			fmt.Fprintf(&b, "подписка: %d профилей, ещё не обновлялась\n", len(h.Config.Profiles))
		} else {
			fmt.Fprintf(&b, "подписка: %d профилей, обновлена %s назад\n",
				len(h.Config.Profiles), shortDur(time.Since(s.LastFetchedAt)))
		}
	}

	if h.QualityStatePath != "" {
		if block := health.StatusLines(health.Load(h.QualityStatePath), time.Now()); block != "" {
			b.WriteString(block)
			b.WriteByte('\n')
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

	if mss := h.Config.Proxy0.MSSClampValue(); h.Config.Proxy0.Enabled && mss > 0 && keenetic.Available() && keenetic.IptablesPresent() {
		check(keenetic.MSSClampInPlace(ctx, mss), fmt.Sprintf("MSS-клампинг %d на месте", mss))
	}

	if w := h.Config.WGTransport; w.Enabled && w.Iface != "" && keenetic.Available() {
		check(keenetic.WGInterfaceUp(ctx, w.Iface), "WG-транспорт "+w.Iface+" поднят")
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

// portState renders "слушает :PORT (label)" or "НЕ слушает :PORT (label) ⚠️"
// for one of xray's local inbounds.
func portState(port int, label string) string {
	if portListening(port) {
		return fmt.Sprintf("слушает :%d (%s)", port, label)
	}
	return fmt.Sprintf("НЕ слушает :%d (%s) ⚠️", port, label)
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
		fmt.Fprintf(&b, "upstream: ошибка чтения (%v)\n", err)
	case ok:
		fmt.Fprintf(&b, "upstream: %s:%d\n", host, port)
	default:
		b.WriteString("upstream: не задан\n")
	}
	fmt.Fprintf(&b, "MSS-клампинг: %s", h.Config.Proxy0.MSSClampText())
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

// setMSS sets Proxy0.MSSClamp and, while Proxy0 is on, (re)installs the
// forwarded-TCP MSS-clamp rule -- the PMTU black-hole fix. args[0] is
// "auto" | "off" | a 1200..1452 decimal. Pulls in iptables via opkg if
// the router doesn't have it.
func (h *RouterHandler) setMSS(ctx context.Context, args []string) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("usage: set_mss <auto|off|1200..1452>")
	}
	v, err := config.ParseMSSClampArg(args[0])
	if err != nil {
		return "", err
	}
	h.Config.Proxy0.MSSClamp = v
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	summary := "MSS-клампинг (Proxy0): " + h.Config.Proxy0.MSSClampText()

	if !h.Config.Proxy0.Enabled {
		return summary + "\nсохранено — применится при включении proxy0", nil
	}
	mss := h.Config.Proxy0.MSSClampValue()
	if mss <= 0 {
		if err := keenetic.ClearMSSClamp(ctx); err != nil {
			return "", fmt.Errorf("снятие правила: %w", err)
		}
		return summary + "\nправило снято", nil
	}
	var note string
	if !keenetic.IptablesPresent() {
		if err := keenetic.EnsureIptables(ctx); err != nil {
			return "", fmt.Errorf("iptables недоступен: %w", err)
		}
		note = "\niptables установлен через opkg"
	}
	if err := keenetic.SetMSSClamp(ctx, mss); err != nil {
		return "", err
	}
	return summary + note + fmt.Sprintf("\nправило установлено: forwarded TCP MSS → %d", mss), nil
}

// wgTransportShow reports the in-router WireGuard transport state (config
// + live interface).
func (h *RouterHandler) wgTransportShow(ctx context.Context) (string, error) {
	w := h.Config.WGTransport
	var b strings.Builder
	switch {
	case !w.Enabled:
		b.WriteString("WG-транспорт: выкл")
	case !w.Ready():
		iface := w.Iface
		if iface == "" {
			iface = "интерфейс не выбран"
		}
		fmt.Fprintf(&b, "WG-транспорт: вкл (%s) — ключи ещё не согласованы", iface)
	default:
		fmt.Fprintf(&b, "WG-транспорт: вкл — %s, xray :%d, MTU %d", w.Iface, w.WGPort(), w.WGMTU())
	}
	if keenetic.Available() && w.Iface != "" {
		if live, err := keenetic.ShowWGTransport(ctx, w.Iface); err == nil && live != "" {
			b.WriteString("\n" + live)
		}
	}
	return b.String(), nil
}

// wgTransportOn creates/reconciles the Keenetic WireGuard interface,
// generating the xray-side keypair + PSK on first run, and rebinds xray
// so the `wireguard` inbound comes up.
func (h *RouterHandler) wgTransportOn(ctx context.Context) (string, error) {
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — работает только на роутере Keenetic")
	}
	if _, err := h.Config.WGTransport.EnsureKeys(); err != nil {
		return "", err
	}
	ip, err := keenetic.LANIP(ctx, h.Config.Proxy0.LANIP)
	if err != nil {
		return "", fmt.Errorf("определение LAN IP роутера: %w", err)
	}
	if h.Config.WGTransport.Iface == "" {
		iface, err := keenetic.FreeWireguardIface(ctx)
		if err != nil {
			return "", err
		}
		h.Config.WGTransport.Iface = iface
	}
	w := h.Config.WGTransport
	spec := keenetic.WGTransportSpec{
		Iface:      w.Iface,
		Address:    w.WGAddr(),
		MTU:        w.WGMTU(),
		PeerPubKey: w.XrayPublicKey,
		PeerPSK:    w.PSK,
		Endpoint:   net.JoinHostPort(ip, strconv.Itoa(w.WGPort())),
		Keepalive:  25,
	}
	kpub, err := keenetic.ApplyWGTransport(ctx, spec)
	if err != nil {
		return "", err
	}
	h.Config.WGTransport.Enabled = true
	h.Config.WGTransport.KeeneticPublicKey = kpub
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return fmt.Sprintf("WG-транспорт включён: %s (MTU %d), xray :%d.\n"+
		"Заворачивай трафик: 📍 Маршруты → список с интерфейсом %s (или политикой Keenetic).",
		spec.Iface, spec.MTU, w.WGPort(), spec.Iface), nil
}

// wgTransportOff removes the Keenetic WireGuard interface and rebinds
// xray without the inbound. Keys stay in config for a fast re-enable.
func (h *RouterHandler) wgTransportOff(ctx context.Context) (string, error) {
	if keenetic.Available() {
		if err := keenetic.ClearWGTransport(ctx); err != nil {
			return "", err
		}
	}
	h.Config.WGTransport.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return "WG-транспорт выключен (интерфейс снят; xray перестроен без wg-inbound)", nil
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

// daemonLog tails the daemon's own rolling log (applog). args[0], if
// given, is the line count; default 200, capped at 500 so a reply fits a
// chat message.
func (h *RouterHandler) daemonLog(args []string) (string, error) {
	if h.DaemonLog == "" {
		return "", fmt.Errorf("лог демона не настроен для этого агента")
	}
	n := 200
	if len(args) > 0 {
		if v, err := strconv.Atoi(strings.TrimSpace(args[0])); err == nil && v > 0 {
			n = v
		}
	}
	if n > 500 {
		n = 500
	}
	out, err := applog.Tail(h.DaemonLog, n)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "" {
		return "лог пуст", nil
	}
	return out, nil
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
//
// First it drops a rollback marker (the version being left + the exact
// .ipk URL to get back to it) so the restarted daemon can watch itself
// come up and, if it doesn't, hand the operator a one-line
// `keenetic-xray internal self-rollback`.
func (h *RouterHandler) selfUpdate() (string, error) {
	url := h.InstallURL
	if url == "" {
		url = defaultInstallURL
	}

	rollbackNote := ""
	if h.SelfUpdateMarker != "" {
		if m, err := selfupdate.NewMarker(version.Version, nil); err != nil {
			rollbackNote = " (без точки отката: " + err.Error() + ")"
		} else if err := selfupdate.WriteMarker(h.SelfUpdateMarker, m); err != nil {
			rollbackNote = " (маркер отката не записан: " + err.Error() + ")"
		}
	}

	c := exec.Command("sh", "-c", "sleep 2; curl -fsSL "+url+" | sh")
	if err := c.Start(); err != nil {
		return "", fmt.Errorf("запуск обновления: %w", err)
	}
	go func() { _ = c.Wait() }()
	return "обновление агента запущено — переустановка .ipk и рестарт демона через ~2с" + rollbackNote, nil
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
				return "", fmt.Errorf("тег %q: нужен вид v26.9.8 или \"stable\"", args[0])
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

	prof, err := subscription.ResolveSource(ctx, src, selector)
	if err != nil {
		return "", err
	}
	idx := h.Config.UpsertProfile(prof)
	slot := &config.SlotSource{URL: src, Selector: selector, ImportKey: prof.ImportKey()}

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
	hasShared := h.Config.Subscription != nil && h.Config.Subscription.URL != ""
	hasSlots := h.Config.PrimarySource != nil || h.Config.BackupSource != nil
	if !hasShared && !hasSlots {
		return "", fmt.Errorf("нет ни подписки, ни источников слотов -- задай sub_seturl или 🔗 Источники")
	}

	var b strings.Builder

	if hasShared {
		var primaryKey, backupKey string
		if p := h.Config.Primary(); p != nil {
			primaryKey = p.Remark
		}
		if bk := h.Config.Backup(); bk != nil {
			backupKey = bk.Remark
		}
		result, err := subscription.Refresh(ctx, h.Config.Subscription.URL, primaryKey, backupKey)
		if err != nil {
			return "", err
		}
		for _, w := range subscription.ApplyResult(h.Config, result) {
			fmt.Fprintf(&b, "⚠️ %s\n", w)
		}
		fmt.Fprintf(&b, "подписка: %d профилей\n", len(result.Profiles))
	}

	// Independently-sourced slots (PrimarySource/BackupSource) are left
	// untouched by a shared-subscription refresh above, so re-fetch each
	// here -- otherwise a provider's node changes (and this build's new
	// xhttp_extra parsing) never land without re-pasting the URL by hand.
	for _, s := range []struct {
		name    string
		src     *config.SlotSource
		primary bool
	}{
		{"основной", h.Config.PrimarySource, true},
		{"резервный", h.Config.BackupSource, false},
	} {
		if s.src == nil {
			continue
		}
		prof, key, err := subscription.ResolveSourcePinned(ctx, s.src.URL, s.src.Selector, s.src.ImportKey)
		if err != nil {
			fmt.Fprintf(&b, "⚠️ источник (%s): %v\n", s.name, err)
			continue
		}
		s.src.ImportKey = key // anchor (or backfill) so future refreshes stay on this server
		idx := h.Config.UpsertProfile(prof)
		if s.primary {
			h.Config.PrimaryIndex = idx
		} else {
			h.Config.BackupIndex = idx
		}
		fmt.Fprintf(&b, "источник (%s) ← %s\n", s.name, prof.Remark)
	}

	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx) // profiles may have changed -- restart xray on them now

	if b.Len() == 0 {
		return "нечего обновлять", nil
	}
	return strings.TrimRight(b.String(), "\n"), nil
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
