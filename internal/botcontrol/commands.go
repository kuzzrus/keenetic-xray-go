package botcontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
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

	// InitScript is the daemon's init.d script, exec'd by the
	// daemon_restart action. Empty -> that action returns an error.
	InitScript string

	// InstallURL is the install.sh the self_update action re-runs.
	// Empty -> defaultInstallURL.
	InstallURL string
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
	case ActionDaemonRestart:
		return h.daemonRestart()
	case ActionEnsureCore:
		return h.ensureCore(ctx)
	case ActionSelfUpdate:
		return h.selfUpdate()
	case ActionFailoverShow:
		return h.Config.Failover.TunablesText(), nil
	case ActionFailoverSet:
		return h.setFailoverTunable(cmd.Args)
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
	if snap, ok := h.Daemon.Snapshot(ctx); ok {
		_ = h.Daemon.ForceSwitch(ctx, snap.LiveRole)
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

// daemonRestart spawns a detached "restart after a short delay" so this
// process can post the command result before the init script SIGTERMs
// it. The replacement daemon reconnects on its own and emits daemon_start.
func (h *RouterHandler) daemonRestart() (string, error) {
	if err := h.restartDaemonDetached(); err != nil {
		return "", err
	}
	return "перезапуск демона через 2с…", nil
}

// setFailoverTunable adjusts one health-check/failover knob and restarts
// the daemon to apply it -- the Machine reads Config once at
// construction, there is no live reload for these.
func (h *RouterHandler) setFailoverTunable(args []string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("usage: set <key> <value>")
	}
	if err := h.Config.Failover.SetTunable(args[0], args[1]); err != nil {
		return "", err
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	msg := fmt.Sprintf("%s = %s.", args[0], args[1])
	if err := h.restartDaemonDetached(); err != nil {
		msg += " Перезапусти демон вручную, чтобы применить: " + err.Error()
	} else {
		msg += " Демон перезапускается (~2с), чтобы применить."
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
// runs, acceptable for a personal single-router setup.
func (h *RouterHandler) ensureCore(ctx context.Context) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	src, err := xraycore.Ensure(cctx, xraycore.Options{Dest: h.XrayBinary})
	if err != nil {
		return "", err
	}
	if v, verr := xraycore.Version(h.XrayBinary); verr == nil {
		return fmt.Sprintf("xray-core готов (%s): %s", src, v), nil
	}
	return fmt.Sprintf("xray-core установлен (%s)", src), nil
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
	word, mirrored := "backup", false
	if primary {
		h.Config.PrimaryIndex = idx
		h.Config.PrimarySource = slot
		word = "primary"
		if !h.slotSet(h.Config.BackupIndex) {
			h.Config.BackupIndex = idx // no backup yet -- mirror so the daemon can run
			mirrored = true
		}
	} else {
		h.Config.BackupIndex = idx
		h.Config.BackupSource = slot
		if !h.slotSet(h.Config.PrimaryIndex) {
			h.Config.PrimaryIndex = idx
			mirrored = true
		}
	}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)

	msg := fmt.Sprintf("%s ← %s", word, prof.Remark)
	if mirrored {
		other := "backup"
		if !primary {
			other = "primary"
		}
		msg += fmt.Sprintf(" (%s тоже — задай ему отдельный источник для настоящего failover)", other)
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
