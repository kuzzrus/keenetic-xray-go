package botcontrol

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
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
}

// Handle implements Handler.
func (h *RouterHandler) Handle(ctx context.Context, cmd Command) (string, error) {
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
		return h.subSetRole(cmd.Args, true)
	case ActionSubSetBackup:
		return h.subSetRole(cmd.Args, false)
	default:
		return "", fmt.Errorf("unknown action %q", cmd.Action)
	}
}

func (h *RouterHandler) status(ctx context.Context) string {
	var b strings.Builder
	fmt.Fprintf(&b, "variant: %s\n", h.Config.Variant)

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
	case t.To == failover.StateActiveBackup && t.From == failover.StateTestingRecovery:
		return "откат на backup (возврат не подтвердился)"
	case t.To == failover.StateActiveBackup:
		return "переключение на backup"
	case t.To == failover.StateActivePrimary:
		return "возврат на primary"
	case t.To == failover.StateTestingRecovery:
		return "проверка восстановления primary"
	case t.To == failover.StateCooldown && t.From == failover.StateActivePrimary:
		return "primary недоступен — уход на backup"
	case t.To == failover.StateCooldown && t.From == failover.StateTestingRecovery:
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

	var b strings.Builder
	fmt.Fprintf(&b, "refreshed: %d profiles\n", len(result.Profiles))
	for _, w := range warnings {
		fmt.Fprintf(&b, "warning: %s\n", w)
	}
	return b.String(), nil
}

func (h *RouterHandler) subSetRole(args []string, primary bool) (string, error) {
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
	return fmt.Sprintf("%s set to profile %d (%s)", word, idx, h.Config.Profiles[idx].Remark), nil
}
