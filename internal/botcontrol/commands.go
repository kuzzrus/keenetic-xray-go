package botcontrol

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
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
}

// Handle implements Handler.
func (h *RouterHandler) Handle(ctx context.Context, cmd Command) (string, error) {
	switch cmd.Action {
	case ActionStatus:
		return h.status(ctx), nil
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
	if state, ran := h.Daemon.State(ctx); ran {
		fmt.Fprintf(&b, "failover state: %s\n", state)
	} else {
		fmt.Fprintf(&b, "failover state: unknown (daemon not responding)\n")
	}
	if p := h.Config.Primary(); p != nil {
		fmt.Fprintf(&b, "primary: %s\n", p.Remark)
	}
	if bk := h.Config.Backup(); bk != nil {
		fmt.Fprintf(&b, "backup: %s\n", bk.Remark)
	}
	return b.String()
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
