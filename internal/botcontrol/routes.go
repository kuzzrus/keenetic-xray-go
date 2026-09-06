package botcontrol

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// The routes_* actions manage named DNS-route lists: domains/subnets that
// Keenetic's DNS-based routing (KeeneticOS 5.0+) sends through the Proxy0
// interface -- i.e. the tunnel. Each list is one router-side
// `object-group fqdn keenetic-xray-<name>` plus a `dns-proxy route`.
// These handlers are the exact CLI logic (cmd/keenetic-xray/routes.go)
// re-exposed over the bot protocol.

func (h *RouterHandler) routeList(name string) (*config.RouteList, int) {
	for i := range h.Config.Routing.Lists {
		if strings.EqualFold(h.Config.Routing.Lists[i].Name, name) {
			return &h.Config.Routing.Lists[i], i
		}
	}
	return nil, -1
}

// routesNames renders the route lists in a tab-separated, machine-
// readable form -- "name<TAB>count<TAB>on|off<TAB>iface" per line, empty
// when there are none. The bot parses this to build one button per list
// (tab can't appear in a list name -- ValidRouteListName rejects control
// chars). Kept separate from routesListText, which is for humans.
func (h *RouterHandler) routesNames() string {
	var b strings.Builder
	for _, l := range h.Config.Routing.Lists {
		state := "on"
		if l.Disabled {
			state = "off"
		}
		fmt.Fprintf(&b, "%s\t%d\t%s\t%s\n", l.Name, len(l.Entries), state, l.RouteIface())
	}
	return strings.TrimRight(b.String(), "\n")
}

func (h *RouterHandler) routesListText() string {
	ls := h.Config.Routing.Lists
	if len(ls) == 0 {
		return "списков маршрутов нет.\nСоздать: ➕ Новый список, или /routes <роутер> new <имя> <домены…>"
	}
	var b strings.Builder
	for _, l := range ls {
		state := "✅"
		if l.Disabled {
			state = "⛔"
		}
		excl := ""
		if l.Exclusive {
			excl = " · reject"
		}
		fmt.Fprintf(&b, "📁 %s · %d · %s → %s%s\n", l.Name, len(l.Entries), state, l.RouteIface(), excl)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (h *RouterHandler) routesShow(ctx context.Context, args []string) (string, error) {
	only := ""
	if len(args) > 0 {
		only = args[0]
	}
	var b strings.Builder
	if !keenetic.Available() {
		b.WriteString("ndmc недоступен — показываю только конфиг.\n\n")
	}
	live := map[string]keenetic.LiveRoute{}
	if keenetic.Available() {
		lr, err := keenetic.ShowRoutes(ctx)
		if err != nil {
			return "", err
		}
		for _, r := range lr {
			live[r.Group] = r
		}
	}
	for _, l := range h.Config.Routing.Lists {
		if only != "" && !strings.EqualFold(l.Name, only) {
			continue
		}
		grp := keenetic.RouteGroupPrefix + config.SanitizeRouteListName(l.Name)
		fmt.Fprintf(&b, "📁 %s\n  конфиг: %d записей, %s%s\n", l.Name, len(l.Entries), routeStateWord(l.Disabled), routeExclWord(l.Exclusive))
		r, on := live[grp]
		switch {
		case !keenetic.Available():
		case !on:
			b.WriteString("  роутер: нет\n")
		case r.Iface == "":
			fmt.Fprintf(&b, "  роутер: %d записей, не маршрутизируется\n", len(r.Entries))
		default:
			rej := ""
			if r.Reject {
				rej = " reject"
			}
			fmt.Fprintf(&b, "  роутер: %d записей, → %s%s\n", len(r.Entries), r.Iface, rej)
		}
	}
	if b.Len() == 0 {
		return "нет такого списка", nil
	}
	for g := range live {
		if h.listForGroup(g) == nil {
			fmt.Fprintf(&b, "⚠️ на роутере есть наша группа %s без записи в конфиге — уберётся при следующем применении\n", g)
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func (h *RouterHandler) listForGroup(group string) *config.RouteList {
	for i := range h.Config.Routing.Lists {
		if keenetic.RouteGroupPrefix+config.SanitizeRouteListName(h.Config.Routing.Lists[i].Name) == group {
			return &h.Config.Routing.Lists[i]
		}
	}
	return nil
}

func (h *RouterHandler) routesAdd(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return "", fmt.Errorf("usage: routes_add <имя> <записи>")
	}
	name := strings.TrimSpace(args[0])
	l, _ := h.routeList(name)
	created := false
	if l == nil {
		if !config.ValidRouteListName(name) {
			return "", fmt.Errorf("имя %q: 1..32 символа, минимум одна латинская буква/цифра", name)
		}
		h.Config.Routing.Lists = append(h.Config.Routing.Lists, config.RouteList{Name: name})
		l = &h.Config.Routing.Lists[len(h.Config.Routing.Lists)-1]
		created = true
	}

	added, rejected := mergeRouteEntries(l, splitRouteEntries(args[1]))
	head := fmt.Sprintf("список %q", name)
	if created {
		head = fmt.Sprintf("создан список %q", name)
	}
	msg := fmt.Sprintf("%s: +%d записей", head, len(added))
	if len(rejected) > 0 {
		msg += fmt.Sprintf(", отклонено %d:\n  %s", len(rejected), strings.Join(rejected, "\n  "))
	}
	return h.applyRoutes(ctx, msg)
}

func (h *RouterHandler) routesDel(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return "", fmt.Errorf("usage: routes_del <имя> <записи>")
	}
	l, _ := h.routeList(strings.TrimSpace(args[0]))
	if l == nil {
		return "", fmt.Errorf("нет списка %q", args[0])
	}
	remove := map[string]struct{}{}
	for _, raw := range splitRouteEntries(args[1]) {
		if _, norm, err := config.ClassifyRouteEntry(raw); err == nil {
			remove[strings.ToLower(norm)] = struct{}{}
		} else {
			remove[strings.ToLower(strings.TrimSpace(raw))] = struct{}{}
		}
	}
	kept, n := l.Entries[:0], 0
	for _, e := range l.Entries {
		if _, drop := remove[strings.ToLower(e)]; drop {
			n++
			continue
		}
		kept = append(kept, e)
	}
	l.Entries = kept
	return h.applyRoutes(ctx, fmt.Sprintf("список %q: -%d записей", l.Name, n))
}

func (h *RouterHandler) routesRemoveList(ctx context.Context, args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: routes_rmlist <имя>")
	}
	_, idx := h.routeList(strings.TrimSpace(args[0]))
	if idx < 0 {
		return "", fmt.Errorf("нет списка %q", args[0])
	}
	name := h.Config.Routing.Lists[idx].Name
	h.Config.Routing.Lists = append(h.Config.Routing.Lists[:idx], h.Config.Routing.Lists[idx+1:]...)
	return h.applyRoutes(ctx, fmt.Sprintf("список %q удалён", name))
}

func (h *RouterHandler) routesToggle(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: routes_toggle <имя> <on|off>")
	}
	l, _ := h.routeList(strings.TrimSpace(args[0]))
	if l == nil {
		return "", fmt.Errorf("нет списка %q", args[0])
	}
	l.Disabled = args[1] == "off"
	return h.applyRoutes(ctx, fmt.Sprintf("список %q: %s", l.Name, routeStateWord(l.Disabled)))
}

// routesSetIface repoints one list at another interface -- a Proxy
// interface or a WireGuard one (including the in-router WG transport's
// Wireguard4, or a hand-made Keenetic tunnel). The route is re-issued
// onto the new interface and cleared off the old one by applyRoutes'
// full reconcile.
func (h *RouterHandler) routesSetIface(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: routes_setiface <имя> <интерфейс>")
	}
	iface := strings.TrimSpace(args[1])
	if iface == "" || !config.ValidRouteIface(iface) {
		return "", fmt.Errorf("интерфейс %q: нужно имя вида Proxy0 или Wireguard4", args[1])
	}
	l, _ := h.routeList(strings.TrimSpace(args[0]))
	if l == nil {
		return "", fmt.Errorf("нет списка %q", args[0])
	}
	l.Interface = iface
	return h.applyRoutes(ctx, fmt.Sprintf("список %q: → %s", l.Name, l.RouteIface()))
}

// applyRoutes saves the config (Validate runs in Save) and pushes the
// full route set to the router. Best-effort on the router side, reported
// inline -- the config change already took.
func (h *RouterHandler) applyRoutes(ctx context.Context, okMsg string) (string, error) {
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if !keenetic.Available() {
		return okMsg + "\n(сохранено; на роутере применится при следующем запуске демона)", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyRoutes(cctx, botDesiredRoutes(h.Config.Routing))
	if err != nil {
		return okMsg + fmt.Sprintf("\n⚠️ на роутере не применилось: %v", err), nil
	}
	return okMsg + fmt.Sprintf("\nроутер: +%d/-%d записей, групп +%d/-%d", rep.EntriesAdded, rep.EntriesRemoved, len(rep.GroupsCreated), len(rep.GroupsRemoved)), nil
}

func botDesiredRoutes(rc config.RoutingConfig) []keenetic.DesiredRoute {
	out := make([]keenetic.DesiredRoute, 0, len(rc.Lists))
	for _, l := range rc.Lists {
		out = append(out, keenetic.DesiredRoute{
			Group:    keenetic.RouteGroupPrefix + config.SanitizeRouteListName(l.Name),
			Iface:    l.RouteIface(),
			Entries:  l.Entries,
			Reject:   l.Exclusive,
			Disabled: l.Disabled,
		})
	}
	return out
}

func splitRouteEntries(blob string) []string {
	return strings.FieldsFunc(blob, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '\r'
	})
}

// mergeRouteEntries classifies + dedupes raw entries into l, returning
// the accepted (normalized) and the rejected (reason strings).
func mergeRouteEntries(l *config.RouteList, raw []string) (added, rejected []string) {
	have := map[string]struct{}{}
	for _, e := range l.Entries {
		have[strings.ToLower(e)] = struct{}{}
	}
	for _, r := range raw {
		_, norm, err := config.ClassifyRouteEntry(r)
		if err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		if _, dup := have[strings.ToLower(norm)]; dup {
			continue
		}
		have[strings.ToLower(norm)] = struct{}{}
		l.Entries = append(l.Entries, norm)
		added = append(added, norm)
	}
	sort.Strings(l.Entries)
	return added, rejected
}

func routeStateWord(disabled bool) string {
	if disabled {
		return "выкл"
	}
	return "вкл"
}

func routeExclWord(excl bool) string {
	if excl {
		return " · reject"
	}
	return ""
}
