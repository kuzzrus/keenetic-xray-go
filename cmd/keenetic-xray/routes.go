package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// cmdRoutes manages named DNS-route lists: domains/subnets that Keenetic's
// DNS-based routing (KeeneticOS 5.0+) sends through the Proxy0 interface
// -- i.e. the tunnel -- while everything else stays direct. Each list is
// one router-side `object-group fqdn keenetic-xray-<name>` plus a
// `dns-proxy route`. The bot's 📍 Маршруты screen drives the same
// config + keenetic.ApplyRoutes path.
func cmdRoutes(args []string) error {
	if len(args) == 0 {
		return routesUsage()
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		return routesList(cfg)
	case "show":
		return routesShow(cfg, args[1:])
	case "manual":
		return routesManualCmd()
	case "new", "add":
		return routesAddEntries(cfg, args[0] == "new", args[1:])
	case "del":
		return routesDelEntries(cfg, args[1:])
	case "rm":
		return routesRemoveList(cfg, args[1:])
	case "enable", "disable":
		return routesToggle(cfg, args[0] == "enable", args[1:])
	case "set":
		return routesSet(cfg, args[1:])
	case "preset":
		return routesPreset(cfg, args[1:])
	case "apply":
		return routesApply(cfg, "маршруты применены")
	default:
		return routesUsage()
	}
}

func routesUsage() error {
	return fmt.Errorf("usage: keenetic-xray routes {list | show [name] | manual | new <name> [entries…] | " +
		"add <name> <entries…> | del <name> <entries…> | rm <name> | enable <name> | disable <name> | " +
		"set <name> [--iface=Proxy0|Wireguard4] [--exclusive] [--no-exclusive] | " +
		"preset {list | show <name> | add <name> [--ip] [--iface=…] [--exclusive] | sync [<name>|--all] | update} | apply}")
}

func findList(cfg *config.Config, name string) (*config.RouteList, int) {
	for i := range cfg.Routing.Lists {
		if strings.EqualFold(cfg.Routing.Lists[i].Name, name) {
			return &cfg.Routing.Lists[i], i
		}
	}
	return nil, -1
}

func routesList(cfg *config.Config) error {
	if len(cfg.Routing.Lists) == 0 {
		fmt.Println("списков нет — создать: keenetic-xray routes new <имя> <домены…>")
		return nil
	}
	for _, l := range cfg.Routing.Lists {
		state := "вкл"
		if l.Disabled {
			state = "выкл"
		}
		excl := ""
		if l.Exclusive {
			excl = " reject"
		}
		fmt.Printf("%-24s %3d зап.  %s → %s%s\n", l.Name, len(l.Entries), state, l.RouteIface(), excl)
	}
	return nil
}

func routesShow(cfg *config.Config, args []string) error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — эта команда работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	live, err := keenetic.ShowRoutes(ctx)
	if err != nil {
		return err
	}
	liveByGroup := map[string]keenetic.LiveRoute{}
	for _, lr := range live {
		liveByGroup[lr.Group] = lr
	}

	only := ""
	if len(args) > 0 {
		only = args[0]
	}
	for _, l := range cfg.Routing.Lists {
		if only != "" && !strings.EqualFold(l.Name, only) {
			continue
		}
		grp := keenetic.RouteGroupPrefix + config.SanitizeRouteListName(l.Name)
		lr, onRouter := liveByGroup[grp]
		fmt.Printf("%s (%s):\n", l.Name, grp)
		fmt.Printf("  в конфиге: %d записей, %s%s\n", len(l.Entries), routeState(l.Disabled), routeExcl(l.Exclusive))
		if !onRouter {
			fmt.Println("  на роутере: нет")
			continue
		}
		routed := "не маршрутизируется"
		if lr.Iface != "" {
			routed = "→ " + lr.Iface
			if lr.Reject {
				routed += " reject"
			}
		}
		fmt.Printf("  на роутере: %d записей, %s\n", len(lr.Entries), routed)
	}
	// Our groups on the router that aren't in the config at all (drift).
	for _, lr := range live {
		if listForGroup(cfg, lr.Group) == nil {
			fmt.Printf("⚠️ на роутере есть наша группа %s, которой нет в конфиге — уберётся при `routes apply`\n", lr.Group)
		}
	}
	return nil
}

// routesManualCmd lists the operator's own domain route lists on the
// router -- anything without RouteGroupPrefix, built by hand in the
// Keenetic web UI rather than through keenetic-xray. Read-only, no config
// counterpart to compare against.
func routesManualCmd() error {
	if !keenetic.Available() {
		return fmt.Errorf("ndmc не найден — эта команда работает только на роутере Keenetic")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	live, err := keenetic.ShowManualRoutes(ctx)
	if err != nil {
		return err
	}
	if len(live) == 0 {
		fmt.Println("на роутере нет других списков доменной маршрутизации, кроме сделанных через keenetic-xray.")
		return nil
	}
	fmt.Println("списки, добавленные не через keenetic-xray (только чтение):")
	for _, lr := range live {
		routed := "не маршрутизируется"
		if lr.Iface != "" {
			routed = "→ " + lr.Iface
			if lr.Reject {
				routed += " reject"
			}
		}
		fmt.Printf("%-24s %3d зап.  %s\n", lr.Group, len(lr.Entries), routed)
	}
	return nil
}

func routeState(disabled bool) string {
	if disabled {
		return "выкл"
	}
	return "вкл"
}

func routeExcl(excl bool) string {
	if excl {
		return ", reject"
	}
	return ""
}

func listForGroup(cfg *config.Config, group string) *config.RouteList {
	for i := range cfg.Routing.Lists {
		if keenetic.RouteGroupPrefix+config.SanitizeRouteListName(cfg.Routing.Lists[i].Name) == group {
			return &cfg.Routing.Lists[i]
		}
	}
	return nil
}

func routesAddEntries(cfg *config.Config, create bool, args []string) error {
	if len(args) < 1 {
		return routesUsage()
	}
	name := args[0]
	l, _ := findList(cfg, name)
	if l == nil {
		if !create {
			return fmt.Errorf("нет списка %q (создать: routes new %s …)", name, name)
		}
		if !config.ValidRouteListName(name) {
			return fmt.Errorf("имя %q: 1..32 символа, минимум одна латинская буква/цифра (станет именем object-group)", name)
		}
		cfg.Routing.Lists = append(cfg.Routing.Lists, config.RouteList{Name: name})
		l = &cfg.Routing.Lists[len(cfg.Routing.Lists)-1]
	}

	added, rejected := mergeEntries(l, splitEntries(args[1:]))
	printEntryResult("добавлено", added, rejected)
	return routesApply(cfg, fmt.Sprintf("список %q: %d записей", name, len(l.Entries)))
}

func routesDelEntries(cfg *config.Config, args []string) error {
	if len(args) < 2 {
		return routesUsage()
	}
	l, _ := findList(cfg, args[0])
	if l == nil {
		return fmt.Errorf("нет списка %q", args[0])
	}
	remove := map[string]struct{}{}
	for _, raw := range splitEntries(args[1:]) {
		if _, norm, err := config.ClassifyRouteEntry(raw); err == nil {
			remove[norm] = struct{}{}
		} else {
			remove[strings.ToLower(strings.TrimSpace(raw))] = struct{}{}
		}
	}
	kept := l.Entries[:0]
	n := 0
	for _, e := range l.Entries {
		if _, drop := remove[strings.ToLower(e)]; drop {
			n++
			continue
		}
		kept = append(kept, e)
	}
	l.Entries = kept
	fmt.Printf("убрано: %d\n", n)
	return routesApply(cfg, fmt.Sprintf("список %q: %d записей", l.Name, len(l.Entries)))
}

func routesRemoveList(cfg *config.Config, args []string) error {
	if len(args) < 1 {
		return routesUsage()
	}
	_, idx := findList(cfg, args[0])
	if idx < 0 {
		return fmt.Errorf("нет списка %q", args[0])
	}
	cfg.Routing.Lists = append(cfg.Routing.Lists[:idx], cfg.Routing.Lists[idx+1:]...)
	return routesApply(cfg, fmt.Sprintf("список %q удалён", args[0]))
}

func routesToggle(cfg *config.Config, enable bool, args []string) error {
	if len(args) < 1 {
		return routesUsage()
	}
	l, _ := findList(cfg, args[0])
	if l == nil {
		return fmt.Errorf("нет списка %q", args[0])
	}
	l.Disabled = !enable
	return routesApply(cfg, fmt.Sprintf("список %q: %s", l.Name, routeState(l.Disabled)))
}

func routesSet(cfg *config.Config, args []string) error {
	if len(args) < 1 {
		return routesUsage()
	}
	l, _ := findList(cfg, args[0])
	if l == nil {
		return fmt.Errorf("нет списка %q", args[0])
	}
	for _, a := range args[1:] {
		switch {
		case strings.HasPrefix(a, "--iface="):
			l.Interface = strings.TrimPrefix(a, "--iface=")
		case a == "--exclusive":
			l.Exclusive = true
		case a == "--no-exclusive":
			l.Exclusive = false
		default:
			return fmt.Errorf("неизвестный флаг %q", a)
		}
	}
	return routesApply(cfg, fmt.Sprintf("список %q: → %s%s", l.Name, l.RouteIface(), routeExcl(l.Exclusive)))
}

// routesApply saves the config (Validate runs inside Save) and pushes the
// full set to the router if ndmc is present.
func routesApply(cfg *config.Config, okMsg string) error {
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	if !keenetic.Available() {
		fmt.Println(okMsg + " (сохранено; на роутере применится при следующем запуске демона)")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyRoutes(ctx, desiredRoutes(cfg.Routing))
	if err != nil {
		return fmt.Errorf("%s, но применить на роутере не вышло: %w", okMsg, err)
	}
	fmt.Printf("%s. на роутере: +%d/-%d записей, групп +%d/-%d\n",
		okMsg, rep.EntriesAdded, rep.EntriesRemoved, len(rep.GroupsCreated), len(rep.GroupsRemoved))
	flushConntrackAfterRoutes(ctx, cfg, rep)
	return nil
}

// flushConntrackAfterRoutes moves already-open connections onto the new
// route when a route set actually changed: it deletes the conntrack
// entries for the IPs in our object-groups (falling back to a full flush
// if it can't enumerate them). No-op unless `conntrack` is installed.
func flushConntrackAfterRoutes(ctx context.Context, cfg *config.Config, rep keenetic.RouteReport) {
	if rep.EntriesAdded+rep.EntriesRemoved+len(rep.GroupsCreated)+len(rep.GroupsRemoved)+len(rep.RoutesSet)+len(rep.RoutesCleared) == 0 {
		return
	}
	if !keenetic.ConntrackPresent() {
		return
	}
	mode, err := keenetic.FlushConntrackForGroups(ctx, ourRouteGroups(cfg))
	if err != nil {
		fmt.Printf("conntrack: %v\n", err)
		return
	}
	fmt.Printf("conntrack сброшен (%s) — открытые соединения переедут на новый маршрут\n", mode)
}

// ourRouteGroups is the router-side object-group name for every list in
// the config.
func ourRouteGroups(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Routing.Lists))
	for _, l := range cfg.Routing.Lists {
		out = append(out, keenetic.RouteGroupPrefix+config.SanitizeRouteListName(l.Name))
	}
	return out
}

// desiredRoutes resolves config route lists into keenetic.DesiredRoute
// values (router-side group names, resolved interface). Shared shape with
// the bot side.
func desiredRoutes(rc config.RoutingConfig) []keenetic.DesiredRoute {
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

// applyRoutesAtStartup re-asserts the configured DNS-route lists when the
// daemon starts, so a firmware event or config reset that dropped them
// self-heals -- same best-effort, non-fatal pattern as
// applyProxy0AtStartup. Skipped entirely when no lists are configured.
func applyRoutesAtStartup(cfg *config.Config, logf func(string, ...any)) {
	if len(cfg.Routing.Lists) == 0 || !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyRoutes(ctx, desiredRoutes(cfg.Routing))
	if err != nil {
		logf("routes: apply failed: %v", err)
		return
	}
	if rep.EntriesAdded+rep.EntriesRemoved+len(rep.GroupsCreated)+len(rep.GroupsRemoved) > 0 {
		logf("routes: reconciled (+%d/-%d записей, групп +%d/-%d)",
			rep.EntriesAdded, rep.EntriesRemoved, len(rep.GroupsCreated), len(rep.GroupsRemoved))
	}
}

// splitEntries breaks a paste on spaces, commas, semicolons and newlines.
func splitEntries(args []string) []string {
	joined := strings.Join(args, " ")
	fields := strings.FieldsFunc(joined, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\n' || r == '\t' || r == '\r'
	})
	return fields
}

// mergeEntries classifies and appends entries to a list, deduping.
// Returns the accepted (normalized) entries and rejected (raw + reason).
func mergeEntries(l *config.RouteList, raw []string) (added []string, rejected []string) {
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

func printEntryResult(verb string, added, rejected []string) {
	fmt.Printf("%s: %d\n", verb, len(added))
	for _, r := range rejected {
		fmt.Println("  отклонено: " + r)
	}
}
