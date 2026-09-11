package keenetic

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// RouteGroupPrefix namespaces every object-group this project creates on
// the router. ApplyRoutes / ClearRoutes only ever touch names starting
// with it, so a list an operator built by hand in the Keenetic web UI
// (youtube, telegram, domain-list0, ...) is never changed or deleted.
// ShowManualRoutes deliberately reads the *other* names, read-only, for
// operator awareness -- that doesn't violate this invariant.
const RouteGroupPrefix = "keenetic-xray-"

// minRouteOSMajor / minRouteOSMinor is the KeeneticOS floor for
// DNS-based routes (`object-group fqdn` + `dns-proxy route`).
const (
	minRouteOSMajor = 5
	minRouteOSMinor = 0
)

// DesiredRoute is one route list resolved for the router: a full
// (already prefixed) object-group name, its target Proxy interface, the
// FQDN/subnet entries, whether the route line carries "reject" (drop
// matched traffic instead of leaking it direct when the interface is
// down), and whether the list is disabled (keep the object-group so a
// re-enable is instant, but no route line).
type DesiredRoute struct {
	Group    string
	Iface    string
	Entries  []string
	Reject   bool
	Disabled bool
}

// LiveRoute is one of this project's route lists as it currently exists
// on the router.
type LiveRoute struct {
	Group   string
	Iface   string // "" if the object-group exists but isn't routed
	Reject  bool
	Entries []string
}

// RouteReport summarizes what ApplyRoutes changed.
type RouteReport struct {
	GroupsCreated  []string
	GroupsRemoved  []string
	EntriesAdded   int
	EntriesRemoved int
	RoutesSet      []string // group names whose route line was (re)written
	RoutesCleared  []string
	Saved          bool
}

type parsedRoute struct {
	iface  string
	reject bool
}

// ApplyRoutes reconciles the router's DNS-based routes so that exactly
// the `want` lists (this project's, prefixed) are present. It never
// touches an object-group or route whose name lacks RouteGroupPrefix.
// Needs KeeneticOS >= 5.0; a version it can't read is treated as "too
// old" with a clear error. `system configuration save` runs once, only
// if any command was issued. Command failures are collected: as much as
// possible is applied, and the combined error names what didn't take.
func ApplyRoutes(ctx context.Context, want []DesiredRoute) (RouteReport, error) {
	var rep RouteReport
	if !Available() {
		return rep, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if ok, err := OSAtLeast(ctx, minRouteOSMajor, minRouteOSMinor); err != nil {
		return rep, fmt.Errorf("маршруты по доменам требуют KeeneticOS %d.%d+, а версию определить не вышло: %w", minRouteOSMajor, minRouteOSMinor, err)
	} else if !ok {
		maj, min, _, _ := OSVersion(ctx)
		return rep, fmt.Errorf("KeeneticOS %d.%d — маршруты по доменам появились в %d.%d", maj, min, minRouteOSMajor, minRouteOSMinor)
	}

	curGroups, curRoutes, err := readOurRoutes(ctx)
	if err != nil {
		return rep, err
	}

	wantByGroup := make(map[string]DesiredRoute, len(want))
	for _, w := range want {
		wantByGroup[w.Group] = w
	}

	var cmds []string

	for _, w := range want {
		cur, existed := curGroups[w.Group]
		if !existed {
			cmds = append(cmds, "object-group fqdn "+w.Group)
			rep.GroupsCreated = append(rep.GroupsCreated, w.Group)
		}
		add, del := diffEntries(cur, w.Entries)
		for _, e := range add {
			cmds = append(cmds, fmt.Sprintf("object-group fqdn %s include %s", w.Group, e))
		}
		for _, e := range del {
			cmds = append(cmds, fmt.Sprintf("no object-group fqdn %s include %s", w.Group, e))
		}
		rep.EntriesAdded += len(add)
		rep.EntriesRemoved += len(del)

		route, routed := curRoutes[w.Group]
		switch {
		case w.Disabled:
			if routed {
				cmds = append(cmds, fmt.Sprintf("no dns-proxy route object-group %s %s", w.Group, route.iface))
				rep.RoutesCleared = append(rep.RoutesCleared, w.Group)
			}
		case !routed || route.iface != w.Iface || route.reject != w.Reject:
			if routed {
				cmds = append(cmds, fmt.Sprintf("no dns-proxy route object-group %s %s", w.Group, route.iface))
			}
			line := fmt.Sprintf("dns-proxy route object-group %s %s auto", w.Group, w.Iface)
			if w.Reject {
				line += " reject"
			}
			cmds = append(cmds, line)
			rep.RoutesSet = append(rep.RoutesSet, w.Group)
		}
	}

	// Lists we own that are no longer wanted at all -> remove route + group.
	for g, r := range curRoutes {
		if _, ok := wantByGroup[g]; !ok {
			cmds = append(cmds, fmt.Sprintf("no dns-proxy route object-group %s %s", g, r.iface))
			rep.RoutesCleared = append(rep.RoutesCleared, g)
		}
	}
	for g := range curGroups {
		if _, ok := wantByGroup[g]; !ok {
			cmds = append(cmds, "no object-group fqdn "+g)
			rep.GroupsRemoved = append(rep.GroupsRemoved, g)
		}
	}

	if len(cmds) == 0 {
		return rep, nil
	}
	cmds = append(cmds, "system configuration save")

	var failed []string
	for _, c := range cmds {
		if _, err := ndmcRun(ctx, c); err != nil {
			failed = append(failed, fmt.Sprintf("%q: %v", c, err))
		}
	}
	rep.Saved = true
	if len(failed) > 0 {
		return rep, fmt.Errorf("часть команд не выполнилась:\n%s", strings.Join(failed, "\n"))
	}
	return rep, nil
}

// ShowRoutes returns this project's route lists as they currently exist
// on the router, sorted by group name.
func ShowRoutes(ctx context.Context) ([]LiveRoute, error) {
	if !Available() {
		return nil, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	groups, routes, err := readOurRoutes(ctx)
	if err != nil {
		return nil, err
	}
	return liveRoutesFrom(groups, routes), nil
}

// ShowManualRoutes returns every domain-based route list on the router
// that ISN'T ours (no RouteGroupPrefix) -- an operator's own lists, built
// by hand in the Keenetic web UI. Read-only: nothing here is ever changed
// or deleted, this just surfaces what already exists so the operator (or
// the bot) doesn't have to go find it over SSH.
func ShowManualRoutes(ctx context.Context) ([]LiveRoute, error) {
	if !Available() {
		return nil, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	groups, routes, err := readRoutesMatching(ctx, func(name string) bool {
		return !strings.HasPrefix(name, RouteGroupPrefix)
	})
	if err != nil {
		return nil, err
	}
	return liveRoutesFrom(groups, routes), nil
}

// liveRoutesFrom assembles the LiveRoute list from a parsed groups/routes
// pair, sorted by group name. A route without a surviving object-group
// shouldn't happen, but is surfaced if it does.
func liveRoutesFrom(groups map[string][]string, routes map[string]parsedRoute) []LiveRoute {
	out := make([]LiveRoute, 0, len(groups))
	for g, entries := range groups {
		lr := LiveRoute{Group: g, Entries: entries}
		if r, ok := routes[g]; ok {
			lr.Iface, lr.Reject = r.iface, r.reject
		}
		out = append(out, lr)
	}
	for g, r := range routes {
		if _, ok := groups[g]; !ok {
			out = append(out, LiveRoute{Group: g, Iface: r.iface, Reject: r.reject})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

// ClearRoutes removes every route list this project owns (prefix match)
// and saves. A no-op if there are none.
func ClearRoutes(ctx context.Context) error {
	if !Available() {
		return fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	groups, routes, err := readOurRoutes(ctx)
	if err != nil {
		return err
	}
	var cmds []string
	for g, r := range routes {
		cmds = append(cmds, fmt.Sprintf("no dns-proxy route object-group %s %s", g, r.iface))
	}
	for g := range groups {
		cmds = append(cmds, "no object-group fqdn "+g)
	}
	if len(cmds) == 0 {
		return nil
	}
	cmds = append(cmds, "system configuration save")
	for _, c := range cmds {
		if _, err := ndmcRun(ctx, c); err != nil {
			return fmt.Errorf("ndmc %q: %w", c, err)
		}
	}
	return nil
}

// readOurRoutes parses `show running-config` for this project's
// object-groups and dns-proxy routes only.
func readOurRoutes(ctx context.Context) (groups map[string][]string, routes map[string]parsedRoute, err error) {
	return readRoutesMatching(ctx, func(name string) bool { return strings.HasPrefix(name, RouteGroupPrefix) })
}

// readRoutesMatching parses `show running-config` for every fqdn
// object-group (and its dns-proxy route, if any) whose name satisfies
// match. Block membership is by indentation: a column-0 line opens/closes
// a block, indented lines are its children (matching how Keenetic emits
// the config -- 4-space children, "!" separators).
func readRoutesMatching(ctx context.Context, match func(name string) bool) (groups map[string][]string, routes map[string]parsedRoute, err error) {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return nil, nil, fmt.Errorf("show running-config: %w", err)
	}
	groups = map[string][]string{}
	routes = map[string]parsedRoute{}

	var inGroup string
	inDNSProxy := false
	for _, line := range strings.Split(out, "\n") {
		body := strings.TrimLeft(line, " \t")
		if body == "" {
			continue
		}
		f := strings.Fields(body)
		if body == line { // column-0: block boundary
			inGroup, inDNSProxy = "", false
			switch {
			case len(f) == 3 && f[0] == "object-group" && f[1] == "fqdn" && match(f[2]):
				inGroup = f[2]
				if _, ok := groups[inGroup]; !ok {
					groups[inGroup] = []string{}
				}
			case len(f) == 1 && f[0] == "dns-proxy":
				inDNSProxy = true
			}
			continue
		}
		// indented child line
		switch {
		case inGroup != "" && f[0] == "include" && len(f) >= 2:
			groups[inGroup] = append(groups[inGroup], f[1])
		case inDNSProxy && f[0] == "route" && len(f) >= 5 && f[1] == "object-group" && match(f[2]):
			routes[f[2]] = parsedRoute{iface: f[3], reject: len(f) >= 6 && f[5] == "reject"}
		}
	}
	return groups, routes, nil
}

// diffEntries returns which of want are missing from cur (add) and which
// of cur aren't in want (del). Case-insensitive; want is assumed already
// normalized by config.ClassifyRouteEntry.
func diffEntries(cur, want []string) (add, del []string) {
	haveCur := make(map[string]struct{}, len(cur))
	for _, c := range cur {
		haveCur[strings.ToLower(c)] = struct{}{}
	}
	haveWant := make(map[string]struct{}, len(want))
	for _, w := range want {
		lw := strings.ToLower(w)
		haveWant[lw] = struct{}{}
		if _, ok := haveCur[lw]; !ok {
			add = append(add, w)
		}
	}
	for _, c := range cur {
		if _, ok := haveWant[strings.ToLower(c)]; !ok {
			del = append(del, c)
		}
	}
	sort.Strings(add)
	sort.Strings(del)
	return add, del
}
