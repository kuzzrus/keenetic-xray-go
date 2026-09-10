package presets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// This file binds the embedded presets to a live *config.Config: seeding
// a route list from a preset, re-syncing a bound list, and reporting
// drift. Both the CLI (`keenetic-xray routes preset …`) and the bot's
// 📦 Готовые списки screen call these so the two behave identically.
// None of them save or push -- the caller runs the usual routes apply.

// BoundList returns the route list bound to preset id `name`
// ("youtube" / "youtube-ip"), or nil.
func BoundList(cfg *config.Config, name string) *config.RouteList {
	for i := range cfg.Routing.Lists {
		if strings.EqualFold(cfg.Routing.Lists[i].Preset, name) {
			return &cfg.Routing.Lists[i]
		}
	}
	return nil
}

func findByName(cfg *config.Config, name string) *config.RouteList {
	for i := range cfg.Routing.Lists {
		if strings.EqualFold(cfg.Routing.Lists[i].Name, name) {
			return &cfg.Routing.Lists[i]
		}
	}
	return nil
}

// Drift compares a bound list's entries against the embedded preset:
// entries the preset would add, entries it would remove, its current
// rev, and whether the list is bound to a preset this build still ships.
func Drift(l config.RouteList) (added, removed int, curRev string, bound bool) {
	if l.Preset == "" {
		return 0, 0, "", false
	}
	want, ok := Entries(l.Preset)
	if !ok {
		return 0, 0, "", false
	}
	p, _ := Find(l.Preset)
	have := lowerSet(l.Entries)
	wantSet := lowerSet(want)
	for w := range wantSet {
		if _, ok := have[w]; !ok {
			added++
		}
	}
	for h := range have {
		if _, ok := wantSet[h]; !ok {
			removed++
		}
	}
	return added, removed, p.Rev, true
}

// DriftNote is one preset-bound list with new drift the operator hasn't
// been told about yet.
type DriftNote struct {
	Name           string
	Added, Removed int
}

// NewDrift reports every preset-bound list in cfg that both has drift
// (see Drift) and is at a preset revision the caller hasn't reported
// before (RouteList.NotifiedRev) -- so a daily caller can tell the
// operator about a changed upstream list exactly once, not on every
// call until they get around to syncing. It stamps NotifiedRev on each
// list it reports so a second call with the same data returns nothing;
// the caller is responsible for saving cfg (matching Apply/Sync, which
// also mutate in place and leave saving to the caller).
func NewDrift(cfg *config.Config) []DriftNote {
	var out []DriftNote
	for i := range cfg.Routing.Lists {
		l := &cfg.Routing.Lists[i]
		added, removed, curRev, bound := Drift(*l)
		if !bound || (added == 0 && removed == 0) || curRev == l.NotifiedRev {
			continue
		}
		out = append(out, DriftNote{Name: l.Name, Added: added, Removed: removed})
		l.NotifiedRev = curRev
	}
	return out
}

func lowerSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[strings.ToLower(strings.TrimSpace(x))] = struct{}{}
	}
	return m
}

// Apply seeds or refreshes the route list(s) for preset `name` in cfg.
// With withIP it also binds the "<name>-ip" CIDR companion. iface and
// exclusive, when set, land on the domain list. Returns the list ids
// touched. A pre-existing list with that name that was made by hand (no
// Preset) or bound to a different preset is an error -- the caller should
// surface it.
func Apply(cfg *config.Config, name string, withIP bool, iface string, exclusive bool) ([]string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	p, ok := Find(name)
	if !ok {
		return nil, fmt.Errorf("нет встроенного списка %q", name)
	}
	if iface != "" && !config.ValidRouteIface(iface) {
		return nil, fmt.Errorf("интерфейс %q: нужно имя вида Proxy0 или Wireguard4", iface)
	}

	ids := []string{p.Name}
	if withIP && p.Kind == "domains" && HasCIDR(p.Name) {
		ids = append(ids, p.Name+"-ip")
	}

	var touched []string
	for _, id := range ids {
		entries, ok := Entries(id)
		if !ok || len(entries) == 0 {
			return nil, fmt.Errorf("встроенный список %q пуст", id)
		}
		pr, _ := Find(id)
		if l := findByName(cfg, id); l != nil {
			if l.Preset == "" {
				return nil, fmt.Errorf("список %q уже существует и сделан вручную — удали или переименуй его", id)
			}
			if !strings.EqualFold(l.Preset, id) {
				return nil, fmt.Errorf("список %q привязан к другому пресету (%s)", id, l.Preset)
			}
		}
		l := findByName(cfg, id)
		if l == nil {
			cfg.Routing.Lists = append(cfg.Routing.Lists, config.RouteList{Name: id})
			l = &cfg.Routing.Lists[len(cfg.Routing.Lists)-1]
		}
		sorted := append([]string(nil), entries...)
		sort.Strings(sorted)
		l.Entries = sorted
		l.Preset = pr.Name
		l.PresetRev = pr.Rev
		if id == p.Name {
			if iface != "" {
				l.Interface = iface
			}
			if exclusive {
				l.Exclusive = true
			}
		}
		touched = append(touched, id)
	}
	return touched, nil
}

// SyncResult is one list refreshed by Sync.
type SyncResult struct {
	Name           string
	Added, Removed int
}

// Sync refreshes every preset-bound list (or just the one whose preset id
// or list name matches `only`) from the embedded presets. `only` == ""
// means all.
func Sync(cfg *config.Config, only string) ([]SyncResult, error) {
	only = strings.ToLower(strings.TrimSpace(only))
	var out []SyncResult
	matched := false
	for i := range cfg.Routing.Lists {
		l := &cfg.Routing.Lists[i]
		if l.Preset == "" {
			continue
		}
		if only != "" && !strings.EqualFold(l.Preset, only) && !strings.EqualFold(l.Name, only) {
			continue
		}
		matched = true
		want, ok := Entries(l.Preset)
		if !ok {
			return nil, fmt.Errorf("список %q привязан к пресету %q, которого нет в этой сборке агента", l.Name, l.Preset)
		}
		a, r, _, _ := Drift(*l)
		sorted := append([]string(nil), want...)
		sort.Strings(sorted)
		l.Entries = sorted
		if p, ok := Find(l.Preset); ok {
			l.PresetRev = p.Rev
		}
		out = append(out, SyncResult{Name: l.Name, Added: a, Removed: r})
	}
	if only != "" && !matched {
		return nil, fmt.Errorf("нет применённого пресета %q", only)
	}
	return out, nil
}
