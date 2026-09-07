// Package addons manages optional router-side components a user can turn
// on next to keenetic-xray itself: a local DNS resolver (unbound), a DPI
// bypass daemon (nfqws2), and the opkg packages this project otherwise
// only nags about (conntrack, cron). Each component knows how to detect,
// install, remove, (re)configure and describe itself; the CLI (`keenetic
// -xray addon …`) and, later, the bot's 🧩 Дополнения screen drive them
// through this one interface so the two behave identically.
//
// Everything that actually touches the system (opkg, init.d, files,
// process checks) goes through the injectable vars in sys.go -- same
// convention as internal/keenetic's lookNdmc/ndmcRun and
// internal/install's cron hooks -- so the decision logic here is
// testable without a real Entware router.
package addons

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// errNoConfig is what a component with nothing to tune returns from
// Configure.
var errNoConfig = fmt.Errorf("у этого компонента нет настроек")

// State is a component's current condition, filled in by Detect.
type State struct {
	Installed bool
	Running   bool   // meaningful only for components with a daemon
	HasDaemon bool   // false -> ignore Running (a library/package, not a service)
	Version   string // "" if unknown or not installed
	Detail    string // one short human line: "слушает 127.0.0.1:5353", "режим list, порт 443"
}

// Addon is one optional component. Implementations are small and live one
// per file (unbound.go, nfqws2.go, …).
type Addon interface {
	ID() string    // stable slug used in CLI args and callback data: "unbound", "nfqws2"
	Title() string // one line for menus: "Unbound — рекурсивный DNS"
	// About is a short paragraph shown on the component's own screen /
	// `addon show`, explaining what turning it on does.
	About() string

	Detect(ctx context.Context) State
	Install(ctx context.Context) error
	Remove(ctx context.Context) error
	// Configure applies key=value tweaks (the keys each component
	// documents in About / accepts from the bot wizard). An unknown key
	// is an error so a typo in the CLI isn't silently ignored.
	Configure(ctx context.Context, kv map[string]string) error
	// Status is a longer, free-form health report for `addon status` and
	// the bot's Статус button -- may shell out.
	Status(ctx context.Context) (string, error)
}

// order is the fixed display order; anything not listed sorts after,
// alphabetically. Keeps `addon list` and the bot menu stable.
var order = []string{"unbound", "nfqws2", "conntrack", "cron"}

var registry = map[string]Addon{}

// Register adds a component to the catalogue. Called from each
// component file's init().
func Register(a Addon) {
	if _, dup := registry[a.ID()]; dup {
		panic("addons: duplicate id " + a.ID())
	}
	registry[a.ID()] = a
}

// All returns every registered component in display order.
func All() []Addon {
	rank := map[string]int{}
	for i, id := range order {
		rank[id] = i
	}
	out := make([]Addon, 0, len(registry))
	for _, a := range registry {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, oki := rank[out[i].ID()]
		rj, okj := rank[out[j].ID()]
		switch {
		case oki && okj:
			return ri < rj
		case oki != okj:
			return oki
		default:
			return out[i].ID() < out[j].ID()
		}
	})
	return out
}

// Find returns the component with this id.
func Find(id string) (Addon, bool) {
	a, ok := registry[id]
	return a, ok
}

// ParseKV turns ["cache=8", "port=5353"] into a map, rejecting an
// argument without '='.
func ParseKV(args []string) (map[string]string, error) {
	kv := make(map[string]string, len(args))
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("аргумент %q: нужно key=value", a)
		}
		kv[k] = v
	}
	return kv, nil
}
