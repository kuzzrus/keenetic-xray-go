package botcontrol

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// The routes_preset_* actions expose the built-in curated lists
// (internal/presets, refreshed daily in the repo) over the bot protocol.
// They reuse presets.Apply / presets.Sync / presets.Drift so the bot's
// 📦 Готовые списки screen and `keenetic-xray routes preset …` behave
// identically. Mutations go through h.applyRoutes, same as every other
// routes_* handler.

// routesPresetList renders every preset as one tab-separated line for the
// bot to build its menu, preceded by a "#cats" line giving the category
// button order:
//
//	#cats\tМессенджеры\tВидео\t...
//	name\tservice\ttitle\tcategory\tkind\tcount\tinstalled(0|1)\tdriftAdded\tdriftRemoved
//
// installed/drift are evaluated against THIS agent build's embedded
// presets and this router's live config.
func (h *RouterHandler) routesPresetList() string {
	var b strings.Builder

	fmt.Fprintf(&b, "#gen\t%s\n", presets.Generated())

	var cats []string
	for _, c := range presets.ByCategory() {
		cats = append(cats, c.Name)
	}
	fmt.Fprintf(&b, "#cats\t%s\n", strings.Join(cats, "\t"))

	for _, p := range presets.All() {
		installed, dA, dR := 0, 0, 0
		if l := presets.BoundList(h.Config, p.Name); l != nil {
			installed = 1
			dA, dR, _, _ = presets.Drift(*l)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\n",
			p.Name, p.Service, p.Title, p.Category, p.Kind, p.Count, installed, dA, dR)
	}
	return strings.TrimRight(b.String(), "\n")
}

// routesPresetAdd binds a preset to a route list. args[0] is the preset
// name; the rest are bare flags: "ip" (also add the -ip companion),
// "iface=<IfaceN>", "exclusive".
func (h *RouterHandler) routesPresetAdd(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "", fmt.Errorf("usage: routes_preset_add <name> [ip] [iface=<IfaceN>] [exclusive]")
	}
	name := strings.TrimSpace(args[0])
	var withIP, exclusive bool
	iface := ""
	for _, a := range args[1:] {
		switch {
		case a == "ip", a == "--ip":
			withIP = true
		case a == "exclusive", a == "--exclusive":
			exclusive = true
		case strings.HasPrefix(a, "iface="):
			iface = strings.TrimPrefix(a, "iface=")
		case strings.HasPrefix(a, "--iface="):
			iface = strings.TrimPrefix(a, "--iface=")
		default:
			return "", fmt.Errorf("неизвестный флаг %q", a)
		}
	}

	touched, err := presets.Apply(h.Config, name, withIP, iface, exclusive)
	if err != nil {
		return "", err
	}
	return h.applyRoutes(ctx, "готовый список применён: "+strings.Join(touched, ", "))
}

// routesPresetSync refreshes preset-bound lists from this build's
// embedded presets. args[0] is a preset name or "all" (default).
func (h *RouterHandler) routesPresetSync(ctx context.Context, args []string) (string, error) {
	only := ""
	if len(args) > 0 && !strings.EqualFold(strings.TrimSpace(args[0]), "all") {
		only = strings.TrimSpace(args[0])
	}
	res, err := presets.Sync(h.Config, only)
	if err != nil {
		return "", err
	}
	if len(res) == 0 {
		return "нечего синхронизировать — нет списков, привязанных к готовым", nil
	}
	var lines []string
	changed := 0
	for _, r := range res {
		lines = append(lines, fmt.Sprintf("%s: +%d −%d", r.Name, r.Added, r.Removed))
		if r.Added+r.Removed > 0 {
			changed++
		}
	}
	if changed == 0 {
		return "всё уже актуально:\n" + strings.Join(lines, "\n"), nil
	}
	return h.applyRoutes(ctx, "синхронизация готовых списков:\n"+strings.Join(lines, "\n"))
}

// routesPresetUpdate pulls the latest preset lists from the repo right
// now (the daemon also does this on a daily loop). It refreshes the
// embedded->overlay copy; it does not touch any route list -- the
// operator then sees ⬆ on changed presets and taps Синхронизировать.
func (h *RouterHandler) routesPresetUpdate(ctx context.Context) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	res, err := presets.Refresh(rctx, h.Config.PresetsSourceURL)
	if err != nil {
		return "", err
	}
	out := "готовые списки обновлены из репозитория:\n" + res.String()
	if res.Updated > 0 {
		out += "\n\nу изменившихся сервисов появится ⬆ — жми «Синхронизировать»."
	}
	return out, nil
}
