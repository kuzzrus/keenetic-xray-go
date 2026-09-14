package botcontrol

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// susaninConfiguredFn reports whether the Phase 1 susanin addon
// (internal/addons) is installed and has been configured with an
// egress interface. addons.State has no dedicated "configured" field --
// Detail is the only cross-package signal susaninAddon.Detect sets:
// "egress <iface>" once configured, "не настроен -- ..." otherwise.
// Used to refuse enabling adaptive routing while susanin's own,
// conflicting REDIRECT/policy-routing dataplane is active -- same idea,
// same conntrack table, see docs/HANDOFF-susanin.md.
//
// A package-level var (not a plain func), same convention as this
// project's other exec-backed checks (keenetic.ndmcRun,
// adaptiveroute.ipsetRun, ...): swapping it in a test is far simpler
// than faking a full addons.Addon and mutating the real, shared,
// process-global addons registry just to exercise adaptiveRouteOn's
// refusal path.
var susaninConfiguredFn = func(ctx context.Context) bool {
	a, ok := addons.Find("susanin")
	if !ok {
		return false
	}
	st := a.Detect(ctx)
	return st.Installed && !strings.HasPrefix(st.Detail, "не настроен")
}

// adaptiveRouteLAN mirrors cmd/keenetic-xray/adaptiveroute.go's own
// unexported helper of the same name: resolves the LAN interface (real
// kernel device name) and client subnet (cfg.AdaptiveRoute.LANSubnet
// verbatim if set, else a /24 derived from the router's own detected LAN
// IP). Duplicated rather than shared -- that command lives in package
// main, so its helpers aren't importable from here. Keep the two in
// sync if the derivation logic ever changes.
func adaptiveRouteLAN(ctx context.Context, cfg *config.Config) (iface string, subnet *net.IPNet, err error) {
	iface, err = keenetic.LANInterfaceOSName(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("определение LAN-интерфейса: %w", err)
	}
	if cfg.AdaptiveRoute.LANSubnet != "" {
		_, n, perr := net.ParseCIDR(cfg.AdaptiveRoute.LANSubnet)
		if perr != nil {
			return "", nil, fmt.Errorf("lan_subnet %q: %w", cfg.AdaptiveRoute.LANSubnet, perr)
		}
		return iface, n, nil
	}
	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		return "", nil, fmt.Errorf("определение LAN IP: %w", err)
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return "", nil, fmt.Errorf("LAN IP %q: не IPv4", ip)
	}
	mask := net.CIDRMask(24, 32)
	return iface, &net.IPNet{IP: v4.Mask(mask), Mask: mask}, nil
}

// adaptiveRouteShow reports adaptive routing's config plus, when
// reachable, live dataplane state (REDIRECT rule presence, current
// redirect-set size). Informational, like wgTransportShow -- never
// fails just because the router-only bits (LAN detection, ipset query)
// aren't reachable.
func (h *RouterHandler) adaptiveRouteShow(ctx context.Context) (string, error) {
	a := h.Config.AdaptiveRoute
	if !a.Enabled {
		return "Адаптивная маршрутизация: выкл", nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Адаптивная маршрутизация: вкл — xray :%d", a.EffectivePort())

	if !keenetic.Available() {
		return b.String(), nil
	}
	iface, subnet, err := adaptiveRouteLAN(ctx, h.Config)
	if err != nil {
		return b.String(), nil
	}
	fmt.Fprintf(&b, "\nLAN: %s (%s)", iface, subnet)

	opts := adaptiveroute.RedirectOptions{
		SetName:       adaptiveroute.RedirectSetName,
		Port:          a.EffectivePort(),
		LANInterfaces: []string{iface},
	}
	if adaptiveroute.RedirectInPlace(ctx, opts) {
		b.WriteString("\nREDIRECT: активен")
	} else {
		b.WriteString("\nREDIRECT: НЕ активен (нужны 🩺 Doctor/реконсиляция)")
	}
	if members, err := adaptiveroute.Members(ctx, adaptiveroute.RedirectSetName); err == nil {
		fmt.Fprintf(&b, "\nСейчас перенаправлено адресов/подсетей: %d", len(members))
	}
	return b.String(), nil
}

// adaptiveRouteOn mirrors cmd/keenetic-xray's own adaptiveRouteOn (see
// cmd/keenetic-xray/adaptiveroute.go) -- the same dependency-check,
// dependency-install, then dataplane bring-up sequence -- plus a guard
// the CLI only ever printed a warning about: refuse outright if susanin
// (Phase 1, the same idea via a different, conflicting dataplane) is
// currently configured. Checked before the ndmc-availability check: it's
// a plain local addon-state read that doesn't need ndmc at all, so
// there's no reason to make it wait behind (or hide behind a failure
// of) a check it's logically independent from.
func (h *RouterHandler) adaptiveRouteOn(ctx context.Context) (string, error) {
	if susaninConfiguredFn(ctx) {
		return "", fmt.Errorf("аддон susanin настроен -- сначала отключите его (🧩 Дополнения → susanin), нельзя запускать оба одновременно (конфликтующий дата-плейн)")
	}
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}

	if err := adaptiveroute.EnsureIPSetTool(ctx); err != nil {
		return "", err
	}
	// Best-effort, not fatal: without conntrack, the redirect itself
	// still works for new connection attempts -- only an already-
	// established flow's immediate re-route degrades to "wait for the
	// client's own retry". See internal/keenetic/conntrack.go.
	var warn string
	if err := keenetic.EnsureConntrackTool(ctx); err != nil {
		warn = fmt.Sprintf("\n⚠️ conntrack недоступен (%v) — уже открытые соединения не будут сразу перенаправляться, только новые попытки", err)
	}
	iface, subnet, err := adaptiveRouteLAN(ctx, h.Config)
	if err != nil {
		return "", err
	}
	if err := adaptiveroute.EnsureIPSet(ctx, adaptiveroute.RedirectSetName); err != nil {
		return "", fmt.Errorf("создание ipset: %w", err)
	}
	if err := adaptiveroute.EnsureRedirect(ctx, adaptiveroute.RedirectOptions{
		SetName:       adaptiveroute.RedirectSetName,
		Port:          h.Config.AdaptiveRoute.EffectivePort(),
		LANInterfaces: []string{iface},
	}); err != nil {
		return "", fmt.Errorf("установка REDIRECT: %w", err)
	}

	h.Config.AdaptiveRoute.Enabled = true
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return fmt.Sprintf("Адаптивная маршрутизация включена: %s (LAN %s), xray :%d%s",
		iface, subnet, h.Config.AdaptiveRoute.EffectivePort(), warn), nil
}

// adaptiveRouteOff mirrors cmd/keenetic-xray's own adaptiveRouteOff:
// clearing the REDIRECT rule is best-effort (a failure there shouldn't
// block turning the feature off in config), everything else always
// applies.
func (h *RouterHandler) adaptiveRouteOff(ctx context.Context) (string, error) {
	var warn string
	if keenetic.Available() {
		if err := adaptiveroute.ClearRedirect(ctx); err != nil {
			warn = fmt.Sprintf("\n⚠️ не удалось убрать REDIRECT-правило: %v", err)
		}
	}
	h.Config.AdaptiveRoute.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	h.rebindXray(ctx)
	return "Адаптивная маршрутизация выключена" + warn, nil
}
