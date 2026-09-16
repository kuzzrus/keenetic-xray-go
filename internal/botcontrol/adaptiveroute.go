package botcontrol

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
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
	l7sniLine := "\n🔍 L7 SNI: выкл"
	if h.Config.L7SNI.Enabled {
		l7sniLine = "\n🔍 L7 SNI: вкл"
	}
	if !a.Enabled {
		return "Адаптивная маршрутизация: выкл" + l7sniLine, nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Адаптивная маршрутизация: вкл — xray :%d, TTL подтверждённых адресов %s",
		a.EffectivePort(), a.EffectiveOKTTL())
	if bt := a.EffectiveBlockThreshold(); bt > 0 {
		fmt.Fprintf(&b, ", укрупнение блока от %d адресов", bt)
	} else {
		b.WriteString(", укрупнение блоков: выкл")
	}
	b.WriteString(l7sniLine)

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
	if !h.rebindXray(ctx) {
		// The REDIRECT rule above is already live and will keep sending
		// matched traffic to xray's dokodemo-door port -- but if xray
		// itself hasn't regenerated its config to actually listen there
		// yet, that traffic is silently dropped until it does. Say so
		// plainly instead of claiming success: this exact silent gap is
		// what made rebindXray's old bug (see its own doc comment) look
		// like "works after a manual restart, not before" from the bot.
		warn += "\n⚠️ не удалось применить живьём (демон не ответил) — нажмите ♻️ Рестарт демона на карточке роутера, иначе редирект уже активен, а xray его пока не слушает"
	}
	return fmt.Sprintf("Адаптивная маршрутизация включена: %s (LAN %s), xray :%d%s",
		iface, subnet, h.Config.AdaptiveRoute.EffectivePort(), warn), nil
}

// adaptiveRouteOff mirrors cmd/keenetic-xray's own adaptiveRouteOff:
// clearing the REDIRECT rule is best-effort (a failure there shouldn't
// block turning the feature off in config), everything else always
// applies. Also flushes the ipset itself, not just the REDIRECT rule --
// found live (2026-09-15) that without this, "off" left every already-
// confirmed address (individual entries carry up to AdaptiveRoute's own
// OKTTL, 6h by default -- see adaptiveroute.AddIP's doc comment) sitting
// in the set, ready to start redirecting again the instant "on" re-adds
// the rule, even addresses that were false positives. A bare off/on
// toggle silently undid nothing.
//
// Deliberately does NOT also clear the classifier's own persisted state
// the way adaptiveRouteFlush does: while AdaptiveRoute.Enabled is false,
// adaptiveRouteClassifyLoop's ticker branch is a no-op, so a stale
// in-memory belief just sits frozen and harmless until re-enabled -- no
// redirecting happens either way while off. It only matters again once
// switched back on, which is what adaptiveRouteFlush is for.
func (h *RouterHandler) adaptiveRouteOff(ctx context.Context) (string, error) {
	var warn string
	if keenetic.Available() {
		if err := adaptiveroute.ClearRedirect(ctx); err != nil {
			warn = fmt.Sprintf("\n⚠️ не удалось убрать REDIRECT-правило: %v", err)
		}
		if err := adaptiveroute.Flush(ctx, adaptiveroute.RedirectSetName); err != nil {
			warn += fmt.Sprintf("\n⚠️ не удалось очистить список адресов: %v", err)
		}
	}
	h.Config.AdaptiveRoute.Enabled = false
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if !h.rebindXray(ctx) && warn == "" {
		// Lower stakes than adaptiveRouteOn's own warning: the REDIRECT
		// rule (what actually diverts traffic) is already cleared above,
		// so nothing reaches xray's dokodemo-door inbound regardless of
		// whether xray itself re-applied. Still worth a note -- xray's
		// own config keeps the now-pointless inbound until it does.
		warn = "\n⚠️ живое применение не удалось (демон не ответил), но редирект уже снят — при желании нажмите ♻️ Рестарт демона, чтобы xray тоже обновил конфиг"
	}
	return "Адаптивная маршрутизация выключена" + warn, nil
}

// adaptiveRouteFlush mirrors cmd/keenetic-xray's own adaptiveRouteFlush
// (SSH `transport adaptive flush`): clears the redirect ipset, deletes
// the classifier's persisted state, and restarts the daemon -- all
// three matter. A bare ipset flush alone left the *running* classifier's
// in-memory state (loaded once, at daemon startup) still believing
// every flushed address was confirmed, so it didn't hurry to re-add
// anything -- confirmed live (2026-09-15) to leave previously-good
// redirects silently unable to recover for as long as each entry's own
// TTL allowed, which read as "nothing loads" even though fresh
// individual addresses were visibly still being caught. Deleting the
// state file without a restart doesn't help either: the daemon's own
// periodic save (every 5 minutes) just writes the stale in-memory copy
// straight back over it. Only a real restart clears that in-memory
// state, via restartDaemonDetached -- the same safe fire-and-forget
// pattern daemonRestart already uses, so this method's own return value
// reaches the operator before the init script's restart actually kills
// this process.
func (h *RouterHandler) adaptiveRouteFlush(ctx context.Context) (string, error) {
	if !keenetic.Available() {
		return "", fmt.Errorf("ndmc не найден — адаптивная маршрутизация работает только на роутере Keenetic")
	}
	if err := adaptiveroute.Flush(ctx, adaptiveroute.RedirectSetName); err != nil {
		return "", fmt.Errorf("очистка ipset: %w", err)
	}
	var warn string
	if h.AdaptiveRouteStatePath != "" {
		if err := os.Remove(h.AdaptiveRouteStatePath); err != nil && !os.IsNotExist(err) {
			warn = fmt.Sprintf("\n⚠️ не удалось удалить сохранённое состояние классификатора: %v", err)
		}
	}
	if err := h.restartDaemonDetached(); err != nil {
		warn += fmt.Sprintf("\n⚠️ автоматический перезапуск не удался (%v) — перезапустите вручную: ♻️ Рестарт демона", err)
	}
	return "Список перенаправляемых адресов и состояние классификатора очищены, демон перезапускается…" + warn, nil
}

// adaptiveRouteSetTTL sets how long a confirmed-good destination stays
// redirected without a healthy re-check (AdaptiveRoute.OKTTLHours). No
// rebindXray -- unlike Enabled/Port/LANSubnet, this never touches xray's
// own config or the REDIRECT rule, only the classifier's own tuning, and
// adaptiveRouteClassifyLoop already re-reads it from disk every tick
// (see that loop's own comment), so the change is live within ~500ms.
func (h *RouterHandler) adaptiveRouteSetTTL(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: adrt_ttl <часы>")
	}
	hours, err := strconv.Atoi(args[0])
	if err != nil || hours <= 0 {
		return "", fmt.Errorf("часы должны быть положительным целым числом, получено %q", args[0])
	}
	h.Config.AdaptiveRoute.OKTTLHours = hours
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("TTL подтверждённых адресов: %dч", hours), nil
}

// adaptiveRouteSetBlockThreshold sets how many confirmed addresses in
// the same /24 must accumulate before ClrBlockPromote widens the whole
// network into the tunnel at once (AdaptiveRoute.BlockThreshold). Unlike
// adaptiveRouteSetTTL, a non-positive value is valid input, not
// rejected: it disables block-widening entirely, so only the exact
// confirmed address is ever redirected -- see BlockThreshold's own doc
// comment for why a large multi-service provider sharing address space
// makes that a real, useful setting to reach for. Same live-apply and
// no-rebindXray reasoning as adaptiveRouteSetTTL.
func (h *RouterHandler) adaptiveRouteSetBlockThreshold(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: adrt_blockthr <порог>")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return "", fmt.Errorf("порог должен быть целым числом, получено %q", args[0])
	}
	h.Config.AdaptiveRoute.BlockThreshold = n
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if n <= 0 {
		return "укрупнение блоков отключено — в туннель будут попадать только точные подтверждённые адреса", nil
	}
	return fmt.Sprintf("порог укрупнения блока: %d адресов", n), nil
}
