package botcontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/netfetch"
)

// routesScan is the routes_scan action: for each domain given, read its
// page through the router's tunnel, collect the other hosts the page
// pulls from, and say which of them need the tunnel (internal/depscan).
// The answer is depscan's TSV -- the bot parses it back to draw its
// screen; nothing in it changes any list. Adding what the operator ticks
// is a separate routes_add.
func (h *RouterHandler) routesScan(ctx context.Context, args []string) (string, error) {
	seeds, problems := depscan.ParseSeeds(args...)
	if len(seeds) == 0 {
		if len(problems) > 0 {
			return "", errors.New(strings.Join(problems, "; "))
		}
		return "", fmt.Errorf("usage: routes_scan <домен> [<домен> …]")
	}
	tunnel, ok := h.tunnelTransport()
	if !ok {
		return "", errors.New("туннель не работает (xray не запущен или не настроен профиль) — сканировать нечем")
	}
	res, err := depscan.ScanMany(ctx, seeds, depscan.Options{Tunnel: tunnel, Covered: h.coveredBy(ctx)}, h.scanFn)
	if err != nil {
		return "", err
	}
	return res.TSV(), nil
}

func (h *RouterHandler) tunnelTransport() (http.RoundTripper, bool) {
	if h.scanTunnel != nil {
		return h.scanTunnel()
	}
	return netfetch.TunnelTransport()
}

// coveredBy answers "which route list already routes this host?" from the
// enabled lists in the config and, where ndmc is available, the lists the
// operator made by hand on the router (best effort: a failed read just
// leaves them out).
func (h *RouterHandler) coveredBy(ctx context.Context) func(string) string {
	var lists []depscan.NamedList
	for _, l := range h.Config.Routing.Lists {
		if !l.Disabled { // a disabled list routes nothing
			lists = append(lists, depscan.NamedList{Name: l.Name, Entries: l.Entries})
		}
	}
	if keenetic.Available() {
		mctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		if lr, err := keenetic.ShowManualRoutes(mctx); err == nil {
			for _, r := range lr {
				if r.Iface != "" { // a group nothing is routed through covers nothing
					lists = append(lists, depscan.NamedList{Name: r.Group + " (на роутере)", Entries: r.Entries})
				}
			}
		}
		cancel()
	}
	return depscan.CoveredIndex(lists)
}
