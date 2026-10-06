package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/netfetch"
)

// scanManyFn is depscan.ScanMany, replaceable so the tests need no network.
var scanManyFn = depscan.ScanMany

// loadRussianRanges fills the Russian-range table the scan keeps its
// address suggestions clear of (the daemon keeps it loaded; a one-shot CLI
// run has to load it). Replaceable so a test does not touch the global one.
var loadRussianRanges = func() { georangesLoadLocal(func(string, ...any) {}) }

// routesScanCmd is `routes scan <domain> [<domain> …] [--add <list> [--ip]]`:
// read each domain's page through the tunnel, list the other hosts it loads
// from and which of them need the tunnel, and the IPv4 addresses the
// domains and those hosts resolve to (internal/depscan; the bot's 🔎 screen
// is the same scan). With --add the hosts it recommends join an existing
// list; with --ip as well, the addresses go to that list's IP companion
// ("<list>-ip") -- for apps that connect by address without asking DNS,
// calls above all. Without --add nothing changes.
func routesScanCmd(cfg *config.Config, args []string) error {
	var domains []string
	addTo := ""
	withIP := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--add":
			if i+1 >= len(args) {
				return errors.New("--add нужен список: routes scan <домен> --add <список>")
			}
			i++
			addTo = args[i]
		case strings.HasPrefix(a, "--add="):
			addTo = strings.TrimPrefix(a, "--add=")
		case a == "--ip":
			withIP = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("неизвестный флаг %q", a)
		default:
			domains = append(domains, a)
		}
	}
	if withIP && addTo == "" {
		return errors.New("--ip добавляет адреса в список-компаньон, поэтому нужен и --add <список>")
	}
	seeds, problems := depscan.ParseSeeds(domains...)
	for _, p := range problems {
		fmt.Println("пропущено: " + p)
	}
	if len(seeds) == 0 {
		return errors.New("usage: keenetic-xray routes scan <домен> [<домен> …] [--add <список> [--ip]]")
	}
	var target *config.RouteList
	if addTo != "" {
		if target, _ = findList(cfg, addTo); target == nil {
			return fmt.Errorf("нет списка %q (создать: routes new %s …)", addTo, addTo)
		}
	}
	tunnel, ok := netfetch.TunnelTransport()
	if !ok {
		return errors.New("туннель не работает (xray не запущен или не настроен профиль) — сканировать нечем")
	}

	loadRussianRanges()
	ctx, cancel := context.WithTimeout(context.Background(), depscan.DefaultBudget+10*time.Second)
	defer cancel()
	fmt.Printf("читаю %s через туннель, проверяю найденные домены (до %d с)…\n", strings.Join(seeds, ", "), int(depscan.DefaultBudget.Seconds()))
	opts := depscan.Options{Tunnel: tunnel, Covered: scanCovered(ctx, cfg), ExcludeIP: russianIP}
	res, err := scanManyFn(ctx, seeds, opts, nil)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(res.Text())

	need := res.NeedNames()
	needSet := map[string]bool{}
	for _, n := range need {
		needSet[n] = true
	}
	ips := res.IPs(needSet)

	if target == nil {
		if len(need) > 0 {
			fmt.Printf("\nДобавить нужные в список: keenetic-xray routes scan %s --add <список>\n", strings.Join(seeds, " "))
		}
		if len(ips) > 0 {
			fmt.Printf("IP-адреса (%d) нужны приложениям, которые ходят на адрес без DNS, например звонкам; добавить рядом: ... --add <список> --ip\n", len(ips))
		}
		return nil
	}
	if len(need) == 0 && !(withIP && len(ips) > 0) {
		fmt.Println("\nДобавлять нечего.")
		return nil
	}

	fmt.Println()
	if len(need) > 0 {
		added, rejected := mergeEntries(target, need)
		printEntryResult("добавлено в «"+target.Name+"»", added, rejected)
	}
	msg := fmt.Sprintf("список %q: %d записей", target.Name, len(target.Entries))
	if withIP && len(ips) > 0 {
		// target points into cfg.Routing.Lists, which this may reallocate:
		// everything wanted from it is taken above.
		cip, err := cfg.AddCompanionIPs(target.Name, ips)
		if err != nil {
			return err
		}
		if cip.List == "" {
			fmt.Println("IP-список не создан: " + strings.Join(cip.Rejected, "; "))
		} else {
			printEntryResult("IP добавлено в «"+cip.List+"»", cip.Added, cip.Rejected)
			fmt.Printf("Звонки идут по UDP: если через Proxy0 они не заработали, привяжи «%s» к WireGuard/OpkgTun: routes set %s --iface=OpkgTun0\n", cip.List, cip.List)
			msg += fmt.Sprintf("; IP-список %q: %d записей", cip.List, cip.Total)
		}
	}
	return routesApply(cfg, msg)
}

// russianIP reports whether ip is in a Russian range: such an address is
// not offered for a route entry (see internal/depscan/ips.go).
func russianIP(ip string) bool {
	_, ok := georanges.Lookup(ip)
	return ok
}

// scanCovered is the "already routed" index for the scan: our enabled
// lists plus, where ndmc is there, the operator's own on the router.
func scanCovered(ctx context.Context, cfg *config.Config) func(string) string {
	var lists []depscan.NamedList
	for _, l := range cfg.Routing.Lists {
		if !l.Disabled {
			lists = append(lists, depscan.NamedList{Name: l.Name, Entries: l.Entries})
		}
	}
	if keenetic.Available() {
		mctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if lr, err := keenetic.ShowManualRoutes(mctx); err == nil {
			for _, r := range lr {
				if r.Iface != "" {
					lists = append(lists, depscan.NamedList{Name: r.Group + " (на роутере)", Entries: r.Entries})
				}
			}
		}
	}
	return depscan.CoveredIndex(lists)
}
