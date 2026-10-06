package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/netfetch"
)

// scanManyFn is depscan.ScanMany, replaceable so the tests need no network.
var scanManyFn = depscan.ScanMany

// routesScanCmd is `routes scan <domain> [<domain> …] [--add <list>]`: read
// each domain's page through the tunnel, list the other hosts it loads from
// and which of them need the tunnel (internal/depscan; the bot's 🔎 screen is
// the same scan). With --add the hosts it recommends join an existing list;
// without it nothing changes.
func routesScanCmd(cfg *config.Config, args []string) error {
	var domains []string
	addTo := ""
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
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("неизвестный флаг %q", a)
		default:
			domains = append(domains, a)
		}
	}
	seeds, problems := depscan.ParseSeeds(domains...)
	for _, p := range problems {
		fmt.Println("пропущено: " + p)
	}
	if len(seeds) == 0 {
		return errors.New("usage: keenetic-xray routes scan <домен> [<домен> …] [--add <список>]")
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

	ctx, cancel := context.WithTimeout(context.Background(), depscan.DefaultBudget+10*time.Second)
	defer cancel()
	fmt.Printf("читаю %s через туннель, проверяю найденные домены (до %d с)…\n", strings.Join(seeds, ", "), int(depscan.DefaultBudget.Seconds()))
	res, err := scanManyFn(ctx, seeds, depscan.Options{Tunnel: tunnel, Covered: scanCovered(ctx, cfg)}, nil)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(res.Text())

	if target == nil {
		if need := res.NeedNames(); len(need) > 0 {
			fmt.Printf("\nДобавить нужные в список: keenetic-xray routes scan %s --add <список>\n", strings.Join(seeds, " "))
		}
		return nil
	}
	need := res.NeedNames()
	if len(need) == 0 {
		fmt.Println("\nДобавлять нечего.")
		return nil
	}
	added, rejected := mergeEntries(target, need)
	fmt.Println()
	printEntryResult("добавлено в «"+target.Name+"»", added, rejected)
	return routesApply(cfg, fmt.Sprintf("список %q: %d записей", target.Name, len(target.Entries)))
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
