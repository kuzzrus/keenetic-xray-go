package botcontrol

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
	"github.com/kuzzrus/keenetic-xray-go/internal/georanges"
)

type nopRT struct{}

func (nopRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("not used") }

func scanHandler(t *testing.T, fn func(context.Context, string, depscan.Options) (*depscan.Result, error)) *RouterHandler {
	t.Helper()
	cfg := config.Default()
	cfg.Routing.Lists = []config.RouteList{
		{Name: "mine", Entries: []string{"known.example-a.net", "10.1.2.0/24"}},
		{Name: "off", Entries: []string{"disabled.example-b.net"}, Disabled: true},
	}
	return &RouterHandler{
		Config: cfg, ConfigPath: filepath.Join(t.TempDir(), "c.json"),
		scanFn:     fn,
		scanTunnel: func() (http.RoundTripper, bool) { return nopRT{}, true },
	}
}

func resultFor(seed string, hosts ...depscan.Host) *depscan.Result {
	return &depscan.Result{Pages: []depscan.Page{{Seed: seed, FinalHost: seed, Status: 200}}, Hosts: hosts}
}

func TestRouterHandler_RoutesScan_TSVAndCovered(t *testing.T) {
	var gotCovered func(string) string
	h := scanHandler(t, func(_ context.Context, seed string, o depscan.Options) (*depscan.Result, error) {
		gotCovered = o.Covered
		return resultFor(seed, depscan.Host{Name: "img.example-c.net", Class: depscan.ClassNeed, Via: []string{depscan.ViaHTML}}), nil
	})
	out, err := h.Handle(context.Background(), Command{Action: ActionRoutesScan, Args: []string{"Example.COM"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := depscan.ParseTSV(out)
	if err != nil {
		t.Fatalf("not parseable: %v\n%s", err, out)
	}
	if len(r.Pages) != 1 || r.Pages[0].Seed != "example.com" || len(r.Hosts) != 1 || r.Hosts[0].Name != "img.example-c.net" {
		t.Errorf("result = %+v", r)
	}

	// The covered-by index: enabled lists only; a domain covers its
	// subdomains; a subnet entry covers no hostname.
	for host, want := range map[string]string{
		"known.example-a.net":          "mine",
		"deep.sub.known.example-a.net": "mine",
		"disabled.example-b.net":       "", // its list is off, so nothing is routed
		"other.example-a.net":          "",
		"example-a.net":                "", // the parent of an entry is not covered
	} {
		if got := gotCovered(host); got != want {
			t.Errorf("covered(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestRouterHandler_RoutesScan_SeedsDedupedAndCapped(t *testing.T) {
	var seen atomic.Int32
	var seeds []string
	var mu sync.Mutex
	h := scanHandler(t, func(_ context.Context, seed string, _ depscan.Options) (*depscan.Result, error) {
		mu.Lock()
		seeds = append(seeds, seed)
		mu.Unlock()
		seen.Add(1)
		return resultFor(seed), nil
	})
	out, err := h.routesScan(context.Background(), []string{"a.example.com, A.example.com b.example.com", "c.example.com d.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Load() != depscan.MaxSeeds {
		t.Errorf("scanned %d domains, want the cap %d (%v)", seen.Load(), depscan.MaxSeeds, seeds)
	}
	r, _ := depscan.ParseTSV(out)
	if len(r.Pages) != depscan.MaxSeeds {
		t.Errorf("%d pages in the answer", len(r.Pages))
	}
}

func TestRouterHandler_RoutesScan_RejectsBadSeeds(t *testing.T) {
	h := scanHandler(t, func(context.Context, string, depscan.Options) (*depscan.Result, error) {
		t.Error("scanned with no valid domain")
		return nil, nil
	})
	for _, args := range [][]string{nil, {""}, {"192.168.1.1"}, {"10.0.0.0/8"}, {"router.lan"}} {
		if _, err := h.routesScan(context.Background(), args); err == nil {
			t.Errorf("args %q accepted", args)
		}
	}
	// A bad one among good ones is dropped, the good one scanned.
	var got []string
	h2 := scanHandler(t, func(_ context.Context, seed string, _ depscan.Options) (*depscan.Result, error) {
		got = append(got, seed)
		return resultFor(seed), nil
	})
	if _, err := h2.routesScan(context.Background(), []string{"192.168.1.1 good.example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "good.example.com" {
		t.Errorf("scanned %v", got)
	}
}

func TestRouterHandler_RoutesScan_NoTunnel(t *testing.T) {
	h := scanHandler(t, func(context.Context, string, depscan.Options) (*depscan.Result, error) {
		t.Error("scanned without a tunnel")
		return nil, nil
	})
	h.scanTunnel = func() (http.RoundTripper, bool) { return nil, false }
	if _, err := h.routesScan(context.Background(), []string{"example.com"}); err == nil || !strings.Contains(err.Error(), "туннель") {
		t.Errorf("err = %v", err)
	}
}

func TestRouterHandler_RoutesScan_OneFailureKeepsTheOthers(t *testing.T) {
	h := scanHandler(t, func(_ context.Context, seed string, _ depscan.Options) (*depscan.Result, error) {
		if seed == "broken.example.com" {
			return nil, errors.New("через туннель страница не открылась")
		}
		return resultFor(seed, depscan.Host{Name: "img.example-c.net", Class: depscan.ClassNeed}), nil
	})
	out, err := h.routesScan(context.Background(), []string{"good.example.com broken.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := depscan.ParseTSV(out)
	if len(r.Pages) != 2 || len(r.Hosts) != 1 {
		t.Fatalf("pages=%+v hosts=%+v", r.Pages, r.Hosts)
	}
	var failed depscan.Page
	for _, p := range r.Pages {
		if p.Seed == "broken.example.com" {
			failed = p
		}
	}
	if failed.Status != 0 || !strings.Contains(failed.Note, "не открылась") {
		t.Errorf("the failed domain's page = %+v", failed)
	}

	// Everything failing is an error, not an empty answer.
	hAll := scanHandler(t, func(context.Context, string, depscan.Options) (*depscan.Result, error) {
		return nil, errors.New("не открылась")
	})
	if _, err := hAll.routesScan(context.Background(), []string{"a.example.com"}); err == nil {
		t.Error("an all-failed scan returned no error")
	}
}

func TestRouterHandler_RoutesAddIP(t *testing.T) {
	h := scanHandler(t, nil)
	h.Config.Routing.Lists = []config.RouteList{{Name: "calls", Entries: []string{"example.com"}, Interface: "OpkgTun0"}}

	out, err := h.routesAddIP(context.Background(), []string{"calls", "95.47.173.35 95.47.173.36, example.org 192.168.1.5"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`создан IP-список "calls-ip"`, "+2 записей", "отклонено 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("answer lacks %q:\n%s", want, out)
		}
	}
	l := h.Config.Routing.Lists[1]
	if l.Name != "calls-ip" || l.Interface != "OpkgTun0" || len(l.Entries) != 2 {
		t.Errorf("companion = %+v", l)
	}
	// Saved: the file on disk has it.
	saved, err := config.Load(h.ConfigPath)
	if err != nil || len(saved.Routing.Lists) != 2 {
		t.Errorf("saved config: %v %+v", err, saved)
	}

	// Again with one new address: the same list, no new one.
	out, err = h.routesAddIP(context.Background(), []string{"calls", "95.47.173.36 95.47.173.37"})
	if err != nil || !strings.Contains(out, `IP-список "calls-ip": +1 записей, всего 3`) || len(h.Config.Routing.Lists) != 2 {
		t.Errorf("second add: %q %v", out, err)
	}
}

func TestRouterHandler_RoutesAddIP_Refusals(t *testing.T) {
	h := scanHandler(t, nil)
	h.Config.Routing.Lists = []config.RouteList{{Name: "calls"}}
	for _, args := range [][]string{nil, {"calls"}, {"calls", "  "}} {
		if _, err := h.routesAddIP(context.Background(), args); err == nil {
			t.Errorf("args %q accepted", args)
		}
	}
	if _, err := h.routesAddIP(context.Background(), []string{"nope", "8.8.4.4"}); err == nil || !strings.Contains(err.Error(), "нет списка") {
		t.Errorf("unknown list: %v", err)
	}
	// Nothing acceptable: no list is left behind and nothing is saved.
	before := len(h.Config.Routing.Lists)
	out, err := h.routesAddIP(context.Background(), []string{"calls", "example.org 10.0.0.1"})
	if err != nil || !strings.Contains(out, "IP-список не создан") || len(h.Config.Routing.Lists) != before {
		t.Errorf("all rejected: %q %v lists=%d", out, err, len(h.Config.Routing.Lists))
	}
	if _, statErr := os.Stat(h.ConfigPath); statErr == nil {
		t.Error("config saved though nothing changed")
	}
	// Through the dispatcher.
	if _, err := h.Handle(context.Background(), Command{Action: ActionRoutesAddIP, Args: []string{"calls", "8.8.4.4"}}); err != nil {
		t.Errorf("Handle: %v", err)
	}
}

func TestRouterHandler_RoutesScan_OffersNoRussianAddress(t *testing.T) {
	var exclude func(string) bool
	h := scanHandler(t, func(_ context.Context, seed string, o depscan.Options) (*depscan.Result, error) {
		exclude = o.ExcludeIP
		return resultFor(seed), nil
	})
	georanges.SetCurrent(georanges.Parse("5.255.0.0/16\n"))
	t.Cleanup(func() { georanges.SetCurrent(nil) })
	if _, err := h.routesScan(context.Background(), []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	if exclude == nil || !exclude("5.255.255.77") || exclude("8.8.4.4") {
		t.Errorf("the Russian-range filter is not wired (set=%v)", exclude != nil)
	}
}
