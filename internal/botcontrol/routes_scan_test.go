package botcontrol

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
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
