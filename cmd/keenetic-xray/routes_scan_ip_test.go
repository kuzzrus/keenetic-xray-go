package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
)

// scanResultWithIPs is scanResult plus addresses: the scanned domain's own,
// and those of the hosts the page needs and one it only might.
func scanResultWithIPs() *depscan.Result {
	r := scanResult()
	r.Pages[0].SeedIPs = []string{"93.184.216.34"}
	r.Hosts[0].IPs = []string{"95.47.173.35", "95.47.173.36"} // img.example-a.net: need
	r.Hosts[1].IPs = []string{"8.8.4.4"}                      // login.example-b.org: need
	r.Hosts[2].IPs = []string{"1.0.0.1"}                      // csp.example-c.net: maybe, never added
	return r
}

func TestCmdRoutes_Scan_IPNeedsAdd(t *testing.T) {
	scanConfig(t)
	asked := fakeScan(t, scanResultWithIPs(), nil)
	err := run([]string{"routes", "scan", "example.com", "--ip"})
	if err == nil || !strings.Contains(err.Error(), "--add") {
		t.Errorf("err = %v", err)
	}
	if len(*asked) != 0 {
		t.Errorf("scanned %v before refusing", *asked)
	}
}

func TestCmdRoutes_Scan_AddWithIPFillsTheCompanion(t *testing.T) {
	cfgFile, _ := scanConfig(t)
	fakeScan(t, scanResultWithIPs(), nil)
	if err := run([]string{"routes", "scan", "example.com", "--add", "media", "--ip"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(cfgFile)
	var base, ipl *config.RouteList
	for i := range cfg.Routing.Lists {
		switch cfg.Routing.Lists[i].Name {
		case "media":
			base = &cfg.Routing.Lists[i]
		case "media-ip":
			ipl = &cfg.Routing.Lists[i]
		}
	}
	if base == nil || ipl == nil {
		t.Fatalf("lists = %+v", cfg.Routing.Lists)
	}
	if !slices.Equal(base.Entries, []string{"img.example-a.net", "login.example-b.org", "netflix.com"}) {
		t.Errorf("domains = %v", base.Entries)
	}
	// The domain's own address and the two needed hosts' -- not the "maybe" host's.
	want := []string{"8.8.4.4", "93.184.216.34", "95.47.173.35", "95.47.173.36"}
	if !slices.Equal(ipl.Entries, want) {
		t.Errorf("addresses = %v, want %v", ipl.Entries, want)
	}
}

func TestCmdRoutes_Scan_AddWithoutIPLeavesAddressesOut(t *testing.T) {
	cfgFile, _ := scanConfig(t)
	fakeScan(t, scanResultWithIPs(), nil)
	if err := run([]string{"routes", "scan", "example.com", "--add", "media"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(cfgFile)
	if len(cfg.Routing.Lists) != 1 {
		t.Errorf("a list was created without --ip: %+v", cfg.Routing.Lists)
	}
}

func TestCmdRoutes_Scan_IPAloneWhenNothingElseIsRecommended(t *testing.T) {
	// An app's host: no page, no hosts -- just the domain's addresses.
	cfgFile, _ := scanConfig(t)
	fakeScan(t, &depscan.Result{Pages: []depscan.Page{{Seed: "voip.example.com", Note: "страница не открылась", SeedIPs: []string{"149.154.167.51"}}}}, nil)
	if err := run([]string{"routes", "scan", "voip.example.com", "--add", "media", "--ip"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(cfgFile)
	if len(cfg.Routing.Lists) != 2 || !slices.Equal(cfg.Routing.Lists[1].Entries, []string{"149.154.167.51"}) {
		t.Errorf("lists = %+v", cfg.Routing.Lists)
	}
	if got := cfg.Routing.Lists[0].Entries; !slices.Equal(got, []string{"netflix.com"}) {
		t.Errorf("the domain list changed: %v", got)
	}
}
