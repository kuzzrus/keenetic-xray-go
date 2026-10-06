package main

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/depscan"
	"github.com/kuzzrus/keenetic-xray-go/internal/netfetch"
)

// fakeScan stands in for the network: it records the seeds it was asked
// about and answers with res/err, and pretends a tunnel is running.
func fakeScan(t *testing.T, res *depscan.Result, err error) *[]string {
	t.Helper()
	var asked []string
	oldFn, oldSOCKS, oldRanges := scanManyFn, netfetch.TunnelSOCKS, loadRussianRanges
	t.Cleanup(func() { scanManyFn, netfetch.TunnelSOCKS, loadRussianRanges = oldFn, oldSOCKS, oldRanges })
	loadRussianRanges = func() {} // the global table is not the test's to fill
	netfetch.TunnelSOCKS = func() string { return "127.0.0.1:1" }
	scanManyFn = func(_ context.Context, seeds []string, _ depscan.Options, _ depscan.ScanFunc) (*depscan.Result, error) {
		asked = append(asked, seeds...)
		return res, err
	}
	return &asked
}

func scanResult() *depscan.Result {
	return &depscan.Result{
		Pages: []depscan.Page{{Seed: "example.com", FinalHost: "example.com", Status: 200}},
		Hosts: []depscan.Host{
			{Name: "img.example-a.net", Class: depscan.ClassNeed, Via: []string{depscan.ViaHTML}},
			{Name: "login.example-b.org", Class: depscan.ClassNeed, Via: []string{depscan.ViaRedirect}},
			{Name: "csp.example-c.net", Class: depscan.ClassMaybe, Tier: depscan.TierMaybe, Via: []string{depscan.ViaCSP}},
			{Name: "fine.example-d.net", Class: depscan.ClassDirect},
		},
	}
}

func scanConfig(t *testing.T) (string, *config.Config) {
	t.Helper()
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	if err := run([]string{"routes", "new", "media", "netflix.com"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfgFile, cfg
}

func TestCmdRoutes_Scan_PrintsAndChangesNothing(t *testing.T) {
	cfgFile, _ := scanConfig(t)
	asked := fakeScan(t, scanResult(), nil)
	if err := run([]string{"routes", "scan", "Example.com", "192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*asked, []string{"example.com"}) {
		t.Errorf("scanned %v; the IP is no domain to read", *asked)
	}
	cfg, _ := config.Load(cfgFile)
	if got := cfg.Routing.Lists[0].Entries; !slices.Equal(got, []string{"netflix.com"}) {
		t.Errorf("a plain scan changed the list: %v", got)
	}
}

func TestCmdRoutes_Scan_AddJoinsOnlyTheRecommended(t *testing.T) {
	cfgFile, _ := scanConfig(t)
	fakeScan(t, scanResult(), nil)
	if err := run([]string{"routes", "scan", "example.com", "--add", "media"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(cfgFile)
	want := []string{"img.example-a.net", "login.example-b.org", "netflix.com"}
	if got := cfg.Routing.Lists[0].Entries; !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v (the 'maybe' and the directly-open host stay out)", got, want)
	}
	// --add=NAME is the same.
	cfgFile2, _ := scanConfig(t)
	if err := run([]string{"routes", "scan", "--add=media", "example.com"}); err != nil {
		t.Fatal(err)
	}
	cfg2, _ := config.Load(cfgFile2)
	if !slices.Equal(cfg2.Routing.Lists[0].Entries, want) {
		t.Errorf("--add=: %v", cfg2.Routing.Lists[0].Entries)
	}
}

func TestCmdRoutes_Scan_NothingRecommended(t *testing.T) {
	cfgFile, _ := scanConfig(t)
	fakeScan(t, &depscan.Result{Pages: []depscan.Page{{Seed: "example.com", Status: 200}}}, nil)
	if err := run([]string{"routes", "scan", "example.com", "--add", "media"}); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := config.Load(cfgFile); len(cfg.Routing.Lists[0].Entries) != 1 {
		t.Errorf("entries = %v", cfg.Routing.Lists[0].Entries)
	}
}

func TestCmdRoutes_Scan_Errors(t *testing.T) {
	scanConfig(t)
	asked := fakeScan(t, scanResult(), nil)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no domain", []string{"routes", "scan"}, "usage"},
		{"only an IP", []string{"routes", "scan", "192.168.1.1"}, "usage"},
		{"unknown flag", []string{"routes", "scan", "example.com", "--all"}, "неизвестный флаг"},
		{"--add without a list", []string{"routes", "scan", "example.com", "--add"}, "--add нужен список"},
		{"--add an unknown list", []string{"routes", "scan", "example.com", "--add", "nolist"}, "нет списка"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			*asked = nil
			err := run(tc.args)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
			if len(*asked) != 0 {
				t.Errorf("scanned %v before refusing", *asked)
			}
		})
	}
}

func TestCmdRoutes_Scan_NoTunnelAndScanFailure(t *testing.T) {
	scanConfig(t)
	fakeScan(t, nil, errors.New("через туннель страница example.com не открылась: сброс"))
	err := run([]string{"routes", "scan", "example.com"})
	if err == nil || !strings.Contains(err.Error(), "не открылась") {
		t.Errorf("scan failure: err = %v", err)
	}
	netfetch.TunnelSOCKS = func() string { return "" } // restored by fakeScan's cleanup
	if err := run([]string{"routes", "scan", "example.com"}); err == nil || !strings.Contains(err.Error(), "туннель не работает") {
		t.Errorf("no tunnel: err = %v", err)
	}
}
