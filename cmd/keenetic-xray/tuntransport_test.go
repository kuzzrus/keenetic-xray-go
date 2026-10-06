package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestMain lets the tests below use this test binary itself as a stand-in
// for the xray-core binary (`xray run -test -c <file>`), selected via
// KEENETIC_TEST_FAKE_XRAY -- the same trick internal/xrayctl and
// internal/failover use, so no real xray-core is needed in CI.
func TestMain(m *testing.M) {
	switch os.Getenv("KEENETIC_TEST_FAKE_XRAY") {
	case "ok":
		fmt.Println("Configuration OK.")
		os.Exit(0)
	case "no-tun":
		fmt.Println(`Failed to start: infra/conf: failed to load inbound detour config: unknown protocol "tun"`)
		os.Exit(255)
	}
	os.Exit(m.Run())
}

func TestCheckXrayKnowsTun(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_BINARY", os.Args[0])

	t.Setenv("KEENETIC_TEST_FAKE_XRAY", "ok")
	if err := checkXrayKnowsTun(context.Background(), 1280); err != nil {
		t.Fatalf("a core that knows tun was refused: %v", err)
	}

	// A core from before the inbound existed: refused, with xray's own
	// reason and the remedy -- before the router is touched.
	t.Setenv("KEENETIC_TEST_FAKE_XRAY", "no-tun")
	err := checkXrayKnowsTun(context.Background(), 1280)
	if err == nil {
		t.Fatal("a core that does not know tun was accepted")
	}
	for _, want := range []string{"tun-inbound", `unknown protocol "tun"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}

	t.Setenv("KEENETIC_XRAY_BINARY", filepath.Join(t.TempDir(), "no-such-xray"))
	if err := checkXrayKnowsTun(context.Background(), 1280); err == nil {
		t.Error("a missing xray binary was accepted")
	}
}

func TestTunSpec(t *testing.T) {
	cfg := config.Default()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun2"}
	if s := tunSpec(cfg); s.Iface != "OpkgTun2" || s.Address != config.DefaultTunAddr || s.MTU != config.DefaultTunMTU {
		t.Errorf("defaults: %+v", s)
	}
	cfg.TunTransport.Addr, cfg.TunTransport.MTU = "10.9.9.9", 1400
	if s := tunSpec(cfg); s.Address != "10.9.9.9" || s.MTU != 1400 {
		t.Errorf("explicit values not honored: %+v", s)
	}
}

func TestTunRouteLists(t *testing.T) {
	cfg := config.Default()
	cfg.Routing.Lists = []config.RouteList{
		{Name: "a", Interface: "OpkgTun0"},
		{Name: "b", Interface: "Proxy0"},
		{Name: "c"}, // the Proxy0 default
		{Name: "d", Interface: "OpkgTun0"},
		{Name: "e", Interface: "OpkgTun1"},
	}
	if got := strings.Join(tunRouteLists(cfg, "OpkgTun0"), ","); got != "a,d" {
		t.Errorf("tunRouteLists(OpkgTun0) = %q, want a,d", got)
	}
	if got := tunRouteLists(cfg, ""); got != nil {
		t.Errorf("tunRouteLists with no interface = %v, want none", got)
	}
}

func TestCmdTransport_TunUsage(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	err := run([]string{"transport", "tun", "sideways"})
	if err == nil || !strings.Contains(err.Error(), "transport tun {show|on|off|mtu") {
		t.Errorf("err = %v, want the usage line", err)
	}
	// An unknown transport now lists tun among the valid ones.
	err = run([]string{"transport", "nonsense"})
	if err == nil || !strings.Contains(err.Error(), "tun {show|on|off|mtu}") {
		t.Errorf("transport usage does not mention tun: %v", err)
	}
}

// Off the router `on` has nothing to configure: it says so and changes no
// state -- in particular it must not flip the config to "enabled".
func TestCmdTransport_TunOnWithoutRouter(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	err := run([]string{"transport", "tun", "on"})
	if err == nil || !strings.Contains(err.Error(), "ndmc") {
		t.Fatalf("err = %v, want the no-router refusal", err)
	}
	if cfg, lerr := config.Load(cfgFile); lerr != nil || cfg.TunTransport.Enabled {
		t.Errorf("config after a refused `on`: enabled=%v err=%v", cfg.TunTransport.Enabled, lerr)
	}
}

// `off` frees the pinned interface name (so the next `on` picks the lowest
// free one again) but leaves the operator's route lists alone -- it only
// warns about them.
func TestCmdTransport_TunOff(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	cfg := config.Default()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0", MTU: 1400}
	cfg.Routing.Lists = []config.RouteList{{Name: "yt", Interface: "OpkgTun0", Entries: []string{"youtube.com"}}}
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run([]string{"transport", "tun", "off"}); err != nil {
			t.Errorf("transport tun off: %v", err)
		}
	})
	if !strings.Contains(out, "yt") || !strings.Contains(out, "OpkgTun0") {
		t.Errorf("no warning about the route list that targets the interface:\n%s", out)
	}
	got, err := config.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.TunTransport.Enabled || got.TunTransport.Iface != "" {
		t.Errorf("TunTransport after off = %+v, want disabled with the interface freed", got.TunTransport)
	}
	if got.TunTransport.MTU != 1400 {
		t.Errorf("off lost the operator's MTU: %+v", got.TunTransport)
	}
	if len(got.Routing.Lists) != 1 || got.Routing.Lists[0].Interface != "OpkgTun0" {
		t.Errorf("off rewrote the route lists: %+v", got.Routing.Lists)
	}
}

func TestCmdTransport_TunMTU(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	saved := func() config.TunTransportConfig {
		t.Helper()
		cfg, err := config.Load(cfgFile)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.TunTransport
	}

	// Showing says the default and the allowed range, and changes nothing.
	out := captureStdout(t, func() {
		if err := run([]string{"transport", "tun", "mtu"}); err != nil {
			t.Errorf("transport tun mtu: %v", err)
		}
	})
	if !strings.Contains(out, "1280 (по умолчанию)") || !strings.Contains(out, "1280..1500") {
		t.Errorf("show output:\n%s", out)
	}

	// Setting saves it (off a router, or with the transport off, that is all
	// there is to do) and a re-run shows it without the default note.
	out = captureStdout(t, func() {
		if err := run([]string{"transport", "tun", "mtu", "1500"}); err != nil {
			t.Errorf("transport tun mtu 1500: %v", err)
		}
	})
	if got := saved().MTU; got != 1500 {
		t.Errorf("saved MTU = %d, want 1500", got)
	}
	if !strings.Contains(out, "сохранено") {
		t.Errorf("a set with nothing live to apply did not say it was only saved:\n%s", out)
	}
	out = captureStdout(t, func() { _ = run([]string{"transport", "tun", "mtu"}) })
	if !strings.Contains(out, "1500") || strings.Contains(out, "по умолчанию") {
		t.Errorf("show after set:\n%s", out)
	}

	// It touches nothing else: the transport stays as configured.
	cfg := config.Default()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0", MTU: 1400}
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}
	// Enabled, but this is not a router: still just saved.
	if err := run([]string{"transport", "tun", "mtu", "1450"}); err != nil {
		t.Fatalf("transport tun mtu 1450: %v", err)
	}
	if got := saved(); got.MTU != 1450 || !got.Enabled || got.Iface != "OpkgTun0" {
		t.Errorf("after set on an enabled transport: %+v", got)
	}

	// auto = back to the default.
	for _, word := range []string{"auto", "AUTO", "default"} {
		if err := run([]string{"transport", "tun", "mtu", "1500"}); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"transport", "tun", "mtu", word}); err != nil {
			t.Fatalf("mtu %s: %v", word, err)
		}
		if got := saved().MTU; got != 0 {
			t.Errorf("mtu %s left MTU = %d, want 0 (default)", word, got)
		}
	}

	// Anything outside 1280..1500 or not a number is refused and changes nothing.
	if err := run([]string{"transport", "tun", "mtu", "1450"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"1279", "1501", "9000", "0", "-1", "abc", "1500.5", ""} {
		if err := run([]string{"transport", "tun", "mtu", bad}); err == nil {
			t.Errorf("mtu %q was accepted", bad)
		}
		if got := saved().MTU; got != 1450 {
			t.Fatalf("a refused mtu %q changed the saved value to %d", bad, got)
		}
	}
	if err := run([]string{"transport", "tun", "mtu", "1300", "extra"}); err == nil {
		t.Error("mtu with an extra argument was accepted")
	}
}

func TestPrintTransport_TunLines(t *testing.T) {
	cfg := config.Default()
	out := captureStdout(t, func() { printTransport(cfg) })
	if !strings.Contains(out, "TUN-транспорт: выкл") {
		t.Errorf("off state not shown:\n%s", out)
	}
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun3", MTU: 1400}
	out = captureStdout(t, func() { printTransport(cfg) })
	if !strings.Contains(out, "TUN-транспорт: вкл — OpkgTun3, MTU 1400") {
		t.Errorf("on state not shown:\n%s", out)
	}
}

func TestCmdStatus_TunLine(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	cfg := config.Default()
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}
	if out := captureStdout(t, func() { _ = cmdStatus(nil) }); strings.Contains(out, "tun-transport") {
		t.Errorf("a tun-transport line with the transport off:\n%s", out)
	}
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0"}
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}
	if out := captureStdout(t, func() { _ = cmdStatus(nil) }); !strings.Contains(out, "tun-transport: on (OpkgTun0)") {
		t.Errorf("tun-transport line missing:\n%s", out)
	}
}

// doctor's block says nothing off a router -- there is nothing to check.
func TestCheckTunTransport_NoRouterIsSilent(t *testing.T) {
	cfg := config.Default()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0"}
	checkTunTransport(cfg, func(ok bool, msg string) {
		t.Errorf("checkTunTransport reported without a router: %v %q", ok, msg)
	})
}

// The reconcile step must be a safe no-op without a router, whatever the
// config asks for -- the same guard as TestReconcileSteps_NoRouterIsNoop.
func TestReconcileTunTransport_NoRouterIsNoop(t *testing.T) {
	cfg := config.Default()
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0"}
	reconcileTunTransport(context.Background(), nil, cfg, func(f string, a ...any) {
		t.Errorf("reconcileTunTransport logged without a router: "+f, a...)
	})
	off := config.Default()
	reconcileTunTransport(context.Background(), nil, off, func(f string, a ...any) {
		t.Errorf("reconcileTunTransport logged with the transport off: "+f, a...)
	})
}
