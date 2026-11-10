package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// fakeRouter makes keenetic.Available() true for the test (an RCI endpoint that
// answers /rci/show/version), so the commands that refuse to run off a router
// can be driven; nothing else of the router exists.
func fakeRouter(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"title":"5.2.1"}`))
	}))
	if _, err := keenetic.UseRCI(srv.URL, ""); err != nil {
		srv.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = keenetic.UseRCI("", "")
		srv.Close()
	})
}

// depsStub replaces what the commands ask featuredeps and records the calls.
type depsStub struct {
	missing  []featuredeps.Need
	result   featuredeps.Result
	features []featuredeps.Feature
}

func stubDeps(t *testing.T, missing []featuredeps.Need, res featuredeps.Result) *depsStub {
	t.Helper()
	s := &depsStub{missing: missing, result: res}
	origM, origE, origR := featureMissing, featureEnsure, featureEnsureRequired
	featureMissing = func(featuredeps.Feature) []featuredeps.Need { return s.missing }
	ensure := func(_ context.Context, f featuredeps.Feature) featuredeps.Result {
		s.features = append(s.features, f)
		return s.result
	}
	// Both variants: the capture's session picks one by whether it is the
	// process's first start, and a real one reaching an actual iptables (as root,
	// on a dev box) is exactly what these tests must never do.
	featureEnsure, featureEnsureRequired = ensure, ensure
	t.Cleanup(func() { featureMissing, featureEnsure, featureEnsureRequired = origM, origE, origR })
	return s
}

func requiredFailure(name string) featuredeps.Result {
	return featuredeps.Result{Failed: []featuredeps.Failure{{
		Need: featuredeps.Need{Name: name, Pkg: name, Why: "правила"},
		Err:  errors.New("нет связи с репозиторием Entware"),
	}}}
}

func TestEnsureFeatureDeps_SaysWhatItDoesAndWhatItCouldNot(t *testing.T) {
	stubDeps(t,
		[]featuredeps.Need{{Name: "iptables"}, {Name: "conntrack"}},
		featuredeps.Result{
			Installed: []featuredeps.Need{{Name: "iptables", Why: "правила перехвата трафика"}},
			Failed: []featuredeps.Failure{{
				Need: featuredeps.Need{Name: "conntrack", Pkg: "conntrack", Without: "открытые соединения переключатся не сразу"},
				Err:  errors.New("нет связи"),
			}},
		})
	var out bytes.Buffer
	if err := ensureFeatureDepsTo(&out, featuredeps.L7SNI); err != nil {
		t.Fatalf("an optional failure must not be an error: %v", err)
	}
	for _, want := range []string{
		"не хватает: iptables, conntrack — ставлю через opkg",
		"поставил iptables — правила перехвата трафика",
		"предупреждение: conntrack не поставился (нет связи) — открытые соединения переключатся не сразу",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestEnsureFeatureDeps_NothingMissingIsSilent(t *testing.T) {
	stubDeps(t, nil, featuredeps.Result{})
	var out bytes.Buffer
	if err := ensureFeatureDepsTo(&out, featuredeps.AdaptiveRouting); err != nil || out.Len() != 0 {
		t.Errorf("err=%v output=%q, want silence", err, out.String())
	}
}

func TestEnsureFeatureDeps_RequiredFailureIsReturned(t *testing.T) {
	stubDeps(t, []featuredeps.Need{{Name: "iptables"}}, requiredFailure("iptables"))
	var out bytes.Buffer
	err := ensureFeatureDepsTo(&out, featuredeps.L7SNI)
	if err == nil || !strings.Contains(err.Error(), "iptables") || !strings.Contains(err.Error(), "Вручную: opkg update && opkg install iptables") {
		t.Errorf("err = %v", err)
	}
}

func TestL7SNIEnable(t *testing.T) {
	stub := stubDeps(t, nil, featuredeps.Result{})
	cfg := config.Default()
	if err := l7sniEnable(cfg); err != nil || !cfg.L7SNI.Enabled {
		t.Fatalf("err=%v enabled=%v", err, cfg.L7SNI.Enabled)
	}
	if len(stub.features) != 1 || stub.features[0] != featuredeps.L7SNI {
		t.Errorf("asked for %v, want the L7 SNI needs", stub.features)
	}

	stubDeps(t, nil, requiredFailure("iptables"))
	cfg = config.Default()
	err := l7sniEnable(cfg)
	if err == nil || !strings.Contains(err.Error(), "L7 SNI не включён") {
		t.Errorf("err = %v, want it to say L7 SNI was not switched on", err)
	}
	if cfg.L7SNI.Enabled {
		t.Error("L7 SNI was switched on although iptables is missing")
	}
}

func depsConfigPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	t.Setenv("KEENETIC_XRAY_PID_FILE", filepath.Join(dir, "none.pid")) // no daemon to signal
	return path
}

// `transport l7sni on` with a tool missing: an error, and nothing saved -- an L7
// SNI that is "on" but cannot start only looks like it works.
func TestTransportL7SNIOn_MissingToolStopsTheSwitch(t *testing.T) {
	path := depsConfigPath(t)
	fakeRouter(t)
	stubDeps(t, []featuredeps.Need{{Name: "iptables"}}, requiredFailure("iptables"))

	cfg := config.Default()
	var err error
	captureStdout(t, func() { err = transportL7SNI(cfg, []string{"on"}) })
	if err == nil || !strings.Contains(err.Error(), "iptables") {
		t.Fatalf("err = %v, want the iptables problem", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("the config was saved although L7 SNI could not be switched on")
	}
	if cfg.L7SNI.Enabled {
		t.Error("L7 SNI is on in memory")
	}
}

func TestTransportL7SNIOn_SavesAndPointsAtAdaptiveRouting(t *testing.T) {
	path := depsConfigPath(t)
	fakeRouter(t)
	stub := stubDeps(t, nil, featuredeps.Result{})

	cfg := config.Default() // adaptive routing off by default
	var err error
	out := captureStdout(t, func() { err = transportL7SNI(cfg, []string{"on"}) })
	if err != nil {
		t.Fatal(err)
	}
	saved, lerr := config.Load(path)
	if lerr != nil || !saved.L7SNI.Enabled {
		t.Fatalf("saved config: %+v, %v", saved, lerr)
	}
	if len(stub.features) != 1 {
		t.Errorf("deps asked %d times, want once", len(stub.features))
	}
	if !strings.Contains(out, "адаптивная маршрутизация выключена") || !strings.Contains(out, "transport adaptive on") {
		t.Errorf("no pointer at adaptive routing in:\n%s", out)
	}

	// with adaptive routing on there is nothing to point at
	cfg = config.Default()
	cfg.AdaptiveRoute.Enabled = true
	out = captureStdout(t, func() { err = transportL7SNI(cfg, []string{"on"}) })
	if err != nil || strings.Contains(out, "адаптивная маршрутизация выключена") {
		t.Errorf("err=%v, the note must not appear when adaptive routing is on:\n%s", err, out)
	}
}

func TestTransportL7SNIOff_InstallsNothing(t *testing.T) {
	depsConfigPath(t)
	stub := stubDeps(t, nil, featuredeps.Result{})
	cfg := config.Default()
	cfg.L7SNI.Enabled = true
	captureStdout(t, func() { _ = transportL7SNI(cfg, []string{"off"}) })
	if len(stub.features) != 0 {
		t.Errorf("turning L7 SNI off asked for its tools: %v", stub.features)
	}
}

// QUIC modes: the tools are checked again (L7 SNI may predate the check, /opt may
// have been wiped), and the UDP rule is only placed when they are there.
func TestTransportL7SNIQUIC_ChecksToolsBeforePlacingTheRule(t *testing.T) {
	depsConfigPath(t)
	fakeRouter(t)
	reconciles := 0
	orig := reconcileL7SNIHook
	reconcileL7SNIHook = func(context.Context, *config.Config, func(string, ...any)) error { reconciles++; return nil }
	t.Cleanup(func() { reconcileL7SNIHook = orig })

	cfg := config.Default()
	cfg.L7SNI.Enabled = true

	stub := stubDeps(t, nil, requiredFailure("iptables"))
	var err error
	out := captureStdout(t, func() { err = transportL7SNIQUIC(cfg, []string{"observe"}) })
	if err != nil {
		t.Fatalf("the mode is saved, so this is not a failed command: %v", err)
	}
	if reconciles != 0 {
		t.Error("the UDP rule was placed although iptables is missing")
	}
	if !strings.Contains(out, "предупреждение: не удалось подготовить iptables") || !strings.Contains(out, "поставить не удалось") {
		t.Errorf("output must say what is missing:\n%s", out)
	}
	if cfg.L7SNI.QUIC != "observe" {
		t.Errorf("mode = %q, want it saved anyway", cfg.L7SNI.QUIC)
	}

	stub.result = featuredeps.Result{}
	out = captureStdout(t, func() { err = transportL7SNIQUIC(cfg, []string{"act"}) })
	if err != nil || reconciles != 1 {
		t.Errorf("tools present: err=%v reconciles=%d, want the rule placed once", err, reconciles)
	}
	if !strings.Contains(out, "приведено в соответствие") {
		t.Errorf("output:\n%s", out)
	}

	// off: nothing to install, the rule is taken away
	n := len(stub.features)
	captureStdout(t, func() { err = transportL7SNIQUIC(cfg, []string{"off"}) })
	if len(stub.features) != n || reconciles != 2 {
		t.Errorf("off: deps asked %d more times, reconciles=%d, want 0 more and 2", len(stub.features)-n, reconciles)
	}
}

// adaptive routing: iptables is a required tool too (it was not before), and a
// missing one stops the switch before anything is touched.
func TestAdaptiveRouteOn_MissingToolStopsTheSwitch(t *testing.T) {
	path := depsConfigPath(t)
	fakeRouter(t)
	stub := stubDeps(t, nil, requiredFailure("ipset"))

	cfg := config.Default()
	var err error
	captureStdout(t, func() { err = adaptiveRouteOn(cfg) })
	if err == nil || !strings.Contains(err.Error(), "ipset") {
		t.Fatalf("err = %v, want the ipset problem", err)
	}
	if len(stub.features) != 1 || stub.features[0] != featuredeps.AdaptiveRouting {
		t.Errorf("asked for %v", stub.features)
	}
	if cfg.AdaptiveRoute.Enabled {
		t.Error("adaptive routing was switched on")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("the config was saved")
	}
}

// The daemon's start-up: a tool that is missing and cannot be installed in time
// is logged and the feature is not started -- it must not go on to build a
// dataplane on a router that cannot run it.
func TestApplyAdaptiveRouteAtStartup_MissingToolIsLoggedAndStops(t *testing.T) {
	fakeRouter(t)
	stubDeps(t, nil, requiredFailure("ipset"))
	cfg := config.Default()
	cfg.AdaptiveRoute.Enabled = true

	var logs []string
	applyAdaptiveRouteAtStartup(cfg, func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	joined := strings.Join(logs, "\n")
	if !strings.Contains(joined, "adaptive-route: not starting") || !strings.Contains(joined, "ipset") {
		t.Errorf("log = %q", joined)
	}
	if strings.Contains(joined, "LAN detection") || strings.Contains(joined, "REDIRECT") {
		t.Errorf("start-up went on after the tool failed: %q", joined)
	}
}

// --- the wizard's watchdog offer ---------------------------------------------------

func watchdogRig(t *testing.T, armed bool) {
	t.Helper()
	cron := filepath.Join(t.TempDir(), "root")
	t.Setenv("KEENETIC_XRAY_CRON_FILE", cron)
	if armed {
		if err := os.WriteFile(cron, []byte("*/2 * * * * x # "+"keenetic-xray-watchdog\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func stubWatchdogEnable(t *testing.T, out string, err error) *int {
	t.Helper()
	calls := 0
	orig := watchdogEnableFn
	watchdogEnableFn = func() (string, error) { calls++; return out, err }
	t.Cleanup(func() { watchdogEnableFn = orig })
	return &calls
}

// Not armed: the summary no longer tells the operator to type
// `opkg install cron && ...` -- it offers to do it, and "Enter" is yes.
func TestOfferWatchdog_EnterEnablesIt(t *testing.T) {
	watchdogRig(t, false)
	fakeRouter(t)
	calls := stubWatchdogEnable(t, "watchdog enabled (cron confirmed running)", nil)

	var out bytes.Buffer
	offerWatchdog(&out, bufio.NewReader(strings.NewReader("\n")))
	if *calls != 1 {
		t.Fatalf("watchdog enable ran %d times, want 1", *calls)
	}
	for _, want := range []string{"watchdog не активен", "Включить сейчас (при необходимости поставит cron)", "watchdog enabled (cron confirmed running)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "opkg install cron") {
		t.Errorf("the hand-typed command is still printed:\n%s", out.String())
	}
}

func TestOfferWatchdog_NoLeavesItOffAndSaysHowToEnableLater(t *testing.T) {
	watchdogRig(t, false)
	fakeRouter(t)
	calls := stubWatchdogEnable(t, "x", nil)
	for _, answer := range []string{"n\n", "No\n", "н\n", "нет\n"} {
		var out bytes.Buffer
		offerWatchdog(&out, bufio.NewReader(strings.NewReader(answer)))
		if !strings.Contains(out.String(), "keenetic-xray watchdog enable") {
			t.Errorf("answer %q: no way back shown:\n%s", answer, out.String())
		}
	}
	if *calls != 0 {
		t.Errorf("enabled %d times against a 'no'", *calls)
	}
}

func TestOfferWatchdog_FailureSaysWhyAndHowToRetry(t *testing.T) {
	watchdogRig(t, false)
	fakeRouter(t)
	stubWatchdogEnable(t, "", errors.New("cron isn't available and couldn't be installed: opkg install cron: нет связи с репозиторием Entware"))
	var out bytes.Buffer
	offerWatchdog(&out, bufio.NewReader(strings.NewReader("y\n")))
	for _, want := range []string{"не вышло", "нет связи с репозиторием Entware", "keenetic-xray watchdog enable"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestOfferWatchdog_SilentWhenArmedOrOffARouter(t *testing.T) {
	calls := stubWatchdogEnable(t, "x", nil)

	watchdogRig(t, true)
	fakeRouter(t)
	var out bytes.Buffer
	offerWatchdog(&out, bufio.NewReader(strings.NewReader("\n")))
	if out.Len() != 0 || *calls != 0 {
		t.Errorf("armed watchdog: output %q, %d enables", out.String(), *calls)
	}

	watchdogRig(t, false) // not armed, but no router (UseRCI reset below)
	_, _ = keenetic.UseRCI("", "")
	out.Reset()
	offerWatchdog(&out, bufio.NewReader(strings.NewReader("\n")))
	if out.Len() != 0 || *calls != 0 {
		t.Errorf("off a router: output %q, %d enables", out.String(), *calls)
	}
}

// --- optional tools in the background -----------------------------------------------

func TestEnsureOptionalInBackground_OncePerProcessAndPerFeature(t *testing.T) {
	optionalTried.Delete(featuredeps.L7SNI)
	optionalTried.Delete(featuredeps.AdaptiveRouting)
	t.Cleanup(func() {
		optionalTried.Delete(featuredeps.L7SNI)
		optionalTried.Delete(featuredeps.AdaptiveRouting)
	})
	calls := make(chan featuredeps.Feature, 8)
	orig := featureEnsure
	featureEnsure = func(_ context.Context, f featuredeps.Feature) featuredeps.Result {
		calls <- f
		return featuredeps.Result{Failed: []featuredeps.Failure{{
			Need: featuredeps.Need{Name: "conntrack", Pkg: "conntrack", Without: "потеря"}, Err: errors.New("нет связи"),
		}}}
	}
	t.Cleanup(func() { featureEnsure = orig })

	logs := make(chan string, 8)
	logf := func(f string, a ...any) { logs <- fmt.Sprintf(f, a...) }
	ensureOptionalInBackground(featuredeps.L7SNI, "l7sni", logf)
	ensureOptionalInBackground(featuredeps.L7SNI, "l7sni", logf) // a session restart: nothing
	ensureOptionalInBackground(featuredeps.AdaptiveRouting, "adaptive-route", logf)

	got := map[featuredeps.Feature]int{}
	for i := 0; i < 2; i++ {
		select {
		case f := <-calls:
			got[f]++
		case <-time.After(3 * time.Second):
			t.Fatal("the background ensure did not run")
		}
	}
	select {
	case f := <-calls:
		t.Errorf("a third ensure ran for %s", f)
	case <-time.After(150 * time.Millisecond):
	}
	if got[featuredeps.L7SNI] != 1 || got[featuredeps.AdaptiveRouting] != 1 {
		t.Errorf("calls = %v, want one per feature", got)
	}
	select {
	case line := <-logs:
		if !strings.Contains(line, "conntrack не поставился") {
			t.Errorf("log line = %q", line)
		}
	case <-time.After(3 * time.Second):
		t.Error("nothing was logged")
	}
}
