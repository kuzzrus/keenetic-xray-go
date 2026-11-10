package botcontrol

import (
	"context"
	"errors"
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

// availableRouter makes keenetic.Available() true for the test (an RCI endpoint
// that answers /rci/show/version); nothing else of a router exists.
func availableRouter(t *testing.T) {
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

// depsRig is a RouterHandler whose dependency step is a stub.
type depsRig struct {
	h        *RouterHandler
	result   featuredeps.Result
	features []featuredeps.Feature
}

func newDepsRig(t *testing.T) *depsRig {
	t.Helper()
	r := &depsRig{}
	r.h = &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
	r.h.EnsureDeps = func(_ context.Context, f featuredeps.Feature) featuredeps.Result {
		r.features = append(r.features, f)
		return r.result
	}
	return r
}

func missingRequired(name string) featuredeps.Result {
	return featuredeps.Result{Failed: []featuredeps.Failure{{
		Need: featuredeps.Need{Name: name, Pkg: name, Why: "правила перехвата трафика"},
		Err:  errors.New("нет связи с репозиторием Entware"),
	}}}
}

func installed(names ...string) featuredeps.Result {
	var r featuredeps.Result
	for _, n := range names {
		r.Installed = append(r.Installed, featuredeps.Need{Name: n, Why: "для " + n})
	}
	return r
}

func TestInstallsPackages(t *testing.T) {
	for _, a := range []string{ActionAdaptiveRouteOn, ActionL7SNIOn, ActionL7SNIQUICObserve, ActionL7SNIQUICAct,
		ActionSetMSS, ActionWatchdogEnable, ActionAddonInstall} {
		if !installsPackages(a) {
			t.Errorf("%s may run opkg but is not treated as installing", a)
		}
	}
	// Turning something off, or just looking, installs nothing.
	for _, a := range []string{ActionL7SNIQUICOff, ActionL7SNIOff, ActionAdaptiveRouteOff, ActionAdaptiveRouteShow, ActionStatus, ActionDaemonRestart} {
		if installsPackages(a) {
			t.Errorf("%s installs nothing but gets the long budget", a)
		}
	}
}

func TestCommandTimeout_InstallingActionsGetTheLongBudget(t *testing.T) {
	const def = 60 * time.Second
	if got := commandTimeout(ActionL7SNIOn, def); got != depsInstallTimeout {
		t.Errorf("l7sni_on budget = %v, want %v", got, depsInstallTimeout)
	}
	if depsInstallTimeout <= def {
		t.Fatalf("the install budget (%v) is not longer than the default (%v): opkg is still killed halfway", depsInstallTimeout, def)
	}
	if got := commandTimeout(ActionAdaptiveRouteOn, 10*time.Minute); got != 10*time.Minute {
		t.Errorf("a longer configured default must not be shrunk: %v", got)
	}
	if got := commandTimeout(ActionEnsureCore, def); got != coreUpdateTimeout {
		t.Errorf("core budget = %v, want %v", got, coreUpdateTimeout)
	}
	if got := commandTimeout(ActionStatus, def); got != def {
		t.Errorf("an ordinary command's budget = %v, want %v", got, def)
	}
}

// The bot waits for the answer longer than the router may take to give it.
func TestWaitFor(t *testing.T) {
	b := &TelegramBot{ResultTimeout: 20 * time.Second}
	if got := b.waitFor(ActionStatus); got != 20*time.Second {
		t.Errorf("ordinary wait = %v", got)
	}
	got := b.waitFor(ActionL7SNIOn)
	if got <= depsInstallTimeout {
		t.Errorf("wait for an installing action = %v, must exceed the router's own budget %v or the answer is lost", got, depsInstallTimeout)
	}
	short := &TelegramBot{ResultTimeout: 100 * time.Millisecond}
	if short.waitFor(ActionL7SNIOn) != time.Second {
		t.Errorf("a shortened ResultTimeout must shorten the install wait too: %v", short.waitFor(ActionL7SNIOn))
	}
}

func TestDepsNotes(t *testing.T) {
	if got := depsNotes(featuredeps.Result{}); got != "" {
		t.Errorf("notes for nothing = %q", got)
	}
	res := installed("iptables")
	res.Failed = []featuredeps.Failure{{
		Need: featuredeps.Need{Name: "conntrack", Pkg: "conntrack", Without: "открытые соединения переключатся не сразу"},
		Err:  errors.New("нет связи"),
	}}
	got := depsNotes(res)
	for _, want := range []string{"\n✅ поставил iptables — для iptables", "\n⚠️ conntrack не поставился (нет связи) — открытые соединения переключатся не сразу"} {
		if !strings.Contains(got, want) {
			t.Errorf("notes %q lack %q", got, want)
		}
	}
}

// --- L7 SNI on ---------------------------------------------------------------

func TestRouterHandler_L7SNIOn_InstallsThenSwitchesOn(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.result = installed("iptables")

	out, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIOn})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.features) != 1 || r.features[0] != featuredeps.L7SNI {
		t.Errorf("asked for the needs of %v, want L7 SNI", r.features)
	}
	if !r.h.Config.L7SNI.Enabled {
		t.Error("L7 SNI is not on")
	}
	if saved, _ := config.Load(r.h.ConfigPath); !saved.L7SNI.Enabled {
		t.Error("not saved")
	}
	for _, want := range []string{"L7 SNI включается", "✅ поставил iptables — для iptables"} {
		if !strings.Contains(out, want) {
			t.Errorf("reply lacks %q:\n%s", want, out)
		}
	}
}

// The tool is missing and cannot be installed: the button says so, with what to
// type by hand, and L7 SNI stays off -- it used to answer "включается" and then
// die on its first iptables call, with the reason in a log nobody reads.
func TestRouterHandler_L7SNIOn_MissingToolStopsTheSwitch(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.result = missingRequired("iptables")

	out, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIOn})
	if err == nil {
		t.Fatalf("want an error, got reply %q", out)
	}
	for _, want := range []string{"L7 SNI не включён", "iptables", "нет связи с репозиторием Entware", "Вручную: opkg update && opkg install iptables"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if r.h.Config.L7SNI.Enabled {
		t.Error("L7 SNI was switched on")
	}
	if _, statErr := os.Stat(r.h.ConfigPath); statErr == nil {
		t.Error("the config was saved")
	}
}

func TestRouterHandler_L7SNIOn_OptionalToolIsOnlyAWarning(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.result = featuredeps.Result{Failed: []featuredeps.Failure{{
		Need: featuredeps.Need{Name: "conntrack", Pkg: "conntrack", Without: "открытые соединения переключатся не сразу"},
		Err:  errors.New("нет связи"),
	}}}
	out, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIOn})
	if err != nil || !r.h.Config.L7SNI.Enabled {
		t.Fatalf("err=%v enabled=%v: an optional tool must not stop the switch", err, r.h.Config.L7SNI.Enabled)
	}
	if !strings.Contains(out, "⚠️ conntrack не поставился") {
		t.Errorf("reply lacks the warning:\n%s", out)
	}
}

// L7 SNI without adaptive routing does nothing for TLS/HTTP: say so, instead of
// leaving an "on" switch that quietly does nothing.
func TestRouterHandler_L7SNIOn_PointsAtAdaptiveRouting(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)

	out, _ := r.h.Handle(context.Background(), Command{Action: ActionL7SNIOn})
	if !strings.Contains(out, "Адаптивная маршрутизация выключена") {
		t.Errorf("no pointer at adaptive routing:\n%s", out)
	}

	r = newDepsRig(t)
	r.h.Config.AdaptiveRoute.Enabled = true
	out, _ = r.h.Handle(context.Background(), Command{Action: ActionL7SNIOn})
	if strings.Contains(out, "Адаптивная маршрутизация выключена") {
		t.Errorf("the pointer must not appear when adaptive routing is on:\n%s", out)
	}
}

func TestRouterHandler_L7SNIOff_InstallsNothing(t *testing.T) {
	r := newDepsRig(t)
	r.h.Config.L7SNI.Enabled = true
	if _, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIOff}); err != nil {
		t.Fatal(err)
	}
	if len(r.features) != 0 {
		t.Errorf("turning L7 SNI off asked for its tools: %v", r.features)
	}
}

// --- QUIC modes ---------------------------------------------------------------

func TestRouterHandler_L7SNIQUIC_ChecksToolsBeforePlacingTheRule(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.h.Config.L7SNI.Enabled = true
	reconciles := 0
	r.h.ReconcileL7SNI = func(context.Context) error { reconciles++; return nil }

	r.result = missingRequired("iptables")
	out, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve})
	if err != nil {
		t.Fatalf("the mode is saved, so this is not a failed action: %v", err)
	}
	if reconciles != 0 {
		t.Error("the UDP rule was placed although iptables is missing")
	}
	for _, want := range []string{"iptables", "Вручную: opkg update && opkg install iptables", "Режим сохранён"} {
		if !strings.Contains(out, want) {
			t.Errorf("reply lacks %q:\n%s", want, out)
		}
	}
	if saved, _ := config.Load(r.h.ConfigPath); saved.L7SNI.QUIC != "observe" {
		t.Errorf("mode = %q, want it saved anyway", saved.L7SNI.QUIC)
	}

	r.result = installed("iptables")
	out, _ = r.h.Handle(context.Background(), Command{Action: ActionL7SNIQUICAct})
	if reconciles != 1 || !strings.Contains(out, "✅ поставил iptables") || !strings.Contains(out, "приведено в соответствие") {
		t.Errorf("reconciles=%d, reply:\n%s", reconciles, out)
	}
}

func TestRouterHandler_L7SNIQUIC_OffInstallsNothing(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.h.Config.L7SNI.Enabled = true
	r.h.Config.L7SNI.QUIC = config.L7SNIQUICObserve
	r.h.ReconcileL7SNI = func(context.Context) error { return nil }
	if _, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIQUICOff}); err != nil {
		t.Fatal(err)
	}
	if len(r.features) != 0 {
		t.Errorf("switching QUIC off asked for tools: %v", r.features)
	}
}

// With L7 SNI itself off nothing runs, so nothing is installed for it.
func TestRouterHandler_L7SNIQUIC_WithL7SNIOffInstallsNothing(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	if _, err := r.h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve}); err != nil {
		t.Fatal(err)
	}
	if len(r.features) != 0 {
		t.Errorf("asked for tools with L7 SNI off: %v", r.features)
	}
}

// --- adaptive routing -----------------------------------------------------------

func TestRouterHandler_AdaptiveRouteOn_MissingToolStopsTheSwitch(t *testing.T) {
	availableRouter(t)
	r := newDepsRig(t)
	r.result = missingRequired("ipset")

	_, err := r.h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteOn})
	if err == nil || !strings.Contains(err.Error(), "ipset") || !strings.Contains(err.Error(), "Вручную") {
		t.Fatalf("err = %v, want the ipset problem with what to type by hand", err)
	}
	if len(r.features) != 1 || r.features[0] != featuredeps.AdaptiveRouting {
		t.Errorf("asked for %v, want the adaptive routing needs", r.features)
	}
	if r.h.Config.AdaptiveRoute.Enabled {
		t.Error("adaptive routing was switched on")
	}
	if _, statErr := os.Stat(r.h.ConfigPath); statErr == nil {
		t.Error("the config was saved")
	}
}

// --- the bot waits for a router that is installing something ------------------

// answerAfter plays a slow router: it takes the next queued command, works for
// delay (an opkg install), then answers.
func answerAfter(t *testing.T, store *Store, router string, delay time.Duration, res Result) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if cmd, _ := store.Dequeue(router); cmd != nil {
				time.Sleep(delay)
				res.CommandID = cmd.ID
				_ = store.RecordResult(router, res)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

func slowRouterBot(t *testing.T) (*fakeTelegram, *Store, int) {
	t.Helper()
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	// ResultTimeout 100 ms: an ordinary button gives the router 100 ms, one that
	// may install a package 1 s; the "router" below takes 400 ms.
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 100 * time.Millisecond}
	runBotInBackground(t, bot)
	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	return fake, store, fake.lastSent(t).MessageID
}

// The L7 screen: switching on / a QUIC mode may install iptables first -- the
// bot must still be waiting when the router answers, or the operator sees "роутер
// не ответил" for a switch that went through.
func TestTelegramBot_L7SNIScreenWaitsForAnInstallingRouter(t *testing.T) {
	fake, store, msgID := slowRouterBot(t)
	answerAfter(t, store, "home", 400*time.Millisecond, Result{Output: "L7 SNI включается, демон перезапускается…\n✅ поставил iptables — для iptables"})

	fake.pushCallback(1, msgID, "adxQ:home:l7sni_on")
	text := fake.waitForEditContaining(t, 3*time.Second, "поставил iptables")
	if strings.Contains(text, "не ответил") {
		t.Errorf("the bot gave up before the router finished:\n%s", text)
	}
}

// ...while a button that installs nothing is not made to wait: a router that
// does not answer in time is reported, as before.
func TestTelegramBot_L7SNIScreenDoesNotWaitLongForAButtonThatInstallsNothing(t *testing.T) {
	fake, store, msgID := slowRouterBot(t)
	answerAfter(t, store, "home", 400*time.Millisecond, Result{Output: "QUIC-перехват: выкл"})

	fake.pushCallback(1, msgID, "adxQ:home:l7q_off")
	fake.waitForEditContaining(t, 3*time.Second, "не ответил")
}

// The router card path (adaptive routing's button is a plain "act:" one).
func TestTelegramBot_CardButtonThatInstallsWaitsForTheRouter(t *testing.T) {
	fake, store, msgID := slowRouterBot(t)
	answerAfter(t, store, "home", 400*time.Millisecond, Result{Output: "Адаптивная маршрутизация включена\n✅ поставил ipset — для ipset"})

	fake.pushCallback(1, msgID, "act:adrt_on:home")
	text := fake.waitForEditContaining(t, 3*time.Second, "поставил ipset")
	if strings.Contains(text, "не ответил") {
		t.Errorf("the bot gave up before the router finished:\n%s", text)
	}
}

func TestTelegramBot_CardButtonThatInstallsNothingDoesNotWaitLong(t *testing.T) {
	fake, store, msgID := slowRouterBot(t)
	answerAfter(t, store, "home", 400*time.Millisecond, Result{Output: "выключено"})

	fake.pushCallback(1, msgID, "act:adrt_off:home")
	fake.waitForEditContaining(t, 3*time.Second, "не ответил")
}
