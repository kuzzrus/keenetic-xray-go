package featuredeps

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/opkg"
)

// A tool the tests can "install": present reflects whether opkg has been asked
// for it (and was allowed to succeed).
type fakeTool struct {
	have atomic.Bool
}

func (f *fakeTool) probe() bool { return f.have.Load() }

type rig struct {
	t       *testing.T
	mu      sync.Mutex
	joint   [][]string // every opkgInstall call
	single  []string   // every opkgInstallNoUpdate call
	jointFn func(pkgs []string) error
	oneFn   func(pkg string) error
}

// install replaces the opkg hooks and the catalogue for the test.
func install(t *testing.T, needs []Need) *rig {
	t.Helper()
	r := &rig{t: t}
	origI, origN, origC := opkgInstall, opkgInstallNoUpdate, needsFor
	opkgInstall = func(_ context.Context, pkgs ...string) error {
		r.mu.Lock()
		r.joint = append(r.joint, append([]string(nil), pkgs...))
		fn := r.jointFn
		r.mu.Unlock()
		if fn != nil {
			return fn(pkgs)
		}
		return nil
	}
	opkgInstallNoUpdate = func(_ context.Context, pkgs ...string) error {
		r.mu.Lock()
		r.single = append(r.single, strings.Join(pkgs, " "))
		fn := r.oneFn
		r.mu.Unlock()
		if fn != nil {
			return fn(pkgs[0])
		}
		return nil
	}
	needsFor = func(Feature) []Need { return needs }
	t.Cleanup(func() { opkgInstall, opkgInstallNoUpdate, needsFor = origI, origN, origC })
	return r
}

func pkgNeed(name string, tool *fakeTool, without string) Need {
	return Need{Name: name, Pkg: name, Why: "для " + name, Without: without, Present: tool.probe}
}

func TestEnsure_NothingMissingTouchesNothing(t *testing.T) {
	a, b := &fakeTool{}, &fakeTool{}
	a.have.Store(true)
	b.have.Store(true)
	r := install(t, []Need{pkgNeed("iptables", a, ""), pkgNeed("ipset", b, "")})

	res := Ensure(context.Background(), AdaptiveRouting)
	if res.Err() != nil || len(res.Installed) != 0 || len(res.Failed) != 0 || len(res.Lines("", "")) != 0 {
		t.Errorf("result = %+v", res)
	}
	if len(r.joint) != 0 || len(r.single) != 0 {
		t.Errorf("opkg was run although everything is there: %v %v", r.joint, r.single)
	}
}

// Everything that is missing goes in with ONE `opkg update` + install: on a
// slow router the update alone can take half a minute.
func TestEnsure_MissingPackagesAreInstalledInOneGo(t *testing.T) {
	ipt, ips, ct := &fakeTool{}, &fakeTool{}, &fakeTool{}
	ipt.have.Store(true) // already there
	r := install(t, []Need{pkgNeed("iptables", ipt, ""), pkgNeed("ipset", ips, ""), pkgNeed("conntrack", ct, "x")})
	r.jointFn = func(pkgs []string) error {
		ips.have.Store(true)
		ct.have.Store(true)
		return nil
	}

	res := Ensure(context.Background(), AdaptiveRouting)
	if res.Err() != nil {
		t.Fatal(res.Err())
	}
	if len(r.joint) != 1 || strings.Join(r.joint[0], " ") != "ipset conntrack" || len(r.single) != 0 {
		t.Errorf("opkg runs = %v / %v, want one install of ipset and conntrack only", r.joint, r.single)
	}
	lines := res.Lines("✅ ", "⚠️ ")
	if len(lines) != 2 || lines[0] != "✅ поставил ipset — для ipset" || lines[1] != "✅ поставил conntrack — для conntrack" {
		t.Errorf("lines = %q", lines)
	}
}

func TestEnsure_RequiredFailureIsAnErrorThatSaysWhatToDo(t *testing.T) {
	ips := &fakeTool{}
	r := install(t, []Need{pkgNeed("ipset", ips, "")})
	r.jointFn = func([]string) error {
		return &opkg.Error{Pkgs: []string{"ipset"}, Reason: "нет связи с репозиторием Entware — проверь интернет и DNS на роутере", Output: "wget: bad address", Err: errors.New("exit status 1")}
	}

	res := Ensure(context.Background(), AdaptiveRouting)
	err := res.Err()
	if err == nil {
		t.Fatal("a missing required package must be an error")
	}
	for _, want := range []string{"ipset", "для ipset", "нет связи с репозиторием", "wget: bad address", "Вручную: opkg update && opkg install ipset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "opkg install ipset:") {
		t.Errorf("the opkg prefix is repeated in %q", err)
	}
	var oe *opkg.Error
	if !errors.As(err, &oe) {
		t.Error("the underlying opkg error is not reachable through errors.As")
	}
	if len(res.Lines("", "")) != 0 {
		t.Errorf("a required failure is an error, not a warning line: %q", res.Lines("", ""))
	}
}

func TestEnsure_OptionalFailureIsAWarningNotAnError(t *testing.T) {
	ipt, ct := &fakeTool{}, &fakeTool{}
	ipt.have.Store(true)
	r := install(t, []Need{pkgNeed("iptables", ipt, ""), pkgNeed("conntrack", ct, "уже открытые соединения не переключатся сразу")})
	r.jointFn = func([]string) error { return errors.New("exit status 255") }

	res := Ensure(context.Background(), L7SNI)
	if err := res.Err(); err != nil {
		t.Fatalf("an optional tool must not stop the feature: %v", err)
	}
	lines := res.Lines("✅ ", "⚠️ ")
	if len(lines) != 1 {
		t.Fatalf("lines = %q", lines)
	}
	for _, want := range []string{"⚠️ conntrack не поставился", "exit status 255", "уже открытые соединения не переключатся сразу", "вручную: opkg update && opkg install conntrack"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("warning %q lacks %q", lines[0], want)
		}
	}
}

// One package the feed lacks must not hide the one it has: after a failed joint
// run each missing package is tried alone (without a second `opkg update`).
func TestEnsure_FailedJointRunIsRetriedPerPackage(t *testing.T) {
	ipt, ips := &fakeTool{}, &fakeTool{}
	r := install(t, []Need{pkgNeed("iptables", ipt, ""), pkgNeed("ipset", ips, "")})
	r.jointFn = func([]string) error {
		ipt.have.Store(true) // iptables landed, ipset's turn failed the whole command
		return errors.New("exit status 255")
	}
	r.oneFn = func(pkg string) error { return errors.New("Unknown package '" + pkg + "'") }

	res := Ensure(context.Background(), AdaptiveRouting)
	if len(r.single) != 1 || r.single[0] != "ipset" {
		t.Errorf("per-package retries = %v, want only ipset (iptables had landed)", r.single)
	}
	if len(res.Installed) != 1 || res.Installed[0].Name != "iptables" {
		t.Errorf("installed = %+v, want iptables", res.Installed)
	}
	if err := res.Err(); err == nil || !strings.Contains(err.Error(), "ipset") || !strings.Contains(err.Error(), "Unknown package 'ipset'") {
		t.Errorf("err = %v, want ipset's own error", err)
	}
}

func TestEnsure_RetryCanSucceedPerPackage(t *testing.T) {
	a, b := &fakeTool{}, &fakeTool{}
	r := install(t, []Need{pkgNeed("a", a, ""), pkgNeed("b", b, "")})
	r.jointFn = func([]string) error { return errors.New("joint failed") }
	r.oneFn = func(pkg string) error {
		if pkg == "a" {
			a.have.Store(true)
			return nil
		}
		return errors.New("b is not in the feed")
	}
	res := Ensure(context.Background(), AdaptiveRouting)
	if len(res.Installed) != 1 || res.Installed[0].Name != "a" || len(res.Failed) != 1 || res.Failed[0].Need.Name != "b" {
		t.Errorf("result = %+v", res)
	}
}

// opkg exits 0 but the command still does not run (a package without the
// binary, a PATH that does not reach it): never report that as installed.
func TestEnsure_InstalledButStillNotRunnable(t *testing.T) {
	ips := &fakeTool{}
	install(t, []Need{pkgNeed("ipset", ips, "")}) // opkg "succeeds", the probe stays false

	res := Ensure(context.Background(), AdaptiveRouting)
	if len(res.Installed) != 0 {
		t.Errorf("reported installed: %+v", res.Installed)
	}
	if err := res.Err(); err == nil || !strings.Contains(err.Error(), "команда всё равно не запускается") {
		t.Errorf("err = %v", err)
	}
}

func TestEnsure_ProvideNeedRunsEveryTimeAndFailsLoudly(t *testing.T) {
	calls := 0
	var failWith error
	install(t, []Need{{
		Name: "модули ядра NFLOG", Why: "перехват имён", Hint: "Возможно, прошивка не поддерживает",
		Provide: func(context.Context) error { calls++; return failWith },
	}})

	if res := Ensure(context.Background(), L7SNI); res.Err() != nil || len(res.Installed) != 0 {
		t.Errorf("ok run: %+v", res)
	}
	failWith = errors.New("insmod: xt_NFLOG: Invalid module format")
	res := Ensure(context.Background(), L7SNI)
	err := res.Err()
	if err == nil {
		t.Fatal("a failing Provide must be an error")
	}
	for _, want := range []string{"модули ядра NFLOG", "Invalid module format", "Возможно, прошивка не поддерживает"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "Вручную") {
		t.Errorf("a need with no command to run must not say 'Вручную': %q", err)
	}
	if calls != 2 {
		t.Errorf("Provide ran %d times, want 2 (it has no Present probe)", calls)
	}
}

func TestEnsure_ProvideWithPresentIsSkippedWhenThere(t *testing.T) {
	have := &fakeTool{}
	have.have.Store(true)
	ran := false
	install(t, []Need{{Name: "x", Why: "y", Present: have.probe, Provide: func(context.Context) error { ran = true; return nil }}})
	Ensure(context.Background(), L7SNI)
	if ran {
		t.Error("Provide ran although the need is present")
	}
}

// Failures are all collected, not just the first: the operator should see the
// whole picture in one answer.
func TestEnsure_ReportsEveryProblemAtOnce(t *testing.T) {
	ipt, ct := &fakeTool{}, &fakeTool{}
	r := install(t, []Need{
		pkgNeed("iptables", ipt, ""),
		pkgNeed("conntrack", ct, "что-то потеряется"),
		{Name: "модули", Why: "z", Provide: func(context.Context) error { return errors.New("no modules") }},
	})
	r.jointFn = func([]string) error { return errors.New("offline") }
	r.oneFn = func(string) error { return errors.New("offline") }

	res := Ensure(context.Background(), L7SNI)
	if len(res.Failed) != 3 {
		t.Fatalf("failed = %d, want all three", len(res.Failed))
	}
	// both required failures are in the error (different causes: two sentences)
	msg := res.Err().Error()
	if !strings.Contains(msg, "iptables") || !strings.Contains(msg, "модули") || len(strings.Split(msg, "\n")) != 2 {
		t.Errorf("Err should name both required failures, one sentence each: %q", msg)
	}
	if len(res.Lines("", "")) != 1 {
		t.Errorf("the optional conntrack failure should still be a warning line: %q", res.Lines("", ""))
	}
}

// An offline router fails every package alike: the reason and the command to
// type by hand are said once, not once per package.
func TestErr_NeedsThatFailedForTheSameReasonAreOneSentence(t *testing.T) {
	cause := &opkg.Error{Pkgs: []string{"x"}, Reason: "нет связи с репозиторием Entware", Err: errors.New("exit 1")}
	res := Result{Failed: []Failure{
		{Need: Need{Name: "iptables", Pkg: "iptables", Why: "правила"}, Err: cause},
		{Need: Need{Name: "ipset", Pkg: "ipset", Why: "список"}, Err: cause},
		{Need: Need{Name: "conntrack", Pkg: "conntrack", Without: "потеря"}, Err: cause}, // optional: not in the error
	}}
	msg := res.Err().Error()
	if strings.Count(msg, "нет связи с репозиторием Entware") != 1 {
		t.Errorf("the reason is repeated in %q", msg)
	}
	for _, want := range []string{"не удалось подготовить iptables, ipset:", "Вручную: opkg update && opkg install iptables ipset"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "conntrack") || strings.Contains(msg, "\n") {
		t.Errorf("an optional need, or a second line, in %q", msg)
	}
}

func TestErr_DifferentReasonsAreSeparateSentencesAndKeepTheirOwnFix(t *testing.T) {
	res := Result{Failed: []Failure{
		{Need: Need{Name: "iptables", Pkg: "iptables", Why: "правила"}, Err: errors.New("offline")},
		{Need: Need{Name: "модули ядра", Why: "перехват", Hint: "Возможно, прошивка не поддерживает"}, Err: errors.New("no modules")},
	}}
	lines := strings.Split(res.Err().Error(), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.Contains(lines[0], "iptables (правила): offline. Вручную: opkg update && opkg install iptables") {
		t.Errorf("line 1 = %q", lines[0])
	}
	if !strings.Contains(lines[1], "модули ядра (перехват): no modules. Возможно, прошивка не поддерживает") || strings.Contains(lines[1], "Вручную") {
		t.Errorf("line 2 = %q", lines[1])
	}
}

// The capture's start, the bot's button and a reconcile can reach Ensure at the
// same moment; two opkg runs at once fail on opkg's lock.
func TestEnsure_InstallsDoNotOverlap(t *testing.T) {
	ips := &fakeTool{}
	r := install(t, []Need{pkgNeed("ipset", ips, "")})
	var running, overlapped atomic.Int32
	r.jointFn = func([]string) error {
		if running.Add(1) > 1 {
			overlapped.Add(1)
		}
		time.Sleep(20 * time.Millisecond)
		running.Add(-1)
		ips.have.Store(true)
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); Ensure(context.Background(), AdaptiveRouting) }()
	}
	wg.Wait()
	if overlapped.Load() != 0 {
		t.Errorf("%d opkg runs overlapped", overlapped.Load())
	}
}

// The real catalogue: what each feature needs. A change here is a change in
// what an operator's router has to have, so it is pinned.
func TestCatalogue(t *testing.T) {
	type want struct {
		name     string
		optional bool
		pkg      bool
	}
	cases := map[Feature][]want{
		AdaptiveRouting: {{"iptables", false, true}, {"ipset", false, true}, {"conntrack", true, true}},
		L7SNI:           {{"iptables", false, true}, {"модули ядра NFLOG", false, false}, {"conntrack", true, true}},
	}
	for f, wants := range cases {
		got := catalogue(f)
		if len(got) != len(wants) {
			t.Errorf("%s: %d needs, want %d", f, len(got), len(wants))
			continue
		}
		for i, w := range wants {
			n := got[i]
			if n.Name != w.name || n.optional() != w.optional || (n.Pkg != "") != w.pkg {
				t.Errorf("%s[%d] = %q optional=%v pkg=%q, want %+v", f, i, n.Name, n.optional(), n.Pkg, w)
			}
			if n.Pkg != "" && n.Present == nil {
				t.Errorf("%s: package need %q must have a probe", f, n.Name)
			}
			if n.Pkg == "" && (n.Provide == nil || n.Hint == "") {
				t.Errorf("%s: need %q has neither a package nor a Provide with a Hint", f, n.Name)
			}
		}
	}
	if got := catalogue("no-such-feature"); got != nil {
		t.Errorf("an unknown feature has needs: %v", got)
	}
}

// L7 SNI without iptables was the bug: the capture died on its first iptables
// call. It must be a required need of both features that install rules.
func TestCatalogue_IptablesIsRequiredWhereRulesAreInstalled(t *testing.T) {
	for _, f := range []Feature{AdaptiveRouting, L7SNI} {
		found := false
		for _, n := range catalogue(f) {
			if n.Name == "iptables" {
				found = true
				if n.optional() {
					t.Errorf("%s: iptables must not be optional", f)
				}
			}
		}
		if !found {
			t.Errorf("%s does not ensure iptables", f)
		}
	}
}

func TestLines_NoSuffixForAnOptionalNeedWithoutAManualCommand(t *testing.T) {
	r := Result{Failed: []Failure{{Need: Need{Name: "x", Without: "потеря"}, Err: errors.New("boom")}}}
	lines := r.Lines("", "! ")
	if len(lines) != 1 || lines[0] != "! x не поставился (boom) — потеря" {
		t.Errorf("lines = %q", lines)
	}
}

func TestMissing_ListsOnlyWhatCanBeProbedAndIsAbsent(t *testing.T) {
	have, lack := &fakeTool{}, &fakeTool{}
	have.have.Store(true)
	install(t, []Need{
		pkgNeed("iptables", have, ""),
		pkgNeed("ipset", lack, ""),
		{Name: "модули", Why: "z", Provide: func(context.Context) error { return nil }}, // no probe
	})
	got := Missing(L7SNI)
	if len(got) != 1 || got[0].Name != "ipset" {
		t.Errorf("Missing = %+v, want only ipset", got)
	}
	if Names(got) != "ipset" || Names([]Need{{Name: "a"}, {Name: "b"}}) != "a, b" {
		t.Errorf("Names = %q", Names(got))
	}
}

// A caller that runs again and again (the capture's session restarts) must not
// start `opkg update` each time because an optional tool could not be installed:
// EnsureRequired leaves the optional needs alone.
func TestEnsureRequired_IgnoresOptionalNeeds(t *testing.T) {
	ipt, ct := &fakeTool{}, &fakeTool{}
	ipt.have.Store(true)
	r := install(t, []Need{pkgNeed("iptables", ipt, ""), pkgNeed("conntrack", ct, "потеря")})

	res := EnsureRequired(context.Background(), L7SNI)
	if len(r.joint) != 0 || len(r.single) != 0 {
		t.Errorf("opkg ran for an optional tool: %v %v", r.joint, r.single)
	}
	if len(res.Failed) != 0 || len(res.Installed) != 0 {
		t.Errorf("result = %+v", res)
	}

	// a missing required tool is still installed
	ipt.have.Store(false)
	r.jointFn = func([]string) error { ipt.have.Store(true); return nil }
	res = EnsureRequired(context.Background(), L7SNI)
	if len(r.joint) != 1 || strings.Join(r.joint[0], " ") != "iptables" || len(res.Installed) != 1 {
		t.Errorf("joint=%v result=%+v, want iptables installed alone", r.joint, res)
	}
}
