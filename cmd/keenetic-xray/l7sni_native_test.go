package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// wgConfig is a config whose WG transport is on: Wireguard0 is our egress.
func wgConfig() *config.Config {
	c := config.Default()
	c.WGTransport = config.WGTransportConfig{Enabled: true, Iface: "Wireguard0"}
	c.L7SNI.Enabled = true
	c.AdaptiveRoute.Enabled = true
	return c
}

// hisRoutes is the shape of the lists in the router a bundle came from: the
// operator's own lists through the WG transport, one through the LTE modem, one
// of ours, one not routed, one of addresses only.
func hisRoutes() []keenetic.LiveRoute {
	return []keenetic.LiveRoute{
		{Group: "domain-list0", Iface: "Wireguard0", Entries: []string{"instagram.com", "CDNInstagram.com", "203.0.113.0/24"}},
		{Group: "domain-list1", Iface: "Wireguard0", Entries: []string{"youtube.com", "googlevideo.com"}},
		{Group: "domain-list7", Iface: "Proxy0", Entries: []string{"example.org"}},
		{Group: "domain-list9", Iface: "UsbLte0", Entries: []string{"bank.example", "gosuslugi.ru"}},
		{Group: "domain-list5", Iface: "", Entries: []string{"not-routed.example"}},
		{Group: "domain-list6", Iface: "Wireguard0", Entries: []string{"198.51.100.7", "10.0.0.0/8"}},
		{Group: keenetic.RouteGroupPrefix + "telegram", Iface: "Wireguard0", Entries: []string{"t.me"}},
	}
}

func TestL7SNIRouterNamesFrom_SortsTheListsByWhereTheyGo(t *testing.T) {
	r := l7sniRouterNamesFrom(hisRoutes(), wgConfig(), time.Unix(100, 0))

	for _, want := range []string{"instagram.com", "cdninstagram.com", "youtube.com", "googlevideo.com", "example.org"} {
		if _, ok := r.allow[want]; !ok {
			t.Errorf("%q (a list routed into our xray) is not in the names to act on: %v", want, r.allow)
		}
	}
	for _, not := range []string{"bank.example", "t.me", "not-routed.example", "203.0.113.0"} {
		if _, ok := r.allow[not]; ok {
			t.Errorf("%q must not be in the names to act on", not)
		}
	}
	for _, want := range []string{"bank.example", "gosuslugi.ru"} {
		if _, ok := r.veto[want]; !ok {
			t.Errorf("%q (a list routed to the LTE modem) is not protected: %v", want, r.veto)
		}
	}
	if _, ok := r.veto["not-routed.example"]; ok {
		t.Error("a group that is not routed anywhere has no opinion to protect")
	}
	// the lists that hold names, not the groups: the address-only list, the
	// project's own and the unrouted one do not count
	if r.lists != 3 {
		t.Errorf("lists = %d, want 3 (domain-list0, -list1, -list7)", r.lists)
	}
	if len(r.skipped) != 1 || r.skipped[0] != "UsbLte0" {
		t.Errorf("skipped = %v, want [UsbLte0]", r.skipped)
	}
	if !strings.Contains(r.summary(), "UsbLte0") || !strings.Contains(r.summary(), "5 имён из 3 списков") {
		t.Errorf("summary = %q", r.summary())
	}
}

// With the WG transport off, Wireguard0 is somebody else's interface: the same
// lists are names to protect, not to act on.
func TestL7SNIRouterNamesFrom_FollowsTheConfiguredEgress(t *testing.T) {
	cfg := wgConfig()
	cfg.WGTransport.Enabled = false
	r := l7sniRouterNamesFrom(hisRoutes(), cfg, time.Now())
	if _, ok := r.allow["instagram.com"]; ok {
		t.Error("a list through a transport that is switched off is acted on")
	}
	if _, ok := r.veto["instagram.com"]; !ok {
		t.Error("...and its names are not protected")
	}
	if _, ok := r.allow["example.org"]; !ok {
		t.Error("the Proxy0 list stopped being ours")
	}
}

func TestL7SNIRouterNamesFrom_IsCappedForAPathologicalRouter(t *testing.T) {
	var routes []keenetic.LiveRoute
	for g := 0; g < 171; g++ {
		var entries []string
		for i := 0; i < 300; i++ {
			entries = append(entries, fmt.Sprintf("host%d-%d.example", g, i))
		}
		routes = append(routes, keenetic.LiveRoute{Group: fmt.Sprintf("domain-list%d", g), Iface: "Wireguard0", Entries: entries})
	}
	r := l7sniRouterNamesFrom(routes, wgConfig(), time.Now())
	if !r.truncated || len(r.allow) >= l7sniRouterMaxNames+300 {
		t.Errorf("truncated=%v names=%d, want it cut near %d", r.truncated, len(r.allow), l7sniRouterMaxNames)
	}
	if !strings.Contains(r.summary(), "обрезано") {
		t.Errorf("a cut reading says nothing about it: %q", r.summary())
	}
}

// A host is acted on when it is on a list routed into our xray and not under a
// name the operator sent elsewhere -- even when both cover it.
func TestL7SNISnapshot_VetoWins(t *testing.T) {
	snap := l7sniSnapshot{
		domains: l7sniDomainSet{"example.com": {}},
		native:  l7sniDomainSet{"youtube.com": {}},
		veto:    []l7sniDomainSet{{"video.youtube.com": {}}, {"private.example.com": {}}},
	}
	for host, want := range map[string]bool{
		"www.youtube.com":              true,  // the router's list
		"cdn.example.com":              true,  // the config's list
		"video.youtube.com":            false, // vetoed by a list routed elsewhere
		"a.video.youtube.com":          false, // ... and everything under it
		"private.example.com":          false, // vetoed by the second set
		"unrelated.org":                false,
		"notyoutube.com":               false, // label boundary, like the config's lists
		"youtube.com.evil.example.org": false,
	} {
		if got := snap.matchesName(host); got != want {
			t.Errorf("matchesName(%q) = %v, want %v", host, got, want)
		}
	}
	if !snap.hasNames() || (l7sniSnapshot{}).hasNames() {
		t.Error("hasNames: a snapshot with names says no, or an empty one says yes")
	}
	if !(l7sniSnapshot{native: l7sniDomainSet{"a.example": {}}}).hasNames() {
		t.Error("a snapshot with only the router's names has none")
	}
}

// --- the handler with the router's names ----------------------------------

func TestHandler_ARouterListNameIsRedirected(t *testing.T) {
	r := newRig(t)
	snap := l7sniSnapshot{enabled: true, ttl: time.Hour, native: l7sniDomainSet{"youtube.com": {}}, quic: config.L7SNIQUICOff}
	r.feed(clientHelloPacket("www.youtube.com", 443), snap)
	if len(r.redirects) != 1 || r.count(statTLSMatch) != 1 || r.count(statTLSActed) != 1 {
		t.Errorf("redirects=%+v match=%d acted=%d, want one of each", r.redirects, r.count(statTLSMatch), r.count(statTLSActed))
	}
}

func TestHandler_AVetoedNameIsCountedButNotRedirected(t *testing.T) {
	r := newRig(t)
	snap := l7sniSnapshot{
		enabled: true, ttl: time.Hour, quic: config.L7SNIQUICOff,
		native: l7sniDomainSet{"example.com": {}},
		veto:   []l7sniDomainSet{{"bank.example.com": {}}},
	}
	r.feed(clientHelloPacket("online.bank.example.com", 443), snap)
	if len(r.redirects) != 0 || r.count(statTLSMatch) != 0 {
		t.Errorf("a name the operator routed elsewhere was acted on: %+v match=%d", r.redirects, r.count(statTLSMatch))
	}
	if r.count(statTLSName) != 1 {
		t.Error("the sighting itself is not counted")
	}
	r.feed(clientHelloPacket("www.example.com", 443), snap)
	if len(r.redirects) != 1 {
		t.Errorf("a name next to the vetoed one stopped matching: %+v", r.redirects)
	}
}

// --- reading the router -----------------------------------------------------

// stubRouter points the file's router touch points at fakes for one test. It
// returns how many times the lists were read.
func stubRouter(t *testing.T, available bool, routes []keenetic.LiveRoute, err error) *int {
	t.Helper()
	oa, or := l7sniRouterAvailable, l7sniReadRoutes
	reads := 0
	var mu sync.Mutex
	l7sniRouterAvailable = func() bool { return available }
	l7sniReadRoutes = func(context.Context) ([]keenetic.LiveRoute, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		return routes, err
	}
	l7sniRouterCache.Store(nil)
	t.Cleanup(func() {
		l7sniRouterAvailable, l7sniReadRoutes = oa, or
		l7sniRouterCache.Store(nil)
	})
	return &reads
}

// writeCfg saves cfg where configPath() finds it.
func writeCfg(t *testing.T, cfg *config.Config) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logSink) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func TestL7SNIRefreshRouterNames_StoresTheReadingAndLogsOnlyChanges(t *testing.T) {
	routes := hisRoutes()
	stubRouter(t, true, routes, nil)
	writeCfg(t, wgConfig())
	var log logSink

	if err := l7sniRefreshRouterNames(context.Background(), log.logf); err != nil {
		t.Fatal(err)
	}
	r := l7sniRouterCache.Load()
	if r == nil || len(r.allow) != 5 {
		t.Fatalf("cache after the first reading: %+v", r)
	}
	if err := l7sniRefreshRouterNames(context.Background(), log.logf); err != nil {
		t.Fatal(err)
	}
	if got := log.all(); len(got) != 1 || !strings.Contains(got[0], "списки роутера") || !strings.Contains(got[0], "5 имён из 3 списков") {
		t.Errorf("log after two identical readings = %q, want one line", got)
	}

	l7sniReadRoutes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return append(routes, keenetic.LiveRoute{Group: "domain-list20", Iface: "Wireguard0", Entries: []string{"new.example"}}), nil
	}
	if err := l7sniRefreshRouterNames(context.Background(), log.logf); err != nil {
		t.Fatal(err)
	}
	if got := log.all(); len(got) != 2 || !strings.Contains(got[1], "6 имён из 4 списков") {
		t.Errorf("log after a changed reading = %q", got)
	}
}

// The loop keeps what it last read when a reading fails, says why once, and
// goes on.
func TestL7SNIRouterNamesLoop_KeepsTheLastReadingThroughFailures(t *testing.T) {
	oe, or := l7sniRouterRefreshEvery, l7sniRouterRetryAfter
	l7sniRouterRefreshEvery, l7sniRouterRetryAfter = 5*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { l7sniRouterRefreshEvery, l7sniRouterRetryAfter = oe, or })
	stubRouter(t, true, hisRoutes(), nil)
	writeCfg(t, wgConfig())

	var calls int
	var mu sync.Mutex
	l7sniReadRoutes = func(context.Context) ([]keenetic.LiveRoute, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return hisRoutes(), nil
		}
		return nil, errors.New("ndmc: busy")
	}
	var log logSink
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l7sniRouterNamesLoop(ctx, log.logf); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 5 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if r := l7sniRouterCache.Load(); r == nil || len(r.allow) != 5 {
		t.Errorf("the failed readings replaced or emptied the cache: %+v", r)
	}
	failures := 0
	for _, l := range log.all() {
		if strings.Contains(l, "прочитать не удалось") {
			failures++
		}
	}
	if failures != 1 {
		t.Errorf("the same failure was logged %d times, want once: %q", failures, log.all())
	}
}

// --- what the operator is told ----------------------------------------------

func TestL7SNINamesFor_ReadsTheRouterWhenNothingFreshIsCached(t *testing.T) {
	reads := stubRouter(t, true, hisRoutes(), nil)
	cfg := wgConfig()
	cfg.Routing.Lists = []config.RouteList{{Name: "telegram", Entries: []string{"t.me", "telegram.org"}, Interface: "Wireguard0"}}

	n := l7sniNamesFor(context.Background(), cfg)
	if *reads != 1 || n.Config != 2 || n.Router != 5 || n.RouterLists != 3 {
		t.Fatalf("reads=%d names=%+v, want 1 read, 2 from the config and 5 from 3 router lists", *reads, n)
	}
	line, none := n.line()
	if none || !strings.Contains(line, "Имена для сравнения: 7 (из конфига 2, из списков роутера 5 в 3 списках)") || !strings.Contains(line, "списки через UsbLte0 не смотрю") {
		t.Errorf("line = %q (none=%v)", line, none)
	}

	// a fresh copy is used as it is...
	l7sniNamesFor(context.Background(), cfg)
	if *reads != 1 {
		t.Errorf("a fresh cache was read again (%d reads)", *reads)
	}
	// ...a stale one is read again
	old := l7sniRouterCache.Load()
	stale := *old
	stale.at = time.Now().Add(-2 * l7sniRouterMaxAge)
	l7sniRouterCache.Store(&stale)
	l7sniNamesFor(context.Background(), cfg)
	if *reads != 2 {
		t.Errorf("a stale cache was not read again (%d reads)", *reads)
	}
}

func TestL7SNINamesFor_NothingToMatchSaysSoAndWhy(t *testing.T) {
	stubRouter(t, true, []keenetic.LiveRoute{{Group: "domain-list9", Iface: "UsbLte0", Entries: []string{"bank.example"}}}, nil)
	n := l7sniNamesFor(context.Background(), wgConfig())
	line, none := n.line()
	if !none {
		t.Fatalf("none = false for %+v", n)
	}
	for _, want := range []string{"Сравнивать не с чем", "ведущих через Proxy0/Wireguard0", "нет ни одного домена", "имена только считаются", "списки через UsbLte0 не смотрю"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q lacks %q", line, want)
		}
	}
}

// The router cannot be read: the config's lists still count, and the operator is
// told the router's could not be.
func TestL7SNINamesFor_ARouterThatCannotBeReadIsSaid(t *testing.T) {
	stubRouter(t, true, nil, errors.New("show running-config: ndmc timed out"))
	cfg := wgConfig()
	cfg.Routing.Lists = []config.RouteList{{Name: "telegram", Entries: []string{"t.me"}, Interface: "Wireguard0"}}
	n := l7sniNamesFor(context.Background(), cfg)
	line, none := n.line()
	if none || n.Config != 1 || n.RouterErr == nil {
		t.Fatalf("names = %+v none=%v", n, none)
	}
	if !strings.Contains(line, "списки роутера прочитать не удалось: show running-config: ndmc timed out") {
		t.Errorf("line = %q", line)
	}
}

// Off a router there are no router lists to read, and no attempt is made.
func TestL7SNINamesFor_OffARouterIsTheConfigAlone(t *testing.T) {
	reads := stubRouter(t, false, hisRoutes(), nil)
	cfg := wgConfig()
	cfg.Routing.Lists = []config.RouteList{{Name: "telegram", Entries: []string{"t.me"}, Interface: "Wireguard0"}}
	n := l7sniNamesFor(context.Background(), cfg)
	if *reads != 0 || n.Router != 0 || n.Config != 1 {
		t.Errorf("reads=%d names=%+v", *reads, n)
	}
}

func TestL7SNINamesLine_SilentWhileL7IsOff(t *testing.T) {
	reads := stubRouter(t, true, hisRoutes(), nil)
	cfg := wgConfig()
	cfg.L7SNI.Enabled = false
	if line, none := l7sniNamesLine(context.Background(), cfg); line != "" || none || *reads != 0 {
		t.Errorf("line=%q none=%v reads=%d with L7 SNI off", line, none, *reads)
	}
}

func TestPrintL7SNIState_SaysWhatItMatchesAgainst(t *testing.T) {
	stubRouter(t, true, hisRoutes(), nil)
	var b bytes.Buffer
	printL7SNIState(&b, wgConfig())
	if !strings.Contains(b.String(), "Имена для сравнения: 5 (из конфига 0, из списков роутера 5 в 3 списках)") {
		t.Errorf("show does not say what it matches against:\n%s", b.String())
	}

	stubRouter(t, true, nil, nil)
	b.Reset()
	printL7SNIState(&b, wgConfig())
	if !strings.Contains(b.String(), "Сравнивать не с чем") {
		t.Errorf("show does not warn that there is nothing to match:\n%s", b.String())
	}

	cfg := wgConfig()
	cfg.L7SNI.Enabled = false
	b.Reset()
	printL7SNIState(&b, cfg)
	if strings.Contains(b.String(), "Имена для сравнения") || strings.Contains(b.String(), "Сравнивать не с чем") {
		t.Errorf("show talks about names while L7 SNI is off:\n%s", b.String())
	}
}

// The capture block of the counters (CLI stats, bot counters, diag) carries the
// same sentence.
func TestCaptureCheckCarriesTheNamesSentence(t *testing.T) {
	stubRouter(t, true, hisRoutes(), nil)
	writeCfg(t, wgConfig())
	stubL7SNICheck(t, true, mangleRules("eth2.4", 5, 5, 0), "eth2.4")
	got := l7sniCaptureCheck(&l7sniStatsFile{Messages: 10})
	if !strings.Contains(got, "Имена для сравнения: 5") {
		t.Errorf("capture check lacks the names sentence:\n%s", got)
	}
}

// `quic act` with nothing to match against used to say so (through its hints);
// the warning now comes from the names sentence, and only for an act that acts.
func TestL7SNIQUICNamesWarning(t *testing.T) {
	stubRouter(t, true, nil, nil)
	act := wgConfig()
	act.L7SNI.QUIC = config.L7SNIQUICAct
	if line, none := l7sniQUICNamesWarning(act); !none || !strings.Contains(line, "Сравнивать не с чем") {
		t.Errorf("act with nothing to match: %q none=%v", line, none)
	}

	observe := wgConfig()
	observe.L7SNI.QUIC = config.L7SNIQUICObserve
	if line, none := l7sniQUICNamesWarning(observe); none || line != "" {
		t.Errorf("observe counts and needs no list, but warned: %q", line)
	}

	noAdaptive := act
	noAdaptive.AdaptiveRoute.Enabled = false // act reads as observe
	if line, _ := l7sniQUICNamesWarning(noAdaptive); line != "" {
		t.Errorf("an act that only observes warned: %q", line)
	}

	stubRouter(t, true, hisRoutes(), nil)
	if line, none := l7sniQUICNamesWarning(act); none {
		t.Errorf("act with router lists to match warned: %q", line)
	}
}
