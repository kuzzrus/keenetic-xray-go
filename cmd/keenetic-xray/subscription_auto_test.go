package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

// subBody is a subscription of one vless:// node per name (a distinct host each,
// so each is its own server).
func subBody(names ...string) string {
	var b strings.Builder
	for _, n := range names { // the UUID follows the name: a reordered list is the same servers
		fmt.Fprintf(&b, "vless://%08x-1111-2222-3333-444444444444@%s.example.com:443?type=tcp&security=none#%s\n", crc32.ChecksumIEEE([]byte(n)), n, n)
	}
	return b.String()
}

// subServer serves a settable subscription body and counts the requests.
type subServer struct {
	*httptest.Server
	body      atomic.Value
	status    atomic.Int32
	hits      atomic.Int32
	onRequest func() // runs inside the handler, before it answers
}

func newSubServer(t *testing.T, body string) *subServer {
	t.Helper()
	s := &subServer{}
	s.body.Store(body)
	s.status.Store(http.StatusOK)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.onRequest != nil {
			s.onRequest()
		}
		if code := int(s.status.Load()); code != http.StatusOK {
			http.Error(w, "refused", code)
			return
		}
		fmt.Fprint(w, s.body.Load().(string))
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *subServer) set(body string) { s.body.Store(body) }

// autoEnv is an autoRefresher on a temp config, a fake clock and a collecting bot.
type autoEnv struct {
	t       *testing.T
	srv     *subServer
	secret  string // the token in the subscription URL
	cfgPath string
	now     time.Time
	reloads int
	events  chan botcontrol.Event
	logs    []string
	r       *autoRefresher
}

// newAutoEnv writes a config with the server's URL as the shared subscription
// and primes it with a first refresh, then makes it look as if that was
// `age` ago.
func newAutoEnv(t *testing.T, body string, age time.Duration) *autoEnv {
	t.Helper()
	e := &autoEnv{t: t, srv: newSubServer(t, body), secret: "SECRETTOKEN", now: time.Now(), events: make(chan botcontrol.Event, 16)}
	e.cfgPath = filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", e.cfgPath)

	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: e.srv.URL + "/sub/" + e.secret}
	if _, err := subscription.RefreshConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.Subscription.PrimaryKey, cfg.Subscription.BackupKey = cfg.Profiles[0].Remark, cfg.Profiles[1].Remark
	cfg.Subscription.LastFetchedAt = e.now.Add(-age)
	if err := cfg.Save(e.cfgPath); err != nil {
		t.Fatal(err)
	}
	e.srv.hits.Store(0)

	e.r = &autoRefresher{
		logf:      func(f string, a ...any) { e.logs = append(e.logs, fmt.Sprintf(f, a...)) },
		events:    e.events,
		reload:    func() bool { e.reloads++; return true },
		now:       func() time.Time { return e.now },
		statePath: filepath.Join(filepath.Dir(e.cfgPath), "state.json"),
	}
	return e
}

func (e *autoEnv) cfg() *config.Config {
	e.t.Helper()
	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		e.t.Fatal(err)
	}
	return cfg
}

func (e *autoEnv) state() subscription.RefreshState {
	return subscription.LoadRefreshState(e.r.statePath)
}

// pushed drains what the bot was sent.
func (e *autoEnv) pushed() []string {
	var out []string
	for {
		select {
		case ev := <-e.events:
			out = append(out, ev.Text)
		default:
			return out
		}
	}
}

func (e *autoEnv) tick() time.Duration { return e.r.tick(context.Background()) }

func remarks(cfg *config.Config) string {
	var rs []string
	for _, p := range cfg.Profiles {
		rs = append(rs, p.Remark)
	}
	return strings.Join(rs, ",")
}

func TestAutoRefresh_NotDueDoesNotFetch(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), time.Hour)
	if wait := e.tick(); wait != subRefreshPoll {
		t.Errorf("wait = %s, want the poll interval", wait)
	}
	if e.srv.hits.Load() != 0 || e.reloads != 0 || len(e.pushed()) != 0 {
		t.Errorf("hits %d reloads %d: nothing was due", e.srv.hits.Load(), e.reloads)
	}
}

// The ordinary run: due, fetched, nothing differs. The config gets its new
// timestamp; the daemon is NOT reloaded (that restarts xray) and the bot hears nothing.
func TestAutoRefresh_DueButUnchanged(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	if wait := e.tick(); wait != subRefreshPoll {
		t.Errorf("wait = %s", wait)
	}
	if e.srv.hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", e.srv.hits.Load())
	}
	if e.reloads != 0 || len(e.pushed()) != 0 {
		t.Errorf("reloads %d: an unchanged subscription must not restart anything or say anything", e.reloads)
	}
	cfg := e.cfg()
	if cfg.Subscription.LastFetchedAt.Before(e.now.Add(-time.Minute)) {
		t.Errorf("LastFetchedAt %s not updated", cfg.Subscription.LastFetchedAt)
	}
	if st := e.state(); !st.LastSuccess.Equal(e.now) || st.Failures != 0 {
		t.Errorf("state %+v", st)
	}

	// Done: nothing is due again until the interval has passed.
	e.tick()
	if e.srv.hits.Load() != 1 {
		t.Errorf("refetched straight away: %d hits", e.srv.hits.Load())
	}
}

func TestAutoRefresh_ChangedReloadsTheDaemonAndTellsTheBot(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(subBody("alpha", "beta", "gamma"))
	e.tick()

	if got := remarks(e.cfg()); got != "alpha,beta,gamma" {
		t.Fatalf("profiles = %s", got)
	}
	if e.reloads != 1 {
		t.Errorf("reloads = %d, want 1", e.reloads)
	}
	msgs := e.pushed()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "3 профилей") || !strings.Contains(msgs[0], "+ gamma") {
		t.Errorf("messages %q", msgs)
	}
	if cfg := e.cfg(); cfg.Primary().Remark != "alpha" || cfg.Backup().Remark != "beta" {
		t.Errorf("slots moved: %s / %s", cfg.Primary().Remark, cfg.Backup().Remark)
	}
}

// A provider that only reorders its list changes nothing the daemon runs on:
// the config on disk follows (names, order, indexes), but xray is not restarted
// and the operator hears nothing.
func TestAutoRefresh_ReorderIsSilent(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta", "gamma"), 13*time.Hour)
	e.srv.set(subBody("gamma", "beta", "alpha"))
	e.tick()
	if cfg := e.cfg(); remarks(cfg) != "gamma,beta,alpha" || cfg.Primary().Remark != "alpha" || cfg.Backup().Remark != "beta" {
		t.Errorf("after a reorder: %s, primary %s", remarks(cfg), cfg.Primary().Remark)
	}
	if e.reloads != 0 {
		t.Errorf("reloads = %d: a reorder must not restart xray", e.reloads)
	}
	if msgs := e.pushed(); len(msgs) != 0 {
		t.Errorf("a reorder is not news: %q", msgs)
	}
}

// Panels put counters in node names ("осталось 112 ГБ") that differ on every
// fetch. A renamed server -- the active one included -- is the same server: no
// restart, no message, not even the note that it was matched by fingerprint.
func TestAutoRefresh_RenamedServersAreSilent(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta", "gamma"), 13*time.Hour)
	renamed := strings.NewReplacer("#alpha", "#alpha [112 GB left]", "#beta", "#beta [112 GB left]").Replace(subBody("alpha", "beta", "gamma"))
	e.srv.set(renamed)
	e.tick()

	cfg := e.cfg()
	if remarks(cfg) != "alpha [112 GB left],beta [112 GB left],gamma" {
		t.Fatalf("the new names were not stored: %s", remarks(cfg))
	}
	if cfg.Primary().Remark != "alpha [112 GB left]" || cfg.Backup().Remark != "beta [112 GB left]" {
		t.Errorf("slots lost their servers: %s / %s", cfg.Primary().Remark, cfg.Backup().Remark)
	}
	if e.reloads != 0 || len(e.pushed()) != 0 {
		t.Errorf("reloads %d: a rename is neither a restart nor news", e.reloads)
	}

	// And the next fetch, with other numbers in the names, is silent again.
	e.srv.set(strings.ReplaceAll(renamed, "112", "98"))
	e.now = e.now.Add(13 * time.Hour)
	e.tick()
	if e.srv.hits.Load() != 2 || e.reloads != 0 || len(e.pushed()) != 0 {
		t.Errorf("second fetch: hits %d reloads %d", e.srv.hits.Load(), e.reloads)
	}
}

// A server whose settings changed behind the same name and address (a rotated
// UUID) does need the daemon: the live profile is not what it was.
func TestAutoRefresh_ChangedSettingsOfTheActiveServerReload(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(strings.Replace(subBody("alpha", "beta"), "-3333-444444444444@alpha", "-3333-555555555555@alpha", 1))
	e.tick()
	if e.reloads != 1 {
		t.Errorf("reloads = %d, want 1", e.reloads)
	}
	msgs := e.pushed()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "основной (alpha): параметры сервера изменились") || !strings.Contains(msgs[0], "~ параметры изменились: alpha") {
		t.Errorf("messages %q", msgs)
	}
}

// A server that moved -- a new address behind the same name -- is one change,
// reported as such rather than as a removal plus an addition.
func TestAutoRefresh_AMovedServerIsOneChange(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(strings.Replace(subBody("alpha", "beta"), "@alpha.example.com:443", "@alpha-new.example.com:443", 1))
	e.tick()
	if e.reloads != 1 {
		t.Errorf("reloads = %d, want 1", e.reloads)
	}
	msgs := e.pushed()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "основной (alpha): сменился адрес или транспорт") || !strings.Contains(msgs[0], "~ параметры изменились: alpha") ||
		strings.Contains(msgs[0], "+ alpha") || strings.Contains(msgs[0], "− alpha") {
		t.Errorf("messages %q", msgs)
	}
}

// The active server vanishes from the provider's list. The refresh keeps it
// (the daemon stays on a server that may merely be missing from one response)
// and says so -- once, not every twelve hours.
func TestAutoRefresh_AVanishedSlotIsReportedOnce(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(subBody("alpha", "gamma"))
	e.tick()

	cfg := e.cfg()
	if cfg.Backup() == nil || cfg.Backup().Remark != "beta" {
		t.Fatalf("the vanished backup was dropped: %v", cfg.Backup())
	}
	msgs := e.pushed()
	var gone int
	for _, m := range msgs {
		if strings.Contains(m, "«beta» пропал из подписки") {
			gone++
		}
	}
	if gone != 1 {
		t.Fatalf("messages %q: want exactly one about beta", msgs)
	}

	e.now = e.now.Add(13 * time.Hour)
	e.tick()
	for _, m := range e.pushed() {
		if strings.Contains(m, "пропал из подписки") {
			t.Errorf("said again: %q", m)
		}
	}

	// It comes back: the wording is forgotten, so a later disappearance is news again.
	e.srv.set(subBody("alpha", "beta", "gamma"))
	e.now = e.now.Add(13 * time.Hour)
	e.tick()
	if st := e.state(); st.WarnHash != "" {
		t.Errorf("WarnHash %q after the notes went away", st.WarnHash)
	}
}

func TestAutoRefresh_FailureBacksOffRedactsAndTellsOnceAfterAnInterval(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.status.Store(http.StatusForbidden)

	start := e.now
	e.tick()
	st := e.state()
	if st.Failures != 1 || !st.FailingSince.Equal(start) {
		t.Fatalf("state after the first failure: %+v", st)
	}
	if strings.Contains(st.LastError, e.secret) || strings.Contains(strings.Join(e.logs, "\n"), e.secret) {
		t.Errorf("the subscription URL leaked: state %q, log %q", st.LastError, e.logs)
	}
	if !strings.Contains(st.LastError, "<redacted>") || !strings.Contains(st.LastError, "403") {
		t.Errorf("LastError %q should keep the host and the status", st.LastError)
	}

	// Not retried before its time ...
	e.srv.hits.Store(0)
	e.now = start.Add(5 * time.Minute)
	e.tick()
	if e.srv.hits.Load() != 0 {
		t.Error("retried before the back-off")
	}
	// ... and then on the back-off, 10 min, 30 min, 2 h, 6 h, 6 h ...
	var told []int
	for i := 0; i < 6; i++ {
		due := e.state().Due(e.cfg().Subscription.LastFetchedAt, e.now, 12*time.Hour)
		if due.After(e.now) {
			e.now = due
		}
		e.tick()
		if msgs := e.pushed(); len(msgs) > 0 {
			told = append(told, e.state().Failures)
			if !strings.Contains(msgs[0], "не обновляется уже") || strings.Contains(msgs[0], e.secret) {
				t.Errorf("message %q", msgs[0])
			}
		}
	}
	if len(told) != 1 {
		t.Fatalf("told the operator %d times (at failures %v), want once", len(told), told)
	}
	if e.now.Sub(start) < 12*time.Hour {
		t.Errorf("told after %s, before a whole interval had passed", e.now.Sub(start))
	}

	// The provider recovers: the streak ends and everything is forgotten.
	e.srv.status.Store(http.StatusOK)
	e.now = e.state().Due(e.cfg().Subscription.LastFetchedAt, e.now, 12*time.Hour)
	e.tick()
	if st := e.state(); st.Failures != 0 || st.FailNotified || st.LastError != "" {
		t.Errorf("after recovery: %+v", st)
	}
}

// A list that comes back with less than half of its profiles is not applied by
// an unattended refresh -- but the operator is told, once.
func TestAutoRefresh_AShrunkListIsHeldBack(t *testing.T) {
	e := newAutoEnv(t, subBody("a", "b", "c", "d", "e", "f"), 13*time.Hour)
	e.srv.set(subBody("placeholder"))
	e.tick()

	if got := remarks(e.cfg()); got != "a,b,c,d,e,f" {
		t.Errorf("profiles %s: the shrunk list was applied", got)
	}
	if e.reloads != 0 {
		t.Errorf("reloads = %d", e.reloads)
	}
	msgs := e.pushed()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "подписка вернула 1 профилей вместо 6") || !strings.Contains(msgs[0], "/sub_refresh") {
		t.Fatalf("messages %q", msgs)
	}
	st := e.state()
	if st.Failures != 1 || !st.FailNotified {
		t.Errorf("state %+v", st)
	}

	e.now = e.now.Add(time.Hour)
	e.tick()
	if msgs := e.pushed(); len(msgs) != 0 {
		t.Errorf("said again: %q", msgs)
	}
}

func TestAutoRefresh_ASmallListMayShrink(t *testing.T) {
	e := newAutoEnv(t, subBody("a", "b", "c"), 13*time.Hour) // under subRefreshShrinkMin
	e.srv.set(subBody("a"))
	e.tick()
	if got := remarks(e.cfg()); got != "a" {
		t.Errorf("profiles %s", got)
	}
	if e.reloads != 1 {
		t.Errorf("reloads = %d", e.reloads)
	}
}

// The fetch takes as long as the provider takes; the operator may change the
// config meanwhile. A change to what the refresh depends on aborts the attempt
// (nothing is overwritten, no failure is recorded) ...
func TestAutoRefresh_ConfigMovedDuringTheFetchIsNotClobbered(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(subBody("alpha", "beta", "gamma"))
	e.srv.onRequest = func() { // the operator picks beta as the primary
		cfg, err := config.Load(e.cfgPath) // not e.cfg(): a Fatal must not run on the server's goroutine
		if err != nil {
			t.Error(err)
			return
		}
		cfg.PrimaryIndex = 1
		cfg.Subscription.PrimaryKey = "beta"
		if err := cfg.Save(e.cfgPath); err != nil {
			t.Error(err)
		}
	}
	if wait := e.tick(); wait != time.Minute {
		t.Errorf("wait = %s, want a minute", wait)
	}
	cfg := e.cfg()
	if cfg.PrimaryIndex != 1 || cfg.Primary().Remark != "beta" {
		t.Errorf("the operator's change was overwritten: primary %v", cfg.Primary())
	}
	if remarks(cfg) != "alpha,beta" {
		t.Errorf("profiles replaced anyway: %s", remarks(cfg))
	}
	if st := e.state(); st.Failures != 0 || !st.LastAttempt.IsZero() {
		t.Errorf("a moved config is not a failed attempt: %+v", st)
	}
	if e.reloads != 0 || len(e.pushed()) != 0 {
		t.Error("nothing was applied, nothing to report")
	}
}

// ... while a change to something the refresh does not touch survives it.
func TestAutoRefresh_UnrelatedChangeDuringTheFetchIsKept(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	e.srv.set(subBody("alpha", "beta", "gamma"))
	e.srv.onRequest = func() {
		cfg, err := config.Load(e.cfgPath) // not e.cfg(): a Fatal must not run on the server's goroutine
		if err != nil {
			t.Error(err)
			return
		}
		cfg.XHTTPMode = "packet-up"
		cfg.PresetsNoAutoUpdate = true
		if err := cfg.Save(e.cfgPath); err != nil {
			t.Error(err)
		}
	}
	e.tick()
	cfg := e.cfg()
	if remarks(cfg) != "alpha,beta,gamma" {
		t.Errorf("profiles = %s", remarks(cfg))
	}
	if cfg.XHTTPMode != "packet-up" || !cfg.PresetsNoAutoUpdate {
		t.Errorf("the unrelated settings were lost: xhttp %q presets-off %v", cfg.XHTTPMode, cfg.PresetsNoAutoUpdate)
	}
}

func TestAutoRefresh_OffAndNothingToRefreshDoNotFetch(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), 13*time.Hour)
	cfg := e.cfg()
	cfg.SubscriptionNoAutoRefresh = true
	if err := cfg.Save(e.cfgPath); err != nil {
		t.Fatal(err)
	}
	if wait := e.tick(); wait != subRefreshPoll || e.srv.hits.Load() != 0 {
		t.Errorf("off: wait %s hits %d", wait, e.srv.hits.Load())
	}

	cfg.SubscriptionNoAutoRefresh = false
	cfg.Subscription = nil
	cfg.PrimarySource = &config.SlotSource{URL: "vless://11111111-1111-2222-3333-444444444444@h.example.com:443?type=tcp&security=none#pasted"}
	if err := cfg.Save(e.cfgPath); err != nil {
		t.Fatal(err)
	}
	if wait := e.tick(); wait != subRefreshPoll || e.srv.hits.Load() != 0 || !e.state().LastAttempt.IsZero() {
		t.Errorf("a pasted link has nothing to fetch: wait %s hits %d state %+v", wait, e.srv.hits.Load(), e.state())
	}
}

// With no shared subscription, only independently-sourced slots: they are
// refreshed too, and if every one fails that is a failed attempt.
func TestAutoRefresh_SlotSourcesOnly(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta"), time.Hour)
	url := e.srv.URL + "/sub/" + e.secret

	cfg := e.cfg()
	cfg.Subscription = nil
	cfg.PrimarySource = &config.SlotSource{URL: url, Selector: "alpha"}
	cfg.BackupSource = &config.SlotSource{URL: url, Selector: "beta"}
	if err := cfg.Save(e.cfgPath); err != nil {
		t.Fatal(err)
	}
	e.srv.hits.Store(0)

	e.tick() // no state at all: due now
	if e.srv.hits.Load() == 0 {
		t.Fatal("slot sources were not fetched")
	}
	if st := e.state(); st.Failures != 0 || st.LastSuccess.IsZero() {
		t.Errorf("state %+v", st)
	}
	if cfg := e.cfg(); cfg.PrimarySource.ImportKey == "" {
		t.Error("the anchor was not recorded")
	}

	e.srv.status.Store(http.StatusInternalServerError)
	e.now = e.now.Add(13 * time.Hour)
	e.tick()
	st := e.state()
	if st.Failures != 1 || strings.Contains(st.LastError, e.secret) || !strings.Contains(st.LastError, "источник") {
		t.Errorf("every source failed: %+v", st)
	}
}

func TestDescribeChange(t *testing.T) {
	// The primary is always "a" and the backup "b" when they are there, wherever
	// the provider lists them.
	view := func(names ...string) refreshView {
		cfg := config.Default()
		for i, n := range names {
			cfg.Profiles = append(cfg.Profiles, config.Profile{Remark: n, Address: n + ".example.com", Port: 443, UUID: "u-" + n})
			switch n {
			case "a":
				cfg.PrimaryIndex = i
			case "b":
				cfg.BackupIndex = i
			}
		}
		return takeView(cfg)
	}

	if got := describeChange(view("a", "b"), view("a", "b")); got != nil {
		t.Errorf("no change: %q", got)
	}
	if got := describeChange(view("a", "b", "c"), view("c", "b", "a")); got != nil {
		t.Errorf("reorder: %q", got)
	}

	got := strings.Join(describeChange(view("a", "b", "c"), view("a", "x", "c", "y")), "\n")
	for _, want := range []string{"4 профилей", "+ x, y", "− b", "резервный: b → —"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q not in:\n%s", want, got)
		}
	}

	// The same servers under the same names, with other settings behind them.
	rotated := config.Default()
	for i, n := range []string{"a", "b"} {
		rotated.Profiles = append(rotated.Profiles, config.Profile{Remark: n, Address: n + ".example.com", Port: 443, UUID: "rotated-" + n})
		if n == "a" {
			rotated.PrimaryIndex = i
		} else {
			rotated.BackupIndex = i
		}
	}
	got = strings.Join(describeChange(view("a", "b"), takeView(rotated)), "\n")
	if !strings.Contains(got, "~ параметры изменились: a, b") || !strings.Contains(got, "резервный (b): параметры сервера изменились") || !strings.Contains(got, "основной (a): параметры сервера изменились") {
		t.Errorf("changed in place:\n%s", got)
	}

	// A long list is cut.
	var many []string
	for i := 0; i < 9; i++ {
		many = append(many, fmt.Sprintf("n%d", i))
	}
	if got := strings.Join(describeChange(view("a"), view(append([]string{"a"}, many...)...)), "\n"); !strings.Contains(got, "и ещё 4") {
		t.Errorf("long list not shortened:\n%s", got)
	}
}

func TestSubscriptionAutoRefreshLoop_StopsWithItsContext(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		subscriptionAutoRefreshLoop(ctx, func(string, ...any) {}, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
}

func TestCmdSubscriptionAuto(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	t.Setenv("KEENETIC_XRAY_SUB_REFRESH_STATE", filepath.Join(filepath.Dir(path), "state.json"))

	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: "https://p.example/s", LastFetchedAt: time.Now().Add(-2 * time.Hour)}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		if err := run([]string{"subscription", "auto"}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "каждые 12 ч") || !strings.Contains(out, "последнее — 2 ч назад") {
		t.Errorf("status: %q", out)
	}

	out = captureStdout(t, func() {
		if err := run([]string{"subscription", "auto", "6"}); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "каждые 6 ч") || !strings.Contains(out, "сохранено") {
		t.Errorf("set 6: %q", out)
	}
	if got, _ := config.Load(path); got.SubscriptionRefreshHours != 6 {
		t.Errorf("hours = %d", got.SubscriptionRefreshHours)
	}

	out = captureStdout(t, func() { _ = run([]string{"subscription", "auto", "off"}) })
	if !strings.Contains(out, "выключено") {
		t.Errorf("off: %q", out)
	}
	if got, _ := config.Load(path); !got.SubscriptionNoAutoRefresh {
		t.Error("not switched off")
	}
	_ = captureStdout(t, func() { _ = run([]string{"subscription", "auto", "on"}) })
	if got, _ := config.Load(path); got.SubscriptionNoAutoRefresh || got.SubscriptionRefreshHours != 6 {
		t.Errorf("on: %+v", got)
	}

	if err := run([]string{"subscription", "auto", "often"}); err == nil {
		t.Error("a nonsense interval was accepted")
	}
	if err := run([]string{"subscription", "auto", "6", "7"}); err == nil {
		t.Error("extra arguments were accepted")
	}
}

// adoptRefresh and refreshInputs hard-code the fields RefreshConfig owns. If it
// ever starts writing another one, the transplant would silently drop it: this
// fails first.
func TestRefreshConfig_OnlyTouchesTheFieldsTheAutoRefreshTransplants(t *testing.T) {
	e := newAutoEnv(t, subBody("alpha", "beta", "gamma"), 13*time.Hour)
	cfg := e.cfg()
	cfg.PrimarySource = &config.SlotSource{URL: e.srv.URL + "/sub/x", Selector: "gamma"}
	cfg.XHTTPMode = "packet-up"
	cfg.PresetsNoAutoUpdate = true
	cfg.SubscriptionRefreshHours = 6
	e.srv.set(subBody("alpha", "gamma", "delta"))

	top := func(c *config.Config) map[string]string {
		var m map[string]json.RawMessage
		b, _ := json.Marshal(c)
		_ = json.Unmarshal(b, &m)
		out := map[string]string{}
		for k, v := range m {
			out[k] = string(v)
		}
		return out
	}
	before := top(cfg)
	if _, err := subscription.RefreshConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	owned := map[string]bool{"profiles": true, "primary_index": true, "backup_index": true, "subscription": true, "primary_source": true, "backup_source": true}
	for k, v := range top(cfg) {
		if before[k] != v && !owned[k] {
			t.Errorf("RefreshConfig changed %q, which adoptRefresh does not carry over", k)
		}
	}
}
