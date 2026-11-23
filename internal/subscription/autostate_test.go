package subscription

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

var t0 = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func TestRefreshState_Due(t *testing.T) {
	const iv = 12 * time.Hour
	h := func(n float64) time.Duration { return time.Duration(n * float64(time.Hour)) }
	cases := []struct {
		name    string
		st      RefreshState
		fetched time.Time
		want    time.Time
	}{
		{"never refreshed: now", RefreshState{}, time.Time{}, t0},
		{"anchored on LastFetchedAt", RefreshState{}, t0.Add(-h(5)), t0.Add(h(7))},
		{"anchored on the last success when it is later", RefreshState{LastSuccess: t0.Add(-h(2))}, t0.Add(-h(5)), t0.Add(h(10))},
		{"a manual refresh (later LastFetchedAt) pushes it back", RefreshState{LastSuccess: t0.Add(-h(11))}, t0.Add(-h(1)), t0.Add(h(11))},
		{"overdue stays in the past", RefreshState{}, t0.Add(-h(30)), t0.Add(-h(18))},
		{"a timestamp from the future counts as unknown", RefreshState{LastSuccess: t0.Add(h(40))}, t0.Add(h(40)), t0},

		{"first failure: retry in 10 min", RefreshState{LastSuccess: t0.Add(-h(13)), LastAttempt: t0.Add(-h(0.01)), Failures: 1}, t0.Add(-h(13)), t0.Add(-h(0.01) + 10*time.Minute)},
		{"third failure: 2 h", RefreshState{LastSuccess: t0.Add(-h(20)), LastAttempt: t0, Failures: 3}, time.Time{}, t0.Add(2 * time.Hour)},
		{"the back-off settles at six hours", RefreshState{LastAttempt: t0, Failures: 9}, time.Time{}, t0.Add(6 * time.Hour)},
		{"failures but never a success", RefreshState{LastAttempt: t0, Failures: 1}, time.Time{}, t0.Add(10 * time.Minute)},
		{"a success after the failed attempt ends the streak", RefreshState{LastAttempt: t0.Add(-h(3)), Failures: 4}, t0.Add(-h(1)), t0.Add(h(11))},
		{"an attempt stamped in the future is ignored", RefreshState{LastAttempt: t0.Add(h(9)), Failures: 2}, t0.Add(-h(1)), t0.Add(h(11))},
	}
	for i, c := range cases {
		if got := c.st.Due(c.fetched, t0, iv); !got.Equal(c.want) {
			t.Errorf("%d %s: Due = %s, want %s", i, c.name, got.Sub(t0), c.want.Sub(t0))
		}
	}

	// A back-off longer than the interval is cut to the interval.
	stuck := RefreshState{LastAttempt: t0, Failures: 9}
	if got := stuck.Due(time.Time{}, t0, time.Hour); !got.Equal(t0.Add(time.Hour)) {
		t.Errorf("one-hour interval, nine failures: Due = %s, want 1h", got.Sub(t0))
	}
}

func TestRetryDelay(t *testing.T) {
	want := []time.Duration{10 * time.Minute, 10 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour, 6 * time.Hour}
	for failures, w := range want {
		if got := RetryDelay(failures); got != w {
			t.Errorf("RetryDelay(%d) = %s, want %s", failures, got, w)
		}
	}
}

func TestRefreshState_Notes(t *testing.T) {
	var s RefreshState
	s.WarnHash = "w1"
	s.NoteFailure(t0, "boom")
	s.NoteFailure(t0.Add(time.Hour), "boom again")
	if s.Failures != 2 || !s.FailingSince.Equal(t0) || s.LastError != "boom again" || !s.LastAttempt.Equal(t0.Add(time.Hour)) {
		t.Errorf("after two failures: %+v", s)
	}
	if s.WarnHash != "w1" {
		t.Error("a failure forgot the last slot note")
	}

	s.NoteSuccess(t0.Add(2 * time.Hour))
	if s.Failures != 0 || !s.FailingSince.IsZero() || s.LastError != "" || s.FailNotified || !s.LastSuccess.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("a success did not end the streak: %+v", s)
	}
	if s.WarnHash != "w1" {
		t.Error("a success forgot the last slot note")
	}

	// A new streak starts clean even if the old one had been announced.
	s.FailNotified = true
	s.NoteFailure(t0.Add(3*time.Hour), "x")
	s.NoteSuccess(t0.Add(4 * time.Hour))
	s.NoteFailure(t0.Add(5*time.Hour), "y")
	if s.FailNotified || !s.FailingSince.Equal(t0.Add(5*time.Hour)) {
		t.Errorf("new streak: %+v", s)
	}
}

func TestRefreshState_FailureOverdue(t *testing.T) {
	const iv = 12 * time.Hour
	var s RefreshState
	if s.FailureOverdue(t0, iv) {
		t.Error("no failures: not overdue")
	}
	s.NoteFailure(t0, "e")
	if s.FailureOverdue(t0.Add(iv-time.Minute), iv) {
		t.Error("failing for less than an interval: not yet")
	}
	if !s.FailureOverdue(t0.Add(iv), iv) {
		t.Error("failing for a whole interval: overdue")
	}
	s.FailNotified = true
	if s.FailureOverdue(t0.Add(3*iv), iv) {
		t.Error("said once, not again")
	}
}

func TestRefreshState_SaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "state.json") // the directory does not exist yet
	if got := LoadRefreshState(path); got != (RefreshState{}) {
		t.Errorf("missing file: %+v, want the zero state", got)
	}
	want := RefreshState{LastAttempt: t0, LastSuccess: t0.Add(-time.Hour), Failures: 2, FailingSince: t0, LastError: "e", FailNotified: true, WarnHash: "h"}
	if err := SaveRefreshState(path, want); err != nil {
		t.Fatal(err)
	}
	got := LoadRefreshState(path)
	if !got.LastAttempt.Equal(want.LastAttempt) || got.Failures != 2 || got.LastError != "e" || !got.FailNotified || got.WarnHash != "h" || !got.LastSuccess.Equal(want.LastSuccess) {
		t.Errorf("round trip: %+v", got)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".subscription-refresh-*")); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LoadRefreshState(path); got != (RefreshState{}) {
		t.Errorf("garbage file: %+v, want the zero state", got)
	}
}

func TestAutoStatus(t *testing.T) {
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: "https://p.example/s", LastFetchedAt: t0.Add(-5 * time.Hour)}

	got := AutoStatus(cfg, RefreshState{}, t0, true)
	for _, want := range []string{"каждые 12 ч", "последнее — 5 ч назад", "следующее через 7 ч"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q not in %q", want, got)
		}
	}
	if got := AutoStatus(cfg, RefreshState{}, t0, false); strings.Contains(got, "последнее") {
		t.Errorf("withLast=false still says when it last happened: %q", got)
	}

	cfg.SubscriptionRefreshHours = 6
	cfg.Subscription.LastFetchedAt = t0.Add(-7 * time.Hour) // older than the interval: overdue
	if got := AutoStatus(cfg, RefreshState{}, t0, true); !strings.Contains(got, "каждые 6 ч") || !strings.Contains(got, "следующее — с минуты на минуту") {
		t.Errorf("6 h, overdue: %q", got)
	}

	failing := RefreshState{LastAttempt: t0.Add(-time.Minute), Failures: 3, LastError: "таймаут"}
	if got := AutoStatus(cfg, failing, t0, true); !strings.Contains(got, "не удалась (подряд: 3): таймаут") {
		t.Errorf("failing: %q", got)
	}

	cfg.SubscriptionNoAutoRefresh = true
	if got := AutoStatus(cfg, RefreshState{}, t0, true); got != "автообновление подписки: выключено" {
		t.Errorf("off: %q", got)
	}

	bare := config.Default()
	if got := AutoStatus(bare, RefreshState{}, t0, true); !strings.Contains(got, "обновлять нечего") {
		t.Errorf("no subscription: %q", got)
	}
}

func TestLastRefresh(t *testing.T) {
	cfg := config.Default()
	if !LastRefresh(cfg, RefreshState{}).IsZero() {
		t.Error("never: want zero")
	}
	cfg.Subscription = &config.Subscription{URL: "u", LastFetchedAt: t0.Add(-3 * time.Hour)}
	if got := LastRefresh(cfg, RefreshState{LastSuccess: t0.Add(-time.Hour)}); !got.Equal(t0.Add(-time.Hour)) {
		t.Errorf("the later of the two: got %s", got)
	}
	if got := LastRefresh(cfg, RefreshState{LastSuccess: t0.Add(-5 * time.Hour)}); !got.Equal(t0.Add(-3 * time.Hour)) {
		t.Errorf("the later of the two: got %s", got)
	}
}

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		10 * time.Second:             "меньше минуты",
		45 * time.Minute:             "45 мин",
		time.Hour:                    "1 ч",
		12 * time.Hour:               "12 ч",
		3*time.Hour + 10*time.Minute: "3 ч 10 мин",
		7*time.Hour + 59*time.Minute + 40*time.Second: "8 ч",
	} {
		if got := HumanDuration(d); got != want {
			t.Errorf("HumanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
