package botcontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/updatecheck"
)

func TestAgentVersionFromStatus(t *testing.T) {
	cases := []struct {
		name, status, want string
	}{
		{"typical", "agent: v0.29.3 (abc1234)\nvariant: full\nfailover: ACTIVE_PRIMARY\n", "v0.29.3"},
		{"only line", "agent: v0.29.3 (abc1234)", "v0.29.3"},
		{"empty", "", ""},
		{"no commit suffix", "agent: v0.29.3\n", "v0.29.3"},
		{"unrelated first line", "variant: full\nagent: v0.29.3 (abc1234)\n", ""}, // must be the *first* line
		{"garbage", "not a status blob at all", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := agentVersionFromStatus(c.status); got != c.want {
				t.Errorf("agentVersionFromStatus(%q) = %q, want %q", c.status, got, c.want)
			}
		})
	}
}

func TestAppUpdateWatcher_Consider_NotifiesOnceThenStaysQuiet(t *testing.T) {
	var calls [][3]string
	w := &AppUpdateWatcher{Notify: func(subject, from, to string) { calls = append(calls, [3]string{subject, from, to}) }}
	w.notified = map[string]string{}

	w.consider("", "v0.29.0", "v0.29.3")
	w.consider("", "v0.29.0", "v0.29.3") // same target again -- must not repeat
	if len(calls) != 1 {
		t.Fatalf("Notify called %d times, want 1: %v", len(calls), calls)
	}
	if calls[0] != [3]string{"", "v0.29.0", "v0.29.3"} {
		t.Errorf("Notify args = %v, want [\"\" v0.29.0 v0.29.3]", calls[0])
	}
}

func TestAppUpdateWatcher_Consider_RenotifiesOnANewerTarget(t *testing.T) {
	var calls int
	w := &AppUpdateWatcher{Notify: func(string, string, string) { calls++ }}
	w.notified = map[string]string{}

	w.consider("r1", "v0.29.0", "v0.29.3")
	w.consider("r1", "v0.29.0", "v0.29.4") // a newer release supersedes what was already announced
	if calls != 2 {
		t.Errorf("Notify called %d times, want 2 (a newer target should re-announce)", calls)
	}
}

func TestAppUpdateWatcher_Consider_SkipsWhenNotBehind(t *testing.T) {
	var calls int
	w := &AppUpdateWatcher{Notify: func(string, string, string) { calls++ }}
	w.notified = map[string]string{}

	w.consider("", "v0.29.3", "v0.29.3") // already current
	w.consider("", "v0.30.0", "v0.29.3") // ahead (dev/dirty build) -- nothing to say
	if calls != 0 {
		t.Errorf("Notify called %d times, want 0", calls)
	}
}

func TestAppUpdateWatcher_Consider_TracksSubjectsIndependently(t *testing.T) {
	var calls []string
	w := &AppUpdateWatcher{Notify: func(subject, _, _ string) { calls = append(calls, subject) }}
	w.notified = map[string]string{}

	w.consider("", "v0.29.0", "v0.29.3")   // server
	w.consider("r1", "v0.29.0", "v0.29.3") // router r1, same target version
	if len(calls) != 2 {
		t.Fatalf("Notify called %d times, want 2 (distinct subjects)", len(calls))
	}
}

// fakeAppReleaseServer serves a GitHub-releases-shaped response naming a
// single app release, for AppUpdateWatcher.check's HTTP path.
func fakeAppReleaseServer(t *testing.T, latestTag string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"tag_name":"` + latestTag + `","draft":false}]`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestAppUpdateWatcher_Check_NotifiesServerAndOutdatedRouter(t *testing.T) {
	store := newBotStore(t)
	mustRegister(t, store, "r-old")
	mustRegister(t, store, "r-current")
	mustRegister(t, store, "r-never-polled")
	if err := store.SetStatus("r-old", "agent: v0.29.0 (aaa)\nvariant: full\n"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetStatus("r-current", "agent: v0.29.3 (bbb)\nvariant: full\n"); err != nil {
		t.Fatal(err)
	}
	// r-never-polled has no heartbeat at all -- LastStatus is "".

	checker := &updatecheck.Checker{BaseURL: fakeAppReleaseServer(t, "v0.29.3")}
	var calls []struct{ subject, from, to string }
	w := &AppUpdateWatcher{
		Store:          store,
		Checker:        checker,
		CurrentVersion: "v0.29.0",
		Notify: func(subject, from, to string) {
			calls = append(calls, struct{ subject, from, to string }{subject, from, to})
		},
	}
	w.notified = map[string]string{}

	w.check(context.Background())

	got := map[string]bool{}
	for _, c := range calls {
		if c.to != "v0.29.3" {
			t.Errorf("notify(%q) target = %q, want v0.29.3", c.subject, c.to)
		}
		got[c.subject] = true
	}
	if !got[""] {
		t.Error("expected a notification for the server itself (subject \"\")")
	}
	if !got["r-old"] {
		t.Error("expected a notification for r-old (agent v0.29.0 < latest v0.29.3)")
	}
	if got["r-current"] {
		t.Error("r-current is already on latest -- should not have been notified")
	}
	if got["r-never-polled"] {
		t.Error("a router with no heartbeat yet should not be notified about")
	}
}

func TestAppUpdateWatcher_Check_NothingOutdatedNotifiesNothing(t *testing.T) {
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	if err := store.SetStatus("r1", "agent: v0.29.3 (bbb)\n"); err != nil {
		t.Fatal(err)
	}

	checker := &updatecheck.Checker{BaseURL: fakeAppReleaseServer(t, "v0.29.3")}
	notified := false
	w := &AppUpdateWatcher{
		Store: store, Checker: checker, CurrentVersion: "v0.29.3",
		Notify: func(string, string, string) { notified = true },
	}
	w.notified = map[string]string{}
	w.check(context.Background())

	if notified {
		t.Error("everything already current -- Notify should not have been called")
	}
}

func TestAppUpdateWatcher_Check_CheckerFailureIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	store := newBotStore(t)
	notified := false
	w := &AppUpdateWatcher{
		Store:          store,
		Checker:        &updatecheck.Checker{BaseURL: srv.URL},
		CurrentVersion: "v0.1.0",
		Notify:         func(string, string, string) { notified = true },
	}
	w.notified = map[string]string{}
	w.check(context.Background()) // must not panic

	if notified {
		t.Error("a failed release check must not fabricate a notification")
	}
}
