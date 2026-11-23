package subscription

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestRefreshConfig_NothingToRefresh(t *testing.T) {
	_, err := RefreshConfig(context.Background(), config.Default())
	if !errors.Is(err, ErrNothingToRefresh) {
		t.Errorf("err = %v, want ErrNothingToRefresh", err)
	}
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{} // a struct without a URL is still nothing
	if _, err := RefreshConfig(context.Background(), cfg); !errors.Is(err, ErrNothingToRefresh) {
		t.Errorf("empty URL: err = %v, want ErrNothingToRefresh", err)
	}
}

func TestRefreshConfig_SharedSubscription(t *testing.T) {
	url, _ := mutableSubServer(t, nodeA+"\n"+nodeB+"\n")
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: url}

	rep, err := RefreshConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Shared || rep.Profiles != 2 || len(cfg.Profiles) != 2 || len(rep.Sources) != 0 {
		t.Errorf("report %+v, profiles %d", rep, len(cfg.Profiles))
	}
	if cfg.Subscription.LastFetchedAt.IsZero() {
		t.Error("LastFetchedAt not stamped")
	}
}

// A failed fetch of the shared subscription is an error and leaves the config
// exactly as it was -- the caller must be able to drop it or keep going.
func TestRefreshConfig_SharedFetchFailureLeavesConfigUntouched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: srv.URL}
	cfg.Profiles = []config.Profile{{Remark: "kept", Address: "k.example.com", Port: 443}}
	cfg.PrimaryIndex = 0

	if _, err := RefreshConfig(context.Background(), cfg); err == nil {
		t.Fatal("want an error")
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Remark != "kept" || cfg.PrimaryIndex != 0 || !cfg.Subscription.LastFetchedAt.IsZero() {
		t.Errorf("config touched by a failed refresh: %+v", cfg)
	}
}

func TestRefreshConfig_IndependentSlotsAreRefetchedAndAnchored(t *testing.T) {
	url, _ := mutableSubServer(t, nodeA+"\n"+nodeB+"\n")
	cfg := config.Default()
	cfg.PrimarySource = &config.SlotSource{URL: url, Selector: "Alpha"}
	cfg.BackupSource = &config.SlotSource{URL: url, Selector: "Bravo"}

	rep, err := RefreshConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Shared || len(rep.Sources) != 2 {
		t.Fatalf("report %+v", rep)
	}
	if rep.Sources[0].Slot != "primary" || rep.Sources[0].Remark != "Alpha" || rep.Sources[1].Slot != "backup" || rep.Sources[1].Remark != "Bravo" {
		t.Errorf("sources %+v", rep.Sources)
	}
	if p, b := cfg.Primary(), cfg.Backup(); p == nil || p.Remark != "Alpha" || b == nil || b.Remark != "Bravo" {
		t.Errorf("slots not pointed at their sources: %v / %v", p, b)
	}
	if cfg.PrimarySource.ImportKey == "" || cfg.BackupSource.ImportKey == "" {
		t.Error("ImportKey anchors not recorded")
	}
}

// One dead slot source does not stop the other, nor the shared subscription.
func TestRefreshConfig_ASlotSourceFailingDoesNotAbortTheRest(t *testing.T) {
	url, _ := mutableSubServer(t, nodeA+"\n"+nodeB+"\n")
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer dead.Close()
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: url}
	cfg.PrimarySource = &config.SlotSource{URL: dead.URL}
	cfg.BackupSource = &config.SlotSource{URL: url, Selector: "Bravo"}

	rep, err := RefreshConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Shared || len(rep.Sources) != 2 || rep.Sources[0].Err == nil || rep.Sources[1].Err != nil {
		t.Errorf("report %+v", rep)
	}
	if b := cfg.Backup(); b == nil || b.Remark != "Bravo" {
		t.Errorf("the healthy slot was not refreshed: %v", b)
	}
}

// RefreshConfig splits ApplyResult's warnings by position: the parser's first,
// then the notes about the slots. Both a vanished server's note and the parser's
// lines must land in the right list.
func TestRefreshConfig_SlotNotesAreSeparatedFromParseWarnings(t *testing.T) {
	url, set := mutableSubServer(t, nodeA+"\n"+nodeB+"\n")
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: url}
	if _, err := RefreshConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.Subscription.PrimaryKey, cfg.Subscription.BackupKey = "Alpha", "Bravo"

	// Alpha vanishes (Bravo stays), and the list gains a line the parser cannot use.
	set(nodeB + "\nvmess://unsupported\n" + strings.Replace(nodeB, "Bravo", "Charlie", 1) + "\n")
	rep, err := RefreshConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Warnings) < 2 {
		t.Fatalf("warnings %v: want the parse warning and a slot note", rep.Warnings)
	}
	if len(rep.SlotNotes) != 1 || !strings.Contains(rep.SlotNotes[0], "Alpha") {
		t.Errorf("SlotNotes = %v, want the one about Alpha", rep.SlotNotes)
	}
	for _, n := range rep.SlotNotes {
		if strings.Contains(n, "skipped entry") {
			t.Errorf("a parser line leaked into SlotNotes: %q", n)
		}
	}
}

func TestHasRemote(t *testing.T) {
	url := func(s string) *config.SlotSource { return &config.SlotSource{URL: s} }
	cases := []struct {
		name string
		mod  func(*config.Config)
		want bool
	}{
		{"nothing", func(*config.Config) {}, false},
		{"shared", func(c *config.Config) { c.Subscription = &config.Subscription{URL: "https://p.example/s"} }, true},
		{"shared without a URL", func(c *config.Config) { c.Subscription = &config.Subscription{} }, false},
		{"slot with a subscription URL", func(c *config.Config) { c.BackupSource = url(" https://p.example/s ") }, true},
		{"slot with plain http", func(c *config.Config) { c.PrimarySource = url("http://p.example/s") }, true},
		{"slot with a pasted link: nothing to fetch", func(c *config.Config) { c.PrimarySource = url("vless://x@h:443#r") }, false},
	}
	for _, c := range cases {
		cfg := config.Default()
		c.mod(cfg)
		if got := HasRemote(cfg); got != c.want {
			t.Errorf("%s: HasRemote = %v, want %v", c.name, got, c.want)
		}
	}
}

// A fetch error quotes the URL it failed on, and the URL carries the token.
func TestRedactURLs(t *testing.T) {
	for in, want := range map[string]string{
		`fetching https://panel.example.com/sub/SECRETTOKEN: unexpected status 403 Forbidden`: `fetching https://panel.example.com/<redacted>: unexpected status 403 Forbidden`,
		`Get "https://panel.example.com/sub/SECRETTOKEN?x=1": dial tcp: i/o timeout`:          `Get "https://panel.example.com/<redacted>": dial tcp: i/o timeout`,
		`redirected to http://cdn.example.net/a/b (SECRET).`:                                  `redirected to http://cdn.example.net/<redacted> (SECRET).`,
		`no URLs here`: `no URLs here`,
	} {
		got := RedactURLs(in)
		if got != want {
			t.Errorf("RedactURLs(%q)\n got  %q\n want %q", in, got, want)
		}
		if strings.Contains(got, "SECRETTOKEN") {
			t.Errorf("token survived in %q", got)
		}
	}
}

// A provider renaming a node is not news: the slot is matched by its connection
// fingerprint (ApplyResult says so in Warnings), but nothing in SlotNotes asks
// the operator to do anything.
func TestRefreshConfig_ARenamedServerIsNotASlotNote(t *testing.T) {
	url, set := mutableSubServer(t, nodeA+"\n"+nodeB+"\n")
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: url}
	if _, err := RefreshConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.Subscription.PrimaryKey, cfg.Subscription.BackupKey = "Alpha", "Bravo"

	set(nodeArenamed + "\n" + nodeB + "\n")
	rep, err := RefreshConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Primary(); p == nil || p.Remark != "Alpha-NEW-NAME" {
		t.Fatalf("the renamed primary was not followed: %v", p)
	}
	var renamed bool
	for _, w := range rep.Warnings {
		renamed = renamed || strings.Contains(w, renamedNote)
	}
	if !renamed {
		t.Errorf("Warnings %v: the rename should still be mentioned there", rep.Warnings)
	}
	if len(rep.SlotNotes) != 0 {
		t.Errorf("SlotNotes = %v, want none for a rename", rep.SlotNotes)
	}
}
