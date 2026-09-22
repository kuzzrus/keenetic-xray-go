package botcontrol

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidRouterID(t *testing.T) {
	// exactly maxRouterIDLen (32) valid characters -- the boundary
	// itself must still be accepted.
	atLimit := strings.Repeat("a", maxRouterIDLen)
	// BOT-04: one character over the limit -- combined with the longest
	// composite callback_data prefix this project builds
	// ("adnx:"+id+":"+addonID+":router-dns=off", 30 fixed bytes), a
	// router ID this long already only just fits; one more character
	// pushes some composite callback over Telegram's 64-byte limit.
	overLimit := strings.Repeat("a", maxRouterIDLen+1)

	ok := []string{"home", "home-router", "office_2", "R2D2", "a", atLimit}
	bad := []string{"", "has space", "точка", "sla/sh", "semi;colon", "a:b", overLimit, string(make([]byte, 65))}
	for _, id := range ok {
		if !ValidRouterID(id) {
			t.Errorf("ValidRouterID(%q) = false, want true", id)
		}
	}
	for _, id := range bad {
		if ValidRouterID(id) {
			t.Errorf("ValidRouterID(%q) = true, want false", id)
		}
	}
}

func TestStore_AddRouter_TokenAuthAndListing(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}

	tok, err := s.AddRouter("home", "Дом")
	if err != nil {
		t.Fatalf("AddRouter: %v", err)
	}
	if len(tok) != 64 {
		t.Errorf("token = %q, want 64 hex chars", tok)
	}
	if !s.HasRouter("home") {
		t.Error("HasRouter(home) = false after AddRouter")
	}

	got, ok := s.TokenFor("home")
	if !ok || got != tok {
		t.Errorf("TokenFor(home) = (%q, %v), want (%q, true)", got, ok, tok)
	}
	if _, ok := s.TokenFor("nope"); ok {
		t.Error("TokenFor(nope) = ok, want not ok")
	}

	if _, err := s.AddRouter("home", ""); err == nil {
		t.Error("AddRouter on an existing id: want error")
	}
	if _, err := s.AddRouter("bad id", ""); err == nil {
		t.Error("AddRouter with an invalid id: want error")
	}

	tok2, err := s.AddRouter("office", "")
	if err != nil {
		t.Fatalf("AddRouter office: %v", err)
	}
	if tok2 == tok {
		t.Error("two routers got the same token")
	}

	routers := s.Routers()
	if len(routers) != 2 || routers[0].ID != "home" || routers[1].ID != "office" {
		t.Fatalf("Routers() = %+v, want [home office] sorted", routers)
	}
	if routers[0].Name != "Дом" {
		t.Errorf("Routers()[0].Name = %q, want %q", routers[0].Name, "Дом")
	}
}

func TestStore_RemoveRouter(t *testing.T) {
	s, _ := LoadStore("")
	if _, err := s.AddRouter("home", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue("home", "status", nil); err != nil {
		t.Fatal(err)
	}

	if err := s.RemoveRouter("home"); err != nil {
		t.Fatalf("RemoveRouter: %v", err)
	}
	if s.HasRouter("home") {
		t.Error("HasRouter(home) = true after RemoveRouter")
	}
	if _, ok := s.TokenFor("home"); ok {
		t.Error("TokenFor(home) still resolves after RemoveRouter")
	}
	if n := s.PendingCount("home"); n != 0 {
		t.Errorf("PendingCount(home) = %d after RemoveRouter, want 0", n)
	}
	if err := s.RemoveRouter("home"); err == nil {
		t.Error("RemoveRouter on an unknown id: want error")
	}
}

func TestStore_RenameRouter(t *testing.T) {
	s, _ := LoadStore("")
	if _, err := s.AddRouter("home", "Old"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameRouter("home", "Дом"); err != nil {
		t.Fatalf("RenameRouter: %v", err)
	}
	if got := s.NameFor("home"); got != "Дом" {
		t.Errorf("NameFor(home) = %q, want Дом", got)
	}
	if err := s.RenameRouter("nope", "x"); err == nil {
		t.Error("RenameRouter on an unknown id: want error")
	}
}

func TestStore_SeedRouter_IsIdempotent(t *testing.T) {
	s, _ := LoadStore("")
	if err := s.SeedRouter("home", "seed-token", "seeded"); err != nil {
		t.Fatalf("SeedRouter: %v", err)
	}
	// A second seed (e.g. another startup) must not clobber a token the
	// bot may have rotated in the meantime.
	if err := s.SeedRouter("home", "different-token", "other"); err != nil {
		t.Fatalf("SeedRouter (again): %v", err)
	}
	got, _ := s.TokenFor("home")
	if got != "seed-token" {
		t.Errorf("TokenFor(home) = %q, want the first seed to win", got)
	}
	if err := s.SeedRouter("home", "", ""); err == nil {
		t.Error("SeedRouter with an empty token: want error")
	}
}

// TestStore_SeedRoutersFromConfig_RemovalSurvivesRestart is BOT-03's
// regression test: config.json's routers map used to be re-seeded via a
// plain per-ID SeedRouter call on every startup, so a router removed via
// the bot's /remove_router came right back as long as config.json still
// listed it -- SeedRouter can't tell "never seen" apart from
// "deliberately removed," both just look like "not currently in the
// registry." SeedRoutersFromConfig must only ever do this once per store
// file, across a real reload from disk (a fresh process, not just a
// second in-memory call).
func TestStore_SeedRoutersFromConfig_RemovalSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	cfgRouters := map[string]string{"home": "config-token", "cabin": "cabin-token"}

	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if err := s.SeedRoutersFromConfig(cfgRouters); err != nil {
		t.Fatalf("SeedRoutersFromConfig (first): %v", err)
	}
	if !s.HasRouter("home") || !s.HasRouter("cabin") {
		t.Fatalf("first seed didn't register both routers: %+v", s.Routers())
	}

	if err := s.RemoveRouter("home"); err != nil {
		t.Fatalf("RemoveRouter: %v", err)
	}

	// Simulate a real control-server restart: reload the store from disk
	// (a fresh Store value, not the same in-memory one) and re-run the
	// exact same startup seeding call with the exact same config.json
	// content -- config.json is never edited by removing a router via
	// the bot, so this is the realistic repro, not a contrived one.
	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore (reload): %v", err)
	}
	if err := reloaded.SeedRoutersFromConfig(cfgRouters); err != nil {
		t.Fatalf("SeedRoutersFromConfig (after restart): %v", err)
	}

	if reloaded.HasRouter("home") {
		t.Error("removed router came back after a restart -- SeedRoutersFromConfig re-seeded from config.json")
	}
	if !reloaded.HasRouter("cabin") {
		t.Error("untouched router lost across restart")
	}
}

// TestStore_SeedRoutersFromConfig_FirstRunSeedsEverything confirms the
// happy path the once-only guard must not break: a genuinely fresh store
// (nothing ever seeded) still picks up every router config.json lists.
func TestStore_SeedRoutersFromConfig_FirstRunSeedsEverything(t *testing.T) {
	s, _ := LoadStore("")
	if err := s.SeedRoutersFromConfig(map[string]string{"home": "t1", "cabin": "t2"}); err != nil {
		t.Fatalf("SeedRoutersFromConfig: %v", err)
	}
	if !s.HasRouter("home") || !s.HasRouter("cabin") {
		t.Errorf("first-run seed missing routers: %+v", s.Routers())
	}
}

func TestStore_RegistryPersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.json")
	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	tok, err := s.AddRouter("home", "Дом")
	if err != nil {
		t.Fatalf("AddRouter: %v", err)
	}

	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore (reload): %v", err)
	}
	got, ok := reloaded.TokenFor("home")
	if !ok || got != tok {
		t.Errorf("after reload TokenFor(home) = (%q, %v), want (%q, true)", got, ok, tok)
	}
	if routers := reloaded.Routers(); len(routers) != 1 || routers[0].Name != "Дом" {
		t.Errorf("after reload Routers() = %+v", routers)
	}
}
