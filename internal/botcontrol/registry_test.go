package botcontrol

import (
	"path/filepath"
	"testing"
)

func TestValidRouterID(t *testing.T) {
	ok := []string{"home", "home-router", "office_2", "R2D2", "a"}
	bad := []string{"", "has space", "точка", "sla/sh", "semi;colon", "a:b", string(make([]byte, 65))}
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
