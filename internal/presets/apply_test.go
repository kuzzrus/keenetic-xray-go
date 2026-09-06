package presets

import (
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestApplyBindsDomainAndCIDR(t *testing.T) {
	cfg := &config.Config{}
	touched, err := Apply(cfg, "youtube", true, "Wireguard4", true)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(touched) != 2 {
		t.Fatalf("touched = %v, want [youtube youtube-ip]", touched)
	}
	dom := BoundList(cfg, "youtube")
	ip := BoundList(cfg, "youtube-ip")
	if dom == nil || ip == nil {
		t.Fatalf("lists not created: %+v", cfg.Routing.Lists)
	}
	if dom.Preset != "youtube" || dom.PresetRev == "" {
		t.Errorf("domain list not stamped: %+v", *dom)
	}
	if dom.Interface != "Wireguard4" || !dom.Exclusive {
		t.Errorf("modifiers not applied to domain list: %+v", *dom)
	}
	if ip.Interface == "Wireguard4" {
		t.Errorf("modifiers leaked onto the -ip list: %+v", *ip)
	}
	wantDom, _ := Entries("youtube")
	if len(dom.Entries) != len(wantDom) {
		t.Errorf("domain entries = %d, preset has %d", len(dom.Entries), len(wantDom))
	}

	// Re-apply is idempotent (a managed list, overwritten wholesale).
	if _, err := Apply(cfg, "youtube", true, "", false); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if n := len(cfg.Routing.Lists); n != 2 {
		t.Errorf("re-Apply created extra lists: %d", n)
	}
}

func TestApplyRefusesManualCollision(t *testing.T) {
	cfg := &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "reddit", Entries: []string{"reddit.com"}}, // hand-made, no Preset
	}}}
	if _, err := Apply(cfg, "reddit", false, "", false); err == nil {
		t.Fatal("expected Apply to refuse overwriting a hand-made list")
	}
}

func TestApplyUnknownAndBadIface(t *testing.T) {
	cfg := &config.Config{}
	if _, err := Apply(cfg, "nope", false, "", false); err == nil {
		t.Error("unknown preset should error")
	}
	if _, err := Apply(cfg, "youtube", false, "NotAnIface", false); err == nil {
		t.Error("bad interface should error")
	}
}

func TestDriftAndSync(t *testing.T) {
	cfg := &config.Config{}
	if _, err := Apply(cfg, "reddit", false, "", false); err != nil {
		t.Fatal(err)
	}
	l := BoundList(cfg, "reddit")

	if a, r, _, bound := Drift(*l); !bound || a != 0 || r != 0 {
		t.Fatalf("fresh apply should have no drift: a=%d r=%d bound=%v", a, r, bound)
	}

	// Simulate an older build / user edit: drop two, add a stray.
	l.Entries = append(l.Entries[:len(l.Entries)-2], "totally-made-up-domain.example")
	a, r, _, bound := Drift(*l)
	if !bound || a != 2 || r != 1 {
		t.Fatalf("Drift = +%d -%d bound=%v, want +2 -1", a, r, bound)
	}

	res, err := Sync(cfg, "reddit")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if len(res) != 1 || res[0].Added != 2 || res[0].Removed != 1 {
		t.Fatalf("Sync result = %+v, want +2 -1", res)
	}
	if a, r, _, _ := Drift(*BoundList(cfg, "reddit")); a != 0 || r != 0 {
		t.Errorf("after Sync still drifting: +%d -%d", a, r)
	}
}

func TestDriftUnboundList(t *testing.T) {
	l := config.RouteList{Name: "x", Entries: []string{"a.com"}}
	if _, _, _, bound := Drift(l); bound {
		t.Error("a list with no Preset must report bound=false")
	}
}

func TestSyncAllAndMissing(t *testing.T) {
	cfg := &config.Config{}
	if _, err := Sync(cfg, ""); err != nil {
		t.Errorf("Sync(all) on empty config should be a no-op, got %v", err)
	}
	if _, err := Sync(cfg, "youtube"); err == nil {
		t.Error("Sync of a non-applied preset should error")
	}
}
