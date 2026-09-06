package botcontrol

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func presetTestHandler(t *testing.T) *RouterHandler {
	t.Helper()
	return &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
}

func TestRoutesPresetList_Shape(t *testing.T) {
	h := presetTestHandler(t)
	out := h.routesPresetList()
	lines := strings.Split(out, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected #gen + #cats + rows, got:\n%s", out)
	}
	if !strings.HasPrefix(lines[0], "#gen\t") {
		t.Errorf("line 0 = %q, want #gen", lines[0])
	}
	if !strings.HasPrefix(lines[1], "#cats\t") || len(strings.Split(lines[1], "\t")) < 3 {
		t.Errorf("line 1 = %q, want #cats with entries", lines[1])
	}
	sawYouTube := false
	for _, ln := range lines[2:] {
		f := strings.Split(ln, "\t")
		if len(f) != 9 {
			t.Fatalf("row %q has %d fields, want 9", ln, len(f))
		}
		if f[0] == "youtube" {
			sawYouTube = true
			if f[4] != "domains" || f[6] != "0" {
				t.Errorf("fresh youtube row unexpected: %q", ln)
			}
		}
	}
	if !sawYouTube {
		t.Error("no youtube row in preset list")
	}
}

func TestRoutesPresetAdd_BindsAndStamps(t *testing.T) {
	h := presetTestHandler(t)
	ctx := context.Background()

	if _, err := h.routesPresetAdd(ctx, []string{"youtube", "ip"}); err != nil {
		t.Fatalf("routesPresetAdd: %v", err)
	}
	var dom, ip *config.RouteList
	for i := range h.Config.Routing.Lists {
		switch h.Config.Routing.Lists[i].Name {
		case "youtube":
			dom = &h.Config.Routing.Lists[i]
		case "youtube-ip":
			ip = &h.Config.Routing.Lists[i]
		}
	}
	if dom == nil || ip == nil {
		t.Fatalf("expected youtube + youtube-ip lists, got %+v", h.Config.Routing.Lists)
	}
	if dom.Preset != "youtube" || dom.PresetRev == "" || len(dom.Entries) == 0 {
		t.Errorf("domain list not stamped: %+v", *dom)
	}
	if ip.Preset != "youtube-ip" || len(ip.Entries) == 0 {
		t.Errorf("ip list not stamped: %+v", *ip)
	}

	// Fresh add -> no drift -> sync reports nothing to do.
	out, err := h.routesPresetSync(ctx, []string{"youtube"})
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !strings.Contains(out, "актуально") {
		t.Errorf("sync of a just-added preset should be a no-op, got: %q", out)
	}
}

func TestRoutesPresetAdd_RefusesManualCollision(t *testing.T) {
	h := presetTestHandler(t)
	h.Config.Routing.Lists = []config.RouteList{{Name: "youtube", Entries: []string{"example.com"}}}
	if _, err := h.routesPresetAdd(context.Background(), []string{"youtube"}); err == nil {
		t.Fatal("expected an error adding a preset over a hand-made list of the same name")
	}
}

func TestRoutesPresetAdd_UnknownPreset(t *testing.T) {
	h := presetTestHandler(t)
	if _, err := h.routesPresetAdd(context.Background(), []string{"not-a-real-preset"}); err == nil {
		t.Fatal("expected an error for an unknown preset")
	}
}

func TestParsePresetList(t *testing.T) {
	tsv := strings.Join([]string{
		"#gen\t2026-09-07",
		"#cats\tВидео\tСоцсети",
		"youtube\tyoutube\tYouTube\tВидео\tdomains\t173\t1\t3\t1",
		"youtube-ip\tyoutube\tYouTube\tВидео\tcidr\t97\t0\t0\t0",
		"reddit\treddit\tReddit\tСоцсети\tdomains\t12\t0\t0\t0",
	}, "\n")
	pm := parsePresetList(tsv)
	if pm.generated != "2026-09-07" {
		t.Errorf("generated = %q", pm.generated)
	}
	if len(pm.cats) != 2 || pm.cats[0] != "Видео" {
		t.Errorf("cats = %v", pm.cats)
	}
	if len(pm.items) != 3 {
		t.Fatalf("items = %d, want 3", len(pm.items))
	}
	yt := pm.items[0]
	if yt.name != "youtube" || !yt.installed || yt.driftAdd != 3 || yt.driftRemove != 1 || yt.count != 173 {
		t.Errorf("youtube parsed wrong: %+v", yt)
	}
	if !pm.hasCompanion("youtube") || pm.hasCompanion("reddit") {
		t.Errorf("hasCompanion wrong")
	}
	vid := pm.domainItemsInCategory("Видео")
	if len(vid) != 1 || vid[0].item.name != "youtube" {
		t.Errorf("domainItemsInCategory(Видео) = %+v", vid)
	}
	if pm.catIndex("Соцсети") != 1 {
		t.Errorf("catIndex(Соцсети) = %d", pm.catIndex("Соцсети"))
	}
}
