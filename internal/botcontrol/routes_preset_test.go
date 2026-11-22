package botcontrol

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// withCutPreset serves one preset whose list the generator cut: 3 entries held,
// 540 in the source. The package-wide overlay is process-global, hence the
// cleanup.
func withCutPreset(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	manifest := `{"version":1,"generated":"2026-11-22","categories":["Тест"],"presets":[` +
		`{"name":"acme","service":"acme","title":"Acme","category":"Тест","kind":"domains","count":3,"rev":"x","source_count":540,"sources":["s"]},` +
		`{"name":"acme-ip","service":"acme","title":"Acme","category":"Тест","kind":"cidr","count":2,"rev":"y","sources":["s"]}]}`
	for name, body := range map[string]string{"manifest.json": manifest, "acme-ip.lst": "# Acme\n\n8.8.8.0/24\n203.0.113.0/24\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	presets.SetOverlay(dir)
	t.Cleanup(func() { presets.SetOverlay("") })
}

// The count of what the upstream had travels to the bot as the last column.
func TestRoutesPresetList_CarriesTheSourceCount(t *testing.T) {
	withCutPreset(t)
	out := presetTestHandler(t).routesPresetList()
	var row string
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "acme\t") {
			row = ln
		}
	}
	if row == "" {
		t.Fatalf("no acme row in:\n%s", out)
	}
	if f := strings.Split(row, "\t"); len(f) != 11 || f[5] != "3" || f[9] != "540" {
		t.Errorf("row = %q, want count 3 and source count 540 as the 10th field", row)
	}
}

func TestParsePresetList_SourceCountAndOlderAgents(t *testing.T) {
	pm := parsePresetList(strings.Join([]string{
		"acme\tacme\tAcme\tТест\tdomains\t200\t0\t0\t0\t540", // this build of the agent
		"old\told\tOld\tТест\tdomains\t200\t0\t0\t0",         // an agent older than the column
		"fits\tfits\tFits\tТест\tdomains\t150\t0\t0\t0\t0",
	}, "\n"))
	if len(pm.items) != 3 {
		t.Fatalf("items = %d, want 3", len(pm.items))
	}
	if it := pm.items[0]; it.sourceCount != 540 || !it.capped() || it.countText() != "200 из 540" {
		t.Errorf("cut preset parsed as %+v (text %q)", it, it.countText())
	}
	if it := pm.items[1]; it.sourceCount != 0 || it.capped() || it.countText() != "200" {
		t.Errorf("row without the column parsed as %+v (text %q)", it, it.countText())
	}
	if it := pm.items[2]; it.capped() || it.countText() != "150" {
		t.Errorf("preset that fit parsed as %+v (text %q)", it, it.countText())
	}
}

func TestPresetScreenText_SaysWhenTheListWasCut(t *testing.T) {
	cut := presetItem{title: "Acme", category: "Тест", kind: "domains", count: 200, sourceCount: 540}
	text := presetScreenText(cut, true, nil)
	for _, want := range []string{"200 из 540 доменов", "(+ список IP-диапазонов)", "Список урезан: в источнике 540 доменов (без поддоменов, уже покрытых родителем), оставлены 200: главные домены сервиса", "ещё не применён"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q not in:\n%s", want, text)
		}
	}
	fits := presetItem{title: "Acme", category: "Тест", kind: "domains", count: 150}
	text = presetScreenText(fits, false, nil)
	if !strings.Contains(text, "150 доменов") || strings.Contains(text, "урезан") || strings.Contains(text, " из ") {
		t.Errorf("a list that fit must not claim a cut:\n%s", text)
	}
	// The cut note and the applied state sit side by side.
	cut.installed = true
	if text = presetScreenText(cut, false, nil); !strings.Contains(text, "урезан") || !strings.Contains(text, "применён, актуально") {
		t.Errorf("applied and cut:\n%s", text)
	}
}

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
		if len(f) != 11 {
			t.Fatalf("row %q has %d fields, want 11 (source count, then the public DNS services)", ln, len(f))
		}
		if _, err := strconv.Atoi(f[9]); err != nil {
			t.Errorf("row %q: source count %q is not a number", ln, f[9])
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

const googleDNSName = "Google Public DNS (8.8.8.8, 8.8.4.4)"

// The public DNS services a subnet preset covers travel to the bot as the last
// column: set for a list whose ranges hold Google Public DNS, empty for a domain
// preset. (Overlay data: the embedded presets change with every daily refresh.)
func TestRoutesPresetList_CarriesThePublicDNSServices(t *testing.T) {
	withCutPreset(t)
	out := presetTestHandler(t).routesPresetList()
	seen := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Split(ln, "\t")
		if len(f) == 11 && !strings.HasPrefix(ln, "#") {
			seen[f[0]] = f[10]
		}
	}
	if seen["acme-ip"] != googleDNSName {
		t.Errorf("acme-ip row: resolvers column = %q, want %q", seen["acme-ip"], googleDNSName)
	}
	if v, ok := seen["acme"]; !ok || v != "" {
		t.Errorf("a domain preset has an empty resolvers column, got %q (row seen: %v)", v, ok)
	}
}

func TestParsePresetList_PublicDNSColumn(t *testing.T) {
	pm := parsePresetList(strings.Join([]string{
		"google\tgoogle\tGoogle\tТест\tdomains\t200\t0\t0\t0\t1018\t",
		"google-ip\tgoogle\tGoogle\tТест\tcidr\t90\t0\t0\t0\t0\t" + googleDNSName + "; Cloudflare (1.1.1.1)",
		"old\told\tOld\tТест\tdomains\t100\t0\t0\t0\t0", // an agent without the column
		"last\tlast\tLast\tТест\tcidr\t5\t0\t0\t0\t0\t", // a trailing empty field the parser may see trimmed
	}, "\n"))
	if len(pm.items) != 4 {
		t.Fatalf("items = %d, want 4", len(pm.items))
	}
	if got := pm.items[1].resolvers; len(got) != 2 || got[0] != googleDNSName || got[1] != "Cloudflare (1.1.1.1)" {
		t.Errorf("resolvers parsed as %q", got)
	}
	for _, i := range []int{0, 2, 3} {
		if pm.items[i].resolvers != nil {
			t.Errorf("item %d (%s): resolvers = %q, want none", i, pm.items[i].name, pm.items[i].resolvers)
		}
	}
	comp, ok := pm.companion("google")
	if !ok || comp.name != "google-ip" || len(comp.resolvers) != 2 {
		t.Errorf("companion(google) = %+v (%v)", comp, ok)
	}
	if _, ok := pm.companion("old"); ok || pm.hasCompanion("old") {
		t.Error("a preset without an -ip row has no companion")
	}
}

// The warning sits on the domain preset's screen, where the operator chooses
// "Домены + IP-диапазоны" -- and only when there is an IP list to choose.
func TestPresetScreenText_WarnsAboutPublicDNSInTheIPList(t *testing.T) {
	it := presetItem{title: "Google", category: "Тест", kind: "domains", count: 150}
	text := presetScreenText(it, true, []string{googleDNSName})
	for _, want := range []string{"⚠️ в IP-диапазонах есть публичный DNS — " + googleDNSName, "UDP/53", "Список не менялся"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q not in:\n%s", want, text)
		}
	}
	if text = presetScreenText(it, true, nil); strings.Contains(text, "публичный DNS") {
		t.Errorf("no resolvers, yet a warning:\n%s", text)
	}
	if text = presetScreenText(it, false, []string{googleDNSName}); strings.Contains(text, "публичный DNS") {
		t.Errorf("no IP list to choose, yet a warning:\n%s", text)
	}
}
