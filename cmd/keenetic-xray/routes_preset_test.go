package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// withCutPresets serves two presets from an overlay: a domain list the generator
// cut (3 held of 540) with a CIDR companion that was cut too (2 of 1034), and one
// that fit.
func withCutPresets(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	manifest := `{"version":1,"generated":"2026-11-22","categories":["Тест"],"presets":[` +
		`{"name":"acme","service":"acme","title":"Acme","category":"Тест","kind":"domains","count":3,"rev":"x","source_count":540,"sources":["s"]},` +
		`{"name":"acme-ip","service":"acme","title":"Acme","category":"Тест","kind":"cidr","count":2,"rev":"y","source_count":1034,"sources":["s"]},` +
		`{"name":"small","service":"small","title":"Small","category":"Тест","kind":"domains","count":150,"rev":"z","sources":["s"]},` +
		`{"name":"small-ip","service":"small","title":"Small","category":"Тест","kind":"cidr","count":1,"rev":"w","sources":["s"]}]}`
	files := map[string]string{
		"manifest.json": manifest,
		// acme's IP list carries Google Public DNS among its ranges; small's does not.
		"acme-ip.lst":  "# Acme\n\n8.8.8.0/24\n203.0.113.0/24\n",
		"small-ip.lst": "# Small\n\n203.0.113.0/24\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	presets.SetOverlay(dir)
	t.Cleanup(func() { presets.SetOverlay("") })
}

func TestPresetList_ShowsTheCountTheSourceHad(t *testing.T) {
	withCutPresets(t)
	out := captureStdout(t, func() { _ = presetList(config.Default()) })
	var acme, small string
	for _, ln := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(ln, "acme "):
			acme = ln
		case strings.Contains(ln, "small "):
			small = ln
		}
	}
	if !strings.Contains(acme, "3 из 540 дом.") {
		t.Errorf("the cut list's line = %q, want '3 из 540 дом.'", acme)
	}
	if !strings.Contains(small, "150 дом.") || strings.Contains(small, " из ") {
		t.Errorf("the list that fit: %q", small)
	}
}

func TestPresetShow_SaysWhatWasLeftOut(t *testing.T) {
	withCutPresets(t)
	out := captureStdout(t, func() { _ = presetShow(config.Default(), "acme") })
	for _, want := range []string{
		"записей: 3 из 540",
		"урезан:     в источнике 540 доменов, оставлены 3 самых общих",
		"routes add <список> <домен>",
		"+IP-список: acme-ip (2 из 1034 подсетей)",
		"в источнике 1034 подсетей (после объединения соседних), оставлены 2 самых крупных",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%q not in:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() { _ = presetShow(config.Default(), "small") })
	if !strings.Contains(out, "записей: 150\n") || strings.Contains(out, "урезан") {
		t.Errorf("a list that fit must not claim a cut:\n%s", out)
	}
}

// A subnet list that carries Google Public DNS gets a warning on `show` -- on
// the domain preset (where the IP list is offered) and on the subnet preset
// itself -- and a list that carries no resolver gets none.
func TestPresetShow_WarnsAboutPublicDNSInAnIPList(t *testing.T) {
	withCutPresets(t)
	for _, name := range []string{"acme", "acme-ip"} {
		out := captureStdout(t, func() { _ = presetShow(config.Default(), name) })
		for _, want := range []string{"⚠️ DNS:", "Google Public DNS (8.8.8.8, 8.8.4.4)", "Список не менялся"} {
			if !strings.Contains(out, want) {
				t.Errorf("show %s: %q not in:\n%s", name, want, out)
			}
		}
	}
	for _, name := range []string{"small", "small-ip"} {
		if out := captureStdout(t, func() { _ = presetShow(config.Default(), name) }); strings.Contains(out, "⚠️ DNS:") {
			t.Errorf("show %s warns although its ranges hold no public resolver:\n%s", name, out)
		}
	}
}

// Someone who applied a list last month never runs `show`: the browse list marks
// the domain presets whose IP list covers a public resolver, with a legend.
func TestPresetList_MarksIPListsThatCoverPublicDNS(t *testing.T) {
	withCutPresets(t)
	out := captureStdout(t, func() { _ = presetList(config.Default()) })
	var acme, small string
	for _, ln := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(ln, "acme "):
			acme = ln
		case strings.Contains(ln, "small "):
			small = ln
		}
	}
	if !strings.Contains(acme, "+IP⚠") || !strings.Contains(out, "⚠ — в IP-диапазонах есть публичный DNS") {
		t.Errorf("the list with Google DNS in its ranges is not marked (line %q), or the legend is missing:\n%s", acme, out)
	}
	if !strings.Contains(small, "+IP") || strings.Contains(small, "⚠") {
		t.Errorf("the clean list: %q", small)
	}
}
