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
		`{"name":"small","service":"small","title":"Small","category":"Тест","kind":"domains","count":150,"rev":"z","sources":["s"]}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
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
