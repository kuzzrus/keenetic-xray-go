package botcontrol

import (
	"context"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// On a box without opkg (CI, the dev machine) every component's Detect
// reports "not installed", so addon_list is deterministic: four rows,
// tab-separated, in the fixed order.
func TestRouterHandler_AddonList(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	out, err := h.Handle(context.Background(), Command{Action: ActionAddonList})
	if err != nil {
		t.Fatalf("addon_list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("addon_list returned %d lines, want 4:\n%s", len(lines), out)
	}
	wantIDs := []string{"unbound", "nfqws2", "conntrack", "cron"}
	for i, ln := range lines {
		f := strings.Split(ln, "\t")
		if len(f) != 6 {
			t.Errorf("line %d has %d tab-fields, want 6: %q", i, len(f), ln)
			continue
		}
		if f[0] != wantIDs[i] {
			t.Errorf("line %d id = %q, want %q", i, f[0], wantIDs[i])
		}
	}
}

func TestRouterHandler_AddonUnknown(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	if _, err := h.Handle(context.Background(), Command{Action: ActionAddonShow, Args: []string{"nope"}}); err == nil {
		t.Error("expected an error for an unknown component")
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionAddonShow}); err == nil {
		t.Error("expected an error when no component id is given")
	}
}

func TestParseAddonList(t *testing.T) {
	tsv := "unbound\tUnbound — рекурсивный DNS\t1\t1\t1.19.3\t127.0.0.1:5353\n" +
		"nfqws2\tnfqws2 — обход DPI\t0\t-\t\t\n"
	rows := parseAddonList(tsv)
	if len(rows) != 2 {
		t.Fatalf("parseAddonList len = %d, want 2", len(rows))
	}
	if !rows[0].installed || rows[0].running != "1" || rows[0].version != "1.19.3" || rows[0].detail != "127.0.0.1:5353" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].installed || rows[1].running != "-" {
		t.Errorf("row 1 = %+v", rows[1])
	}
}

func TestAddonsScreenKB_CallbackData(t *testing.T) {
	rows := []addonRow{{id: "unbound", title: "Unbound", installed: true}, {id: "nfqws2", title: "nfqws2"}}
	kb := addonsScreenKB("router-1", rows)
	if got := kb.InlineKeyboard[0][0].CallbackData; got != "adn:router-1:unbound" {
		t.Errorf("row 0 callback = %q", got)
	}
	if got := kb.InlineKeyboard[0][0].Text; !strings.HasPrefix(got, "✅") {
		t.Errorf("installed row should be ticked: %q", got)
	}
	if got := kb.InlineKeyboard[1][0].Text; !strings.HasPrefix(got, "⬜") {
		t.Errorf("not-installed row should be empty box: %q", got)
	}
	// last row is the nav row
	last := kb.InlineKeyboard[len(kb.InlineKeyboard)-1]
	if last[len(last)-1].CallbackData != "router:router-1" {
		t.Errorf("nav row back button = %q", last[len(last)-1].CallbackData)
	}
}
