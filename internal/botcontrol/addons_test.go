package botcontrol

import (
	"context"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// On a box without opkg (CI, the dev machine) every component's Detect
// reports "not installed", so addon_list is deterministic: one row per
// component, tab-separated, in the fixed order.
func TestRouterHandler_AddonList(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	out, err := h.Handle(context.Background(), Command{Action: ActionAddonList})
	if err != nil {
		t.Fatalf("addon_list: %v", err)
	}
	lines := strings.Split(strings.Trim(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("addon_list returned %d lines, want 5:\n%s", len(lines), out)
	}
	wantIDs := []string{"unbound", "dnscrypt", "nfqws2", "conntrack", "cron"}
	for i, ln := range lines {
		f := strings.Split(ln, "\t")
		if len(f) != 6 {
			t.Errorf("line %d has %d tab-fields, want 6: %q", i, len(f), ln)
			continue
		}
		if f[0] != wantIDs[i] {
			t.Errorf("line %d id = %q, want %q", i, f[0], wantIDs[i])
		}
		for j, v := range f {
			if v == "" {
				t.Errorf("line %d field %d is blank (should be a %q sentinel): %q", i, j, "-", ln)
			}
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

// The CI box / dev machine has no opkg, so these outcomes are
// deterministic: a not-installed component, an install that can't run
// opkg, a component with no settings.
func TestRouterHandler_AddonShowStatusRemove_NotInstalled(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	ctx := context.Background()

	show, err := h.Handle(ctx, Command{Action: ActionAddonShow, Args: []string{"unbound"}})
	if err != nil {
		t.Fatalf("addon_show: %v", err)
	}
	if !strings.Contains(show, "не установлен") || !strings.Contains(show, "unbound") {
		t.Errorf("addon_show text = %q", show)
	}

	st, err := h.Handle(ctx, Command{Action: ActionAddonStatus, Args: []string{"conntrack"}})
	if err != nil || !strings.Contains(st, "не установлен") {
		t.Errorf("addon_status = %q, %v", st, err)
	}

	// Remove on a not-installed component is a friendly no-op, not an error.
	rm, err := h.Handle(ctx, Command{Action: ActionAddonRemove, Args: []string{"conntrack"}})
	if err != nil || !strings.Contains(rm, "не установлен") {
		t.Errorf("addon_remove = %q, %v", rm, err)
	}
}

func TestRouterHandler_AddonInstall_FailsWithoutOpkg(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	// conntrack is the simplest: Install is just `opkg install conntrack`,
	// which can't run here -> an error surfaces rather than a panic.
	if _, err := h.Handle(context.Background(), Command{Action: ActionAddonInstall, Args: []string{"conntrack"}}); err == nil {
		t.Error("expected addon_install to fail without opkg")
	}
}

func TestRouterHandler_AddonConfigure_RejectsBadInput(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	ctx := context.Background()

	// conntrack takes no settings at all.
	if _, err := h.Handle(ctx, Command{Action: ActionAddonConfigure, Args: []string{"conntrack", "x=1"}}); err == nil {
		t.Error("conntrack configure should reject any key")
	}
	// an arg without '='.
	if _, err := h.Handle(ctx, Command{Action: ActionAddonConfigure, Args: []string{"nfqws2", "noequals"}}); err == nil {
		t.Error("configure should reject an arg without '='")
	}
	// an unknown key for a component that does take settings.
	if _, err := h.Handle(ctx, Command{Action: ActionAddonConfigure, Args: []string{"unbound", "bogus=1"}}); err == nil {
		t.Error("unbound configure should reject an unknown key")
	}
}

func TestParseAddonList(t *testing.T) {
	// The producer never emits a blank field -- "-" stands in for an
	// empty version/detail (addonList's dashIfEmpty).
	tsv := "unbound\tUnbound — рекурсивный DNS\t1\t1\t1.19.3\t127.0.0.1:5353\n" +
		"nfqws2\tnfqws2 — обход DPI\t0\t-\t-\t-\n"
	rows := parseAddonList(tsv)
	if len(rows) != 2 {
		t.Fatalf("parseAddonList len = %d, want 2", len(rows))
	}
	if !rows[0].installed || rows[0].running != "1" || rows[0].version != "1.19.3" || rows[0].detail != "127.0.0.1:5353" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].installed || rows[1].running != "-" || rows[1].version != "" || rows[1].detail != "" {
		t.Errorf("row 1 = %+v (want not-installed, running \"-\", version/detail empty)", rows[1])
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
