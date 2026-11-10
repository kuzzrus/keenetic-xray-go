package botcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func newL7Handler(t *testing.T) *RouterHandler {
	t.Helper()
	return &RouterHandler{Config: config.Default(), ConfigPath: filepath.Join(t.TempDir(), "c.json")}
}

func savedQUIC(t *testing.T, h *RouterHandler) string {
	t.Helper()
	saved, err := config.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	return saved.L7SNI.QUIC
}

func TestRouterHandler_L7SNIQUIC_SavesTheModeAndPlacesTheRule(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.Enabled = true
	h.Config.AdaptiveRoute.Enabled = true
	reconciles := 0
	h.ReconcileL7SNI = func(context.Context) error { reconciles++; return nil }

	for _, tc := range []struct{ action, saved, want string }{
		{ActionL7SNIQUICObserve, "observe", "наблюдение — считаем"},
		{ActionL7SNIQUICAct, "act", "действие — совпавшие"},
		{ActionL7SNIQUICOff, "", "QUIC-перехват: выкл"},
	} {
		out, err := h.Handle(context.Background(), Command{Action: tc.action})
		if err != nil {
			t.Fatalf("%s: %v", tc.action, err)
		}
		if !strings.Contains(out, tc.want) || !strings.Contains(out, "приведено в соответствие") {
			t.Errorf("%s: output %q lacks %q or the rule confirmation", tc.action, out, tc.want)
		}
		if got := savedQUIC(t, h); got != tc.saved {
			t.Errorf("%s: saved %q, want %q (off is stored as the empty default)", tc.action, got, tc.saved)
		}
	}
	if reconciles != 3 {
		t.Errorf("the NFLOG rule was reconciled %d times, want once per change", reconciles)
	}
}

func TestRouterHandler_L7SNIQUIC_ActWarnsAboutAppsWithoutATCPFallback(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.Enabled, h.Config.AdaptiveRoute.Enabled = true, true
	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICAct})
	if err != nil || !strings.Contains(out, "без запасного пути на TCP") {
		t.Errorf("act output = %q, %v", out, err)
	}
	out, _ = h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve})
	if strings.Contains(out, "запасного пути") {
		t.Errorf("observe changes nothing for the client and must not warn about it: %q", out)
	}
}

func TestRouterHandler_L7SNIQUIC_WithL7SNIOffOnlySaves(t *testing.T) {
	h := newL7Handler(t) // L7 SNI is off by default
	h.ReconcileL7SNI = func(context.Context) error { t.Error("the rule was reconciled with l7sni off"); return nil }

	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "но L7 SNI выключен") || !strings.Contains(out, "Включи 🔍 L7 SNI") {
		t.Errorf("observe with l7sni off: %q", out)
	}
	if got := savedQUIC(t, h); got != "observe" {
		t.Errorf("saved %q, want the mode kept for when l7sni is switched on", got)
	}

	out, err = h.Handle(context.Background(), Command{Action: ActionL7SNIQUICOff})
	if err != nil || strings.Contains(out, "Включи") {
		t.Errorf("turning QUIC off needs no hint to switch l7sni on: %q, %v", out, err)
	}
}

func TestRouterHandler_L7SNIQUIC_ReportsARuleThatCouldNotBePlaced(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.Enabled = true
	h.ReconcileL7SNI = func(context.Context) error { return errors.New("iptables: boom") }

	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve})
	if err != nil {
		t.Fatalf("the mode is saved, so this is not a failed action: %v", err)
	}
	if !strings.Contains(out, "⚠️") || !strings.Contains(out, "iptables: boom") || strings.Contains(out, "приведено в соответствие") {
		t.Errorf("output must say the rule failed, not that it was applied: %q", out)
	}
	if got := savedQUIC(t, h); got != "observe" {
		t.Errorf("saved %q, want the mode kept for the daemon's own reconcile to act on", got)
	}
}

func TestRouterHandler_L7SNIQUIC_WithoutAReconcileHook(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.Enabled = true
	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve})
	if err != nil || !strings.Contains(out, "поставит демон при ближайшей сверке") {
		t.Errorf("output = %q, %v", out, err)
	}
}

func TestRouterHandler_L7SNIQUIC_ActWithoutAdaptiveRoutingSaysItOnlyObserves(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.Enabled = true // adaptive routing stays off
	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICAct})
	if err != nil || !strings.Contains(out, "работает как «наблюдение»") {
		t.Errorf("output = %q, %v", out, err)
	}
}

func TestRouterHandler_L7SNIQUIC_NeedsAConfigPath(t *testing.T) {
	h := &RouterHandler{Config: config.Default()}
	if _, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICObserve}); err == nil {
		t.Error("saving without a config path should fail rather than write into the working directory")
	}
}

func TestL7SNIQUICStatusRU_ANonsenseValueSaysSo(t *testing.T) {
	cfg := config.Default()
	cfg.L7SNI = config.L7SNIConfig{Enabled: true, QUIC: "Observe"}
	got := l7sniQUICStatusRU(cfg)
	if !strings.Contains(got, `записано "Observe"`) || !strings.Contains(got, "читается как «выкл»") {
		t.Errorf("status = %q", got)
	}
	cfg.L7SNI.QUIC = "off"
	if got := l7sniQUICStatusRU(cfg); strings.Contains(got, "записано") {
		t.Errorf("an explicit off needs no warning: %q", got)
	}
}

func TestRouterHandler_L7SNIStats(t *testing.T) {
	h := newL7Handler(t)
	if _, err := h.Handle(context.Background(), Command{Action: ActionL7SNIStats}); err == nil {
		t.Error("l7sni_stats without a stats source should say so")
	}
	h.L7SNIStatsText = func() (string, error) { return "TLS (TCP/443): ClientHello разобрано 7", nil }
	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIStats})
	if err != nil || !strings.Contains(out, "ClientHello разобрано 7") {
		t.Errorf("output = %q, %v", out, err)
	}
	h.L7SNIStatsText = func() (string, error) { return "", errors.New("file unreadable") }
	if _, err := h.Handle(context.Background(), Command{Action: ActionL7SNIStats}); err == nil || !strings.Contains(err.Error(), "file unreadable") {
		t.Errorf("a failing stats source must reach the operator: %v", err)
	}
}

func TestRouterHandler_AdaptiveRouteShow_IncludesQUICMode(t *testing.T) {
	h := newL7Handler(t)

	out, _ := h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteShow})
	if strings.Contains(out, "QUIC-перехват") {
		t.Errorf("with l7sni and QUIC both off the line is just noise: %q", out)
	}

	h.Config.L7SNI.Enabled = true
	h.Config.L7SNI.QUIC = config.L7SNIQUICObserve
	out, _ = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteShow})
	if !strings.Contains(out, "L7 SNI: вкл") || !strings.Contains(out, "QUIC-перехват: наблюдение") {
		t.Errorf("adrt_show output = %q", out)
	}

	// a mode chosen while l7sni was off must not be silently forgotten
	h.Config.L7SNI.Enabled = false
	out, _ = h.Handle(context.Background(), Command{Action: ActionAdaptiveRouteShow})
	if !strings.Contains(out, "но L7 SNI выключен") {
		t.Errorf("a saved QUIC mode with l7sni off should be shown as inactive: %q", out)
	}
}

// The warning about apps that have no TCP fallback describes what redirecting
// does; with act not in effect nothing is redirected and the status line says
// the capture only observes, so the two must not appear together.
func TestRouterHandler_L7SNIQUIC_ActWarningOnlyWhenActIsInEffect(t *testing.T) {
	const warn = "без запасного пути на TCP"
	for _, tc := range []struct {
		name               string
		l7sni, adaptive    bool
		wantWarn, wantNote string
	}{
		{"in effect", true, true, "yes", "действие — совпавшие"},
		{"adaptive routing off: it only observes", true, false, "", "работает как «наблюдение»"},
		{"l7sni off: nothing runs", false, true, "", "но L7 SNI выключен"},
	} {
		h := newL7Handler(t)
		h.Config.L7SNI.Enabled, h.Config.AdaptiveRoute.Enabled = tc.l7sni, tc.adaptive
		out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICAct})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !strings.Contains(out, tc.wantNote) {
			t.Errorf("%s: output %q lacks %q", tc.name, out, tc.wantNote)
		}
		if got := strings.Contains(out, warn); got != (tc.wantWarn != "") {
			t.Errorf("%s: warning present = %v, want %v: %q", tc.name, got, tc.wantWarn != "", out)
		}
	}
}

// A mode that could not be saved was not chosen: it must not stay in memory,
// where "show" would report it and the next unrelated save would write it.
func TestRouterHandler_L7SNIQUIC_FailedSaveLeavesTheModeAlone(t *testing.T) {
	h := newL7Handler(t)
	h.Config.L7SNI.QUIC = config.L7SNIQUICObserve
	// Save creates a missing directory, so make the "directory" a file: the
	// write cannot succeed.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = filepath.Join(blocker, "c.json")

	if _, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICAct}); err == nil {
		t.Fatal("a save below a regular file should fail")
	}
	if h.Config.L7SNI.QUIC != config.L7SNIQUICObserve {
		t.Errorf("after a failed save the in-memory mode is %q, want the previous %q", h.Config.L7SNI.QUIC, config.L7SNIQUICObserve)
	}
	if _, err := h.Handle(context.Background(), Command{Action: ActionL7SNIQUICOff}); err == nil {
		t.Fatal("a save below a regular file should fail")
	}
	if h.Config.L7SNI.QUIC != config.L7SNIQUICObserve {
		t.Errorf("after a failed off the in-memory mode is %q, want the previous %q", h.Config.L7SNI.QUIC, config.L7SNIQUICObserve)
	}
}
