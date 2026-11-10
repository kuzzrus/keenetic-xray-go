package botcontrol

import (
	"context"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func showFor(t *testing.T, adaptive, l7 bool, quic string) string {
	t.Helper()
	h := newL7Handler(t)
	h.Config.AdaptiveRoute.Enabled = adaptive
	h.Config.L7SNI = config.L7SNIConfig{Enabled: l7, QUIC: quic}
	out, err := h.Handle(context.Background(), Command{Action: ActionL7SNIShow})
	if err != nil {
		t.Fatalf("l7sni_show: %v", err)
	}
	return out
}

func wantAll(t *testing.T, name, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s: %q not in:\n%s", name, w, out)
		}
	}
}

func wantNone(t *testing.T, name, out string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(out, n) {
			t.Errorf("%s: %q in:\n%s", name, n, out)
		}
	}
}

// The first thing the L7 screen says is where its three switches stand and what
// to press for the one that is off -- the operator who asked "where do I turn
// QUIC on?" had a screen that only ever showed an answer to the last button.
func TestL7SNIShow_SaysWhereEachSwitchStandsAndWhatToPress(t *testing.T) {
	out := showFor(t, true, false, "")
	wantAll(t, "l7sni off", out, "🎯 Адаптивная маршрутизация: вкл", "🔍 L7 SNI: выкл", "Нажми «🔍 L7 SNI вкл»")
	wantNone(t, "l7sni off", out, "⚠️")

	out = showFor(t, true, true, "")
	wantAll(t, "quic off", out, "🔍 L7 SNI: вкл", "QUIC-перехват: выкл", "«👁 QUIC наблюдение»", "«⚡ QUIC действие»")
	wantNone(t, "quic off", out, "Нажми «🔍 L7 SNI вкл»", "⚠️")

	out = showFor(t, true, true, "observe")
	wantAll(t, "quic observe", out, "QUIC-перехват: наблюдение")
	wantNone(t, "quic observe", out, "➡️", "⚠️")

	out = showFor(t, true, true, "act")
	wantAll(t, "quic act", out, "QUIC-перехват: действие")
	wantNone(t, "quic act", out, "➡️", "⚠️")
}

// The other half of the operator's question: L7 SNI does not replace adaptive
// routing, it feeds it -- the answer to "do I switch adaptive routing off and
// L7 on separately?" is on the screen too.
func TestL7SNIShow_AdaptiveRoutingOffIsAWarningNotAnInstructionToKeepItOff(t *testing.T) {
	out := showFor(t, false, true, "act")
	wantAll(t, "adaptive off", out, "🎯 Адаптивная маршрутизация: выкл", "⚠️", "Выключать её ради L7 не нужно", "работает как «наблюдение»")
}

func TestL7SNIScreen_ButtonsSayWhatTheyDoToQUIC(t *testing.T) {
	var labels []string
	for _, row := range l7sniScreenKB("home").InlineKeyboard {
		for _, b := range row {
			labels = append(labels, b.Text)
		}
	}
	all := strings.Join(labels, "|")
	// "QUIC: выкл" used to read as a state; every QUIC button now names QUIC and its action
	for _, want := range []string{"⏹ QUIC выкл", "👁 QUIC наблюдение", "⚡ QUIC действие"} {
		if !strings.Contains(all, want) {
			t.Errorf("buttons %q lack %q", all, want)
		}
	}
	if strings.Contains(all, "QUIC: выкл") {
		t.Errorf("a button still reads like a state: %q", all)
	}
	text := l7sniScreenText("home", "")
	wantAll(t, "screen text", text, "выключать её не нужно", "«QUIC выкл» его выключает")
}
