package botcontrol

import (
	"strings"
	"testing"
)

func buttonData(kb inlineKeyboard) map[string]bool {
	out := map[string]bool{}
	for _, row := range kb.InlineKeyboard {
		for _, b := range row {
			out[b.CallbackData] = true
		}
	}
	return out
}

// The TUN transport's screen: reachable from "Порты и транспорт", with the
// three actions, and honest about being experimental and about the one
// foot-gun (routing the VLESS server's own address into it).
func TestTunTransportScreen(t *testing.T) {
	if !buttonData(portsTransportScreenKB("r1"))["tunt:r1"] {
		t.Error("the TUN screen is not reachable from the ports/transport screen")
	}

	got := buttonData(tunTransportScreenKB("r1"))
	for _, want := range []string{"act:tun_on:r1", "act:tun_off:r1", "act:tun_show:r1", "ptm:r1"} {
		if !got[want] {
			t.Errorf("TUN screen has no %q button; has %v", want, got)
		}
	}

	text := tunTransportScreenText("r1")
	for _, want := range []string{"r1", "экспериментальный", "OpkgTunN", "VLESS-сервера", "keenetic-xray-tun", "Скорость", "Proxy0"} {
		if !strings.Contains(text, want) {
			t.Errorf("TUN screen text lacks %q:\n%s", want, text)
		}
	}
}

func TestCallbackAction_Tun(t *testing.T) {
	for name, want := range map[string]string{
		"tun_show": ActionTunTransportShow,
		"tun_on":   ActionTunTransportOn,
		"tun_off":  ActionTunTransportOff,
	} {
		if got := callbackAction(name); got != want {
			t.Errorf("callbackAction(%q) = %q, want %q", name, got, want)
		}
	}
}

// A list can be aimed at the OpkgTun interface from its interface chooser.
func TestRouteIfaceTokens_OpkgTun(t *testing.T) {
	if got := routeIfaceTokens["t0"]; got != "OpkgTun0" {
		t.Errorf("routeIfaceTokens[t0] = %q, want OpkgTun0", got)
	}
}
