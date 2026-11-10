package botcontrol

import (
	"strings"
	"testing"
	"time"
)

func TestL7SNIScreen_KeyboardAndText(t *testing.T) {
	cb := callbacks(l7sniScreenKB("home"))
	for name := range l7sniScreenNames {
		if !cb["adxQ:home:"+name] {
			t.Errorf("L7 screen has no button for %q: %v", name, cb)
		}
		if callbackAction(name) == "" {
			t.Errorf("%q is a button of the L7 screen but maps to no router action", name)
		}
	}
	if !cb["adxS:home"] || !cb["adrt:home"] {
		t.Errorf("L7 screen lacks the counters button or the way back: %v", cb)
	}
	text := l7sniScreenText("home", "")
	for _, want := range []string{"L7 SNI и QUIC", "наблюдение", "действие", "ECH", "запасного пути на TCP"} {
		if !strings.Contains(text, want) {
			t.Errorf("L7 screen text lacks %q", want)
		}
	}
	// with the router's answer on top it must still fit one message
	if n := len([]rune(l7sniScreenText("home", strings.Repeat("я", 400)))); n > telegramTextLimit-100 {
		t.Errorf("L7 screen with a long answer is %d runes, limit %d", n, telegramTextLimit)
	}
}

func TestAdaptiveScreen_LinksToTheL7Screen(t *testing.T) {
	cb := callbacks(adaptiveRouteScreenKB("home"))
	if !cb["adxQ:home"] {
		t.Errorf("adaptive screen has no way into the L7 screen: %v", cb)
	}
	if cb["act:l7sni_on:home"] || cb["act:l7sni_off:home"] {
		t.Errorf("the L7 switches moved to their own screen; the old act: buttons are still on the adaptive one: %v", cb)
	}
	if text := adaptiveRouteScreenText("home"); !strings.Contains(text, "L7 SNI и QUIC") {
		t.Errorf("adaptive screen text does not mention the L7 screen")
	}
}

func TestTelegramBot_L7SNIScreenSetsTheQUICMode(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	seen := answerCommands(t, store, "home", []Result{
		{Output: "🎯 Адаптивная маршрутизация: вкл\n🔍 L7 SNI: вкл\n🔍 QUIC-перехват: выкл"},
		{Output: "QUIC-перехват: наблюдение — считаем имена и ECH-расширения, ничего не переправляем\nПравило перехвата UDP/443 приведено в соответствие; демон подхватит режим сам, перезапуск не нужен."},
		{Err: "сохранить не вышло"},
	})

	// open the screen: the menu itself comes at once, the router's state follows on top of it
	fake.pushCallback(1, msgID, "adxQ:home")
	fake.waitForEditContaining(t, 3*time.Second, "🔍 L7 SNI и QUIC — home")
	if e := fake.lastEdit(t); !e.hasButton("adxQ:home:l7q_obs") || !e.hasButton("adxS:home") {
		t.Fatalf("L7 screen buttons = %v", e.Buttons)
	}
	state := fake.waitForEditContaining(t, 3*time.Second, "🔍 QUIC-перехват: выкл")
	if !strings.HasPrefix(state, "🎯 Адаптивная маршрутизация: вкл") || !strings.Contains(state, "🔍 L7 SNI и QUIC — home") {
		t.Errorf("the state should head the screen:\n%s", state)
	}
	if cmd := <-seen; cmd.Action != ActionL7SNIShow || len(cmd.Args) != 0 {
		t.Errorf("opening the screen asked the router for %+v, want %s without args", cmd, ActionL7SNIShow)
	}

	// choose observe: the router is asked, the screen comes back with its answer on top
	fake.pushCallback(1, msgID, "adxQ:home:l7q_obs")
	text := fake.waitForEditContaining(t, 3*time.Second, "QUIC-перехват: наблюдение")
	if !strings.Contains(text, "🔍 L7 SNI и QUIC — home") {
		t.Errorf("the answer should head the L7 screen again:\n%s", text)
	}
	if cmd := <-seen; cmd.Action != ActionL7SNIQUICObserve || len(cmd.Args) != 0 {
		t.Errorf("command = %+v, want %s without args", cmd, ActionL7SNIQUICObserve)
	}
	if !fake.lastEdit(t).hasButton("adxQ:home:l7q_act") {
		t.Errorf("after the change the operator should still be on the L7 screen: %v", fake.lastEdit(t).Buttons)
	}

	// a failure leaves the operator on this screen too, with the reason
	fake.pushCallback(1, msgID, "adxQ:home:l7q_act")
	text = fake.waitForEditContaining(t, 3*time.Second, "сохранить не вышло")
	if !strings.Contains(text, "⚠️") || !fake.lastEdit(t).hasButton("adxQ:home:l7q_off") {
		t.Errorf("failure screen:\n%s\nbuttons %v", text, fake.lastEdit(t).Buttons)
	}
	if cmd := <-seen; cmd.Action != ActionL7SNIQUICAct {
		t.Errorf("second command = %s, want %s", cmd.Action, ActionL7SNIQUICAct)
	}
}

// An agent that does not know l7sni_show (it is older than the control server)
// answers with an error: the menu must stay as it was, not show the error as if
// a button had failed.
func TestTelegramBot_L7SNIScreenSurvivesAnAgentWithoutTheStateAction(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	seen := answerCommands(t, store, "home", []Result{{Err: "неизвестное действие l7sni_show"}})
	fake.pushCallback(1, msgID, "adxQ:home")
	fake.waitForEditContaining(t, 3*time.Second, "🔍 L7 SNI и QUIC — home")
	if cmd := <-seen; cmd.Action != ActionL7SNIShow {
		t.Fatalf("opening the screen asked for %s, want %s", cmd.Action, ActionL7SNIShow)
	}
	time.Sleep(300 * time.Millisecond) // the answer, if it were going to be drawn, has been by now
	if text := fake.lastEdit(t).Text; strings.Contains(text, "неизвестное действие") || strings.Contains(text, "⚠️") {
		t.Errorf("the menu shows the agent's error:\n%s", text)
	}
	if !fake.lastEdit(t).hasButton("adxQ:home:l7q_obs") {
		t.Errorf("the menu lost its buttons: %v", fake.lastEdit(t).Buttons)
	}
}

func TestTelegramBot_L7SNIStatsScreen(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	seen := answerCommands(t, store, "home", []Result{
		{Output: "TLS (TCP/443): ClientHello разобрано 500\nQUIC (UDP/443): режим «наблюдение»\n"},
	})
	fake.pushCallback(1, msgID, "adxS:home")
	text := fake.waitForEditContaining(t, 3*time.Second, "ClientHello разобрано 500")
	if !strings.Contains(text, "📈 L7-счётчики — home") {
		t.Errorf("stats screen:\n%s", text)
	}
	if cmd := <-seen; cmd.Action != ActionL7SNIStats {
		t.Errorf("command = %s, want %s", cmd.Action, ActionL7SNIStats)
	}
	if e := fake.lastEdit(t); !e.hasButton("adxS:home") || !e.hasButton("adxQ:home") {
		t.Errorf("stats buttons = %v, want refresh and the way back to the L7 screen", e.Buttons)
	}
}

func TestTelegramBot_L7SNIBadButtonsDoNotCrash(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID

	// a name that is not one of the screen's buttons must not reach the router
	fake.pushCallback(1, msgID, "adxQ:home:adrt_flush")
	fake.waitForEditContaining(t, 3*time.Second, "плохая кнопка")
	if cmd, _ := store.Dequeue("home"); cmd != nil {
		t.Errorf("a callback for %q queued %s for the router", "adxQ:home:adrt_flush", cmd.Action)
	}

	fake.pushCallback(1, msgID, "adxQ:nope")
	fake.waitForEditContaining(t, 3*time.Second, "нет такого роутера: nope")
	fake.pushCallback(1, msgID, "adxS:nope")
	fake.waitForEditContaining(t, 3*time.Second, "нет такого роутера: nope")
}

// Telegram refuses a keyboard with callback_data over 64 bytes; the longest
// router ID ValidRouterID lets through must still fit every button of the
// L7 screens (like the list screens' test in telegram_adaptive_test.go).
func TestL7SNIScreens_CallbackDataFitsTelegram(t *testing.T) {
	id := strings.Repeat("a", maxRouterIDLen)
	if !ValidRouterID(id) {
		t.Fatalf("setup: %q is not a valid router ID", id)
	}
	for name, kb := range map[string]inlineKeyboard{
		"adaptive": adaptiveRouteScreenKB(id), "l7": l7sniScreenKB(id), "stats": l7sniStatsKB(id),
	} {
		for _, row := range kb.InlineKeyboard {
			for _, b := range row {
				if len(b.CallbackData) > 64 {
					t.Errorf("%s screen: callback_data %q is %d bytes, over Telegram's 64", name, b.CallbackData, len(b.CallbackData))
				}
			}
		}
	}
}
