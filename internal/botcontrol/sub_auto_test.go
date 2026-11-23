package botcontrol

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
)

func TestRouterHandler_SubAuto(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := config.Default()
	cfg.Subscription = &config.Subscription{URL: "https://p.example/s", LastFetchedAt: time.Now().Add(-2 * time.Hour)}
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath, SubRefreshStatePath: filepath.Join(dir, "state.json")}
	do := func(args ...string) (string, error) {
		return h.Handle(context.Background(), Command{Action: ActionSubAuto, Args: args})
	}

	out, err := do()
	if err != nil || !strings.Contains(out, "каждые 12 ч") || !strings.Contains(out, "последнее — 2 ч назад") || strings.Contains(out, "сохранено") {
		t.Errorf("status: %q, %v", out, err)
	}

	out, err = do("6")
	if err != nil || !strings.Contains(out, "сохранено") || !strings.Contains(out, "каждые 6 ч") {
		t.Errorf("set 6: %q, %v", out, err)
	}
	if saved, _ := config.Load(cfgPath); saved.SubscriptionRefreshHours != 6 {
		t.Errorf("not persisted: %d", saved.SubscriptionRefreshHours)
	}

	out, err = do("off")
	if err != nil || !strings.Contains(out, "выключено") {
		t.Errorf("off: %q, %v", out, err)
	}
	if saved, _ := config.Load(cfgPath); !saved.SubscriptionNoAutoRefresh {
		t.Error("off not persisted")
	}

	// "status" asks, never sets.
	if out, err = do("status"); err != nil || strings.Contains(out, "сохранено") || !strings.Contains(out, "выключено") {
		t.Errorf("status word: %q, %v", out, err)
	}

	if out, err = do("on"); err != nil || !strings.Contains(out, "каждые 6 ч") {
		t.Errorf("on: %q, %v", out, err)
	}
	for _, bad := range [][]string{{"often"}, {"0"}, {"169"}, {"6", "7"}} {
		if _, err := do(bad...); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if saved, _ := config.Load(cfgPath); saved.SubscriptionRefreshHours != 6 || saved.SubscriptionNoAutoRefresh {
		t.Errorf("a rejected value changed the config: %+v", saved)
	}
}

// What the daemon's own refresh recorded shows in status even though it left
// this handler's copy of the config alone.
func TestRouterHandler_StatusShowsTheAutomaticRefresh(t *testing.T) {
	d := newTestDaemon(t)
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "a"), testProfile("backup", "b")}
	cfg.PrimaryIndex, cfg.BackupIndex = 0, 1
	cfg.Proxy0.Enabled = false
	cfg.Subscription = &config.Subscription{URL: "https://p.example/s", LastFetchedAt: time.Now().Add(-20 * time.Hour)}

	state := filepath.Join(t.TempDir(), "state.json")
	if err := subscription.SaveRefreshState(state, subscription.RefreshState{LastSuccess: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	h := &RouterHandler{Daemon: d, Config: cfg, OptPath: t.TempDir(), SubRefreshStatePath: state}

	// "обновлена 1h назад", not the 20 h the config's own timestamp says; the
	// auto line leaves out "последнее" because the line above already says it.
	waitStatus(t, h, "подписка: 2 профилей, обновлена 1h назад", "автообновление подписки: каждые 12 ч, следующее через 11 ч")
	out, _ := h.Handle(context.Background(), Command{Action: ActionStatus})
	if strings.Contains(out, "последнее —") {
		t.Errorf("the refresh time is said twice:\n%s", out)
	}
}

func TestHelpMentionsSubAuto(t *testing.T) {
	if !strings.Contains(helpText, "/sub_auto <router>") {
		t.Error("/help does not list /sub_auto")
	}
}

func TestTelegramBot_SubAutoCommandAsksTheRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	seen := answerCommands(t, store, "home", []Result{
		{Output: "автообновление подписки: каждые 12 ч, следующее через 5 ч"},
		{Output: "сохранено; демон подхватит это в течение 10 минут\nавтообновление подписки: каждые 6 ч"},
	})
	fake.push(1, "/sub_auto home")
	waitSent(t, fake, 3*time.Second, "каждые 12 ч")
	if cmd := <-seen; cmd.Action != ActionSubAuto || len(cmd.Args) != 0 {
		t.Errorf("no argument: the router was asked %+v, want %s without arguments", cmd, ActionSubAuto)
	}
	fake.push(1, "/sub_auto home 6")
	waitSent(t, fake, 3*time.Second, "каждые 6 ч")
	if cmd := <-seen; cmd.Action != ActionSubAuto || len(cmd.Args) != 1 || cmd.Args[0] != "6" {
		t.Errorf("with 6: the router was asked %+v, want %s with the one argument", cmd, ActionSubAuto)
	}
}

func TestTelegramBot_SubAutoUsage(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 200 * time.Millisecond}
	runBotInBackground(t, bot)

	for _, text := range []string{"/sub_auto", "/sub_auto home 6 7"} {
		if got := replyTo(t, fake, text); !strings.Contains(got, "формат: /sub_auto <роутер>") {
			t.Errorf("%q -> %q, want the usage", text, got)
		}
	}
}
