package botcontrol

import (
	"strings"
	"testing"
	"time"
)

func TestParseProfileList(t *testing.T) {
	in := "0: alpha -- a.example.com:443 [primary]\n1: beta -- b.example.com:443 [backup]\n2: gamma -- c:80"
	got := parseProfileList(in)
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("parseProfileList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if parseProfileList("no profiles configured") != nil {
		t.Error("a non-list string should parse to nil")
	}
}

func TestNumberedProfiles(t *testing.T) {
	if got := numberedProfiles([]string{"a", "b"}); got != "0: a\n1: b" {
		t.Errorf("numberedProfiles = %q", got)
	}
}

func TestWizResult(t *testing.T) {
	if got := wizResult(true, "", "done"); got != "done" {
		t.Errorf("answered/no-err = %q", got)
	}
	if got := wizResult(true, "boom", ""); !strings.Contains(got, "boom") {
		t.Errorf("answered/err = %q", got)
	}
	if got := wizResult(false, "", ""); !strings.Contains(got, "не ответил") {
		t.Errorf("timeout = %q", got)
	}
	if got := wizResult(false, "queue full", ""); got != "queue full" {
		t.Errorf("queue error = %q", got)
	}
}

// waitSent blocks until some sent message contains want (most recent
// first), or fails the test. Unlike fake.lastSent it does not fatal
// while nothing has been sent yet.
func waitSent(t *testing.T, f *fakeTelegram, timeout time.Duration, want string) string {
	t.Helper()
	return f.waitFor(t, timeout, "a sent message containing "+want, func() string {
		texts := f.sentTexts()
		for i := len(texts) - 1; i >= 0; i-- {
			if strings.Contains(texts[i], want) {
				return texts[i]
			}
		}
		return ""
	})
}

// fakeAgent drains routerID's command queue and answers each command with
// reply(action), until the test ends.
func fakeAgent(t *testing.T, store *Store, routerID string, reply func(action string) string) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cmd, _ := store.Dequeue(routerID); cmd != nil {
				_ = store.RecordResult(routerID, Result{CommandID: cmd.ID, Output: reply(cmd.Action)})
				continue
			}
			time.Sleep(15 * time.Millisecond)
		}
	}()
}

func TestTelegramBot_SetupWizard_UnknownRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)

	fake.push(1, "/setup nope")
	if reply := fake.waitForReply(t, 3*time.Second); !strings.Contains(reply, "нет такого роутера") {
		t.Errorf("reply = %q", reply)
	}
}

func TestTelegramBot_SetupWizard_VlessLink(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)
	fakeAgent(t, store, "r1", func(action string) string {
		if action == ActionSetupLink {
			return "готово: My Node"
		}
		return "ok"
	})

	fake.push(1, "/setup r1")
	waitSent(t, fake, 3*time.Second, "Вставьте vless")

	fake.push(1, "vless://11111111-2222-3333-4444-555555555555@host.example:443?type=tcp&security=none#My%20Node")
	got := waitSent(t, fake, 3*time.Second, "готово")
	if !strings.Contains(got, "My Node") {
		t.Errorf("final message = %q", got)
	}
}

func TestTelegramBot_SetupWizard_Subscription(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)
	fakeAgent(t, store, "r1", func(action string) string {
		if action == ActionProfileList {
			return "0: alpha -- a.example.com:443\n1: beta -- b.example.com:443"
		}
		return "ok"
	})

	fake.push(1, "/setup r1")
	waitSent(t, fake, 3*time.Second, "Вставьте vless")

	fake.push(1, "https://provider.example/sub/token")
	primaryPrompt := waitSent(t, fake, 4*time.Second, "Номер PRIMARY")
	if !strings.Contains(primaryPrompt, "alpha") || !strings.Contains(primaryPrompt, "beta") {
		t.Errorf("PRIMARY prompt missing the profile list: %q", primaryPrompt)
	}

	fake.push(1, "0")
	waitSent(t, fake, 3*time.Second, "Номер BACKUP")

	fake.push(1, "1")
	got := waitSent(t, fake, 3*time.Second, "настроено")
	if !strings.Contains(got, "primary=alpha") || !strings.Contains(got, "backup=beta") {
		t.Errorf("final message = %q", got)
	}
}
