package botcontrol

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExplainAction_AsksTheDaemonsExplainer(t *testing.T) {
	h := newL7Handler(t)
	var asked []string
	h.Explain = func(_ context.Context, q string) (string, error) {
		asked = append(asked, q)
		return "🔎 " + q + "\nИтог: в туннель", nil
	}
	out, err := h.Handle(context.Background(), Command{Action: ActionExplain, Args: []string{"web.whatsapp.com"}})
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out != "🔎 web.whatsapp.com\nИтог: в туннель" {
		t.Errorf("out = %q, want the explainer's text as it is", out)
	}
	if len(asked) != 1 || asked[0] != "web.whatsapp.com" {
		t.Errorf("the explainer was asked %q, want exactly [web.whatsapp.com]", asked)
	}
}

func TestExplainAction_NeedsExactlyOneQuery(t *testing.T) {
	h := newL7Handler(t)
	h.Explain = func(context.Context, string) (string, error) {
		t.Error("the explainer must not be asked without a usable query")
		return "", nil
	}
	for _, args := range [][]string{nil, {}, {""}, {"  "}, {"a.example", "b.example"}} {
		_, err := h.Handle(context.Background(), Command{Action: ActionExplain, Args: args})
		if err == nil || !strings.Contains(err.Error(), "формат: /why") {
			t.Errorf("args %q: err = %v, want the usage", args, err)
		}
	}
}

func TestExplainAction_AgentWithoutAnExplainerSaysSo(t *testing.T) {
	h := newL7Handler(t)
	_, err := h.Handle(context.Background(), Command{Action: ActionExplain, Args: []string{"a.example"}})
	if err == nil || !strings.Contains(err.Error(), "не умеет объяснять") {
		t.Errorf("err = %v, want the agent to say it cannot explain", err)
	}
}

func TestExplainAction_PassesTheExplainersErrorOn(t *testing.T) {
	h := newL7Handler(t)
	h.Explain = func(context.Context, string) (string, error) {
		return "", errors.New("1.2.3.0/24: нужно имя или один адрес")
	}
	_, err := h.Handle(context.Background(), Command{Action: ActionExplain, Args: []string{"1.2.3.0/24"}})
	if err == nil || !strings.Contains(err.Error(), "нужно имя или один адрес") {
		t.Errorf("err = %v, want the explainer's reason", err)
	}
}

func TestHelpMentionsWhy(t *testing.T) {
	if !strings.Contains(helpText, "/why <router>") {
		t.Error("/help does not list /why")
	}
}

func TestTelegramBot_WhyCommandAsksTheRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 3 * time.Second}
	runBotInBackground(t, bot)

	seen := answerCommands(t, store, "home", []Result{{Output: "🔎 web.whatsapp.com\nИтог: в туннель по списку «domain-list3» → Wireguard0."}})
	fake.push(1, "/why home https://web.whatsapp.com/")
	waitSent(t, fake, 3*time.Second, "Итог: в туннель по списку")
	cmd := <-seen
	if cmd.Action != ActionExplain || len(cmd.Args) != 1 || cmd.Args[0] != "https://web.whatsapp.com/" {
		t.Errorf("the router was asked %+v, want %s with the query as the one argument", cmd, ActionExplain)
	}
}

// replyTo sends text as the operator and returns the bot's next message: unlike
// waitSent it cannot be satisfied by an earlier reply that happens to say the same.
func replyTo(t *testing.T, f *fakeTelegram, text string) string {
	t.Helper()
	before := len(f.sentTexts())
	f.push(1, text)
	return f.waitFor(t, 3*time.Second, "a reply to "+text, func() string {
		if texts := f.sentTexts(); len(texts) > before {
			return texts[len(texts)-1]
		}
		return ""
	})
}

func TestTelegramBot_WhyCommandUsageAndUnknownRouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "home")
	// No agent answers: a query that got through to the router would only time out.
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 200 * time.Millisecond}
	runBotInBackground(t, bot)

	for _, text := range []string{"/why", "/why home", "/why home a.example b.example"} {
		if got := replyTo(t, fake, text); !strings.Contains(got, "формат: /why <роутер>") {
			t.Errorf("%q -> %q, want the usage", text, got)
		}
	}
	if got := replyTo(t, fake, "/why nope a.example"); !strings.Contains(got, "нет такого роутера") {
		t.Errorf("unknown router -> %q", got)
	}
}
