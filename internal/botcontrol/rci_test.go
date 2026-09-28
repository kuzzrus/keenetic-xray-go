package botcontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

const testRCIToken = "4RZVZobf1GUbarwNL0irYboZut05Aqpby8y"

// rciTokenEndpoint answers /rci/show/version only with the right
// X-Ndma-Tkn, the way KeeneticOS 5.2 does.
func rciTokenEndpoint(t *testing.T, want string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(keenetic.RCITokenHeader) != want {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"title":"5.2.1"}`))
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { _, _ = keenetic.UseRCI("", "") })
	return srv.URL
}

// TestRouterHandler_RCIToken: the token lands in config.json, works for
// the probe, turns RCI on, and never comes back in a reply.
func TestRouterHandler_RCIToken(t *testing.T) {
	cfg := config.Default()
	cfg.RCI.URL = rciTokenEndpoint(t, testRCIToken)
	path := filepath.Join(t.TempDir(), "config.json")
	h := &RouterHandler{Config: cfg, ConfigPath: path}
	ctx := context.Background()
	handle := func(action string, args ...string) (string, error) {
		t.Helper()
		out, err := h.Handle(ctx, Command{Action: action, Args: args})
		if strings.Contains(out, testRCIToken) || (err != nil && strings.Contains(err.Error(), testRCIToken)) {
			t.Fatalf("%s leaked the token: %q, %v", action, out, err)
		}
		return out, err
	}

	if _, err := handle(ActionRCIToken, "two words"); err == nil {
		t.Error("a malformed token was accepted")
	}
	if _, err := handle(ActionRCIOn); err == nil || !strings.Contains(err.Error(), "токен") {
		t.Errorf("rci_on without the token: err = %v, want the token hint", err)
	}

	out, err := handle(ActionRCIToken, testRCIToken)
	if err != nil || !strings.Contains(out, "сохранён") || !strings.Contains(out, "RCI отвечает") {
		t.Fatalf("rci_token: %q, %v", out, err)
	}
	if saved, err := config.Load(path); err != nil || saved.RCI.Token != testRCIToken {
		t.Fatalf("saved token = %q, %v", saved.RCI.Token, err)
	}

	if out, err := handle(ActionRCIOn); err != nil || !keenetic.RCIActive() {
		t.Fatalf("rci_on: %q, %v, active=%v", out, err, keenetic.RCIActive())
	}
	if out, _ := handle(ActionRCIShow); !strings.Contains(out, "задан (") || !strings.Contains(out, "отвечает") {
		t.Errorf("rci_show = %q", out)
	}

	if out, err := handle(ActionRCIToken, ""); err != nil || !strings.Contains(out, "удалён") {
		t.Fatalf("clearing the token: %q, %v", out, err)
	}
	if keenetic.RCIActive() {
		t.Error("RCI stayed on with the old token after it was cleared")
	}
	if out, err := handle(ActionRCIOff); err != nil {
		t.Fatalf("rci_off: %q, %v", out, err)
	}
	if saved, _ := config.Load(path); saved.RCI.Token != "" || saved.RCI.Enabled {
		t.Errorf("after clear+off: %+v", saved.RCI)
	}
}

// TestTelegramBot_RCITokenWizard_DeletesTheSecret: every message the
// token dialog reads is deleted from the chat -- a malformed one too --
// and the token reaches the router as the command argument without the
// bot ever repeating it.
func TestTelegramBot_RCITokenWizard_DeletesTheSecret(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	msgID := fake.lastSent(t).MessageID
	fake.pushCallback(1, msgID, "rcim:r1")
	fake.waitForEditContaining(t, 3*time.Second, "🔌 RCI r1")
	fake.pushCallback(1, msgID, "rcitok:r1")
	waitSent(t, fake, 3*time.Second, "Токен RCI для r1")

	fake.pushMessage(1, 501, "not a token")
	waitSent(t, fake, 3*time.Second, "не похоже на токен")

	fake.pushMessage(1, 502, testRCIToken)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cmd, _ := store.Dequeue("r1"); cmd != nil {
			if cmd.Action != ActionRCIToken || len(cmd.Args) != 1 || cmd.Args[0] != testRCIToken {
				t.Errorf("queued %q %q, want rci_token with the token", cmd.Action, cmd.Args)
			}
			_ = store.RecordResult("r1", Result{CommandID: cmd.ID, Output: "🔑 токен RCI сохранён на роутере"})
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	reply := waitSent(t, fake, 3*time.Second, "токен RCI сохранён")
	if strings.Contains(reply, "не получилось") {
		t.Errorf("reply warns about a failed delete although it worked: %q", reply)
	}
	for _, id := range []int{501, 502} {
		if !slices.Contains(fake.deletedIDs(), id) {
			t.Errorf("message %d was not deleted (deleted: %v)", id, fake.deletedIDs())
		}
	}
	for _, s := range fake.sentTexts() {
		if strings.Contains(s, testRCIToken) {
			t.Errorf("the bot repeated the token: %q", s)
		}
	}
}

func TestTelegramBot_RCITokenWizard_WarnsWhenItCannotDelete(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	fake.deleteFails = true
	store := newBotStore(t)
	mustRegister(t, store, "r1")
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second}
	runBotInBackground(t, bot)
	fakeAgent(t, store, "r1", func(string) string { return "🔑 токен RCI сохранён на роутере" })

	fake.push(1, "/menu")
	fake.waitForReply(t, 3*time.Second)
	fake.pushCallback(1, fake.lastSent(t).MessageID, "rcitok:r1")
	waitSent(t, fake, 3*time.Second, "Токен RCI для r1")
	fake.pushMessage(1, 601, testRCIToken)
	waitSent(t, fake, 3*time.Second, "удали его сам")
}
