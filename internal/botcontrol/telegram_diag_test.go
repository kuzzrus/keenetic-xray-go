package botcontrol

import (
	"strings"
	"testing"
	"time"
)

func (f *fakeTelegram) waitDocument(t *testing.T, timeout time.Duration) sentDocument {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if n := len(f.documents); n > 0 {
			d := f.documents[n-1]
			f.mu.Unlock()
			return d
		}
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no document was sent")
	return sentDocument{}
}

// TestTelegramBot_DiagArrivesAsAFile: the diag bundle is far longer than
// a Telegram message, which cut it at 4096 characters -- the daemon-log
// tail at its end was exactly what got lost. It now arrives whole, as a
// .txt, from the router-card button and from /diag.
func TestTelegramBot_DiagArrivesAsAFile(t *testing.T) {
	report := "==== keenetic-xray diag ====\n" + strings.Repeat("line of the bundle\n", 600) + "==== end ====\n"
	for _, trigger := range []string{"button", "command"} {
		t.Run(trigger, func(t *testing.T) {
			srv, fake := newFakeTelegram(t)
			store := newBotStore(t)
			mustRegister(t, store, "r1")
			bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: store, APIBase: srv.URL, ResultTimeout: 2 * time.Second, DiagTimeout: 3 * time.Second}
			runBotInBackground(t, bot)
			fakeAgent(t, store, "r1", func(action string) string {
				if action != ActionDiag {
					return "?"
				}
				return report
			})

			if trigger == "button" {
				fake.push(1, "/menu")
				fake.waitForReply(t, 3*time.Second)
				fake.pushCallback(1, fake.lastSent(t).MessageID, "diagf:r1")
			} else {
				fake.push(1, "/diag r1")
			}
			doc := fake.waitDocument(t, 5*time.Second)
			if doc.Content != report {
				t.Errorf("document has %d bytes, want the whole %d-byte report", len(doc.Content), len(report))
			}
			if !strings.HasPrefix(doc.Name, "diag-r1-") || !strings.HasSuffix(doc.Name, ".txt") {
				t.Errorf("document name = %q", doc.Name)
			}
			if doc.ChatID != 1 || !strings.Contains(doc.Caption, "диагностика r1") {
				t.Errorf("document = chat %d, caption %q", doc.ChatID, doc.Caption)
			}
		})
	}
}

func TestTelegramBot_DiagNeedsARouter(t *testing.T) {
	srv, fake := newFakeTelegram(t)
	bot := &TelegramBot{Token: "t", AllowedChats: map[int64]bool{1: true}, Store: newBotStore(t), APIBase: srv.URL}
	runBotInBackground(t, bot)
	fake.push(1, "/diag")
	waitSent(t, fake, 3*time.Second, "формат: /diag <роутер>")
	fake.push(1, "/diag nope")
	waitSent(t, fake, 3*time.Second, "нет такого роутера")
}
