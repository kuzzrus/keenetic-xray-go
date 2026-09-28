package botcontrol

import (
	"context"
	"fmt"
	"time"
)

// DefaultDiagTimeout is how long the bot waits for a router's diag
// bundle: longer than DefaultResultTimeout, since the bundle runs a
// dozen ndmc reads and probes on the router (h.diag allows it 45 s).
const DefaultDiagTimeout = 75 * time.Second

// sendDiagFile runs diag on routerID and sends the whole bundle back as
// a .txt document. As a message it was cut at Telegram's 4096
// characters -- losing the daemon-log tail the report exists for. Blocks
// until the report arrives, so callers run it on its own goroutine: the
// update loop handles one update at a time.
func (b *TelegramBot) sendDiagFile(ctx context.Context, chatID int64, routerID string) {
	if !b.Store.HasRouter(routerID) {
		b.sendMessage(ctx, chatID, fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID))
		return
	}
	cmdID, err := b.Store.Enqueue(routerID, ActionDiag, nil)
	if err != nil {
		b.sendMessage(ctx, chatID, "не удалось поставить команду в очередь: "+err.Error())
		return
	}
	if !routerOnline(b.Store.LastPollAt(routerID)) {
		b.sendMessage(ctx, chatID, routerID+": "+queuedNote(b.Store.LastPollAt(routerID)))
		return
	}
	b.sendMessage(ctx, chatID, "🧾 собираю диагностику "+routerID+" — это до минуты…")
	timeout := b.DiagTimeout
	if timeout <= 0 {
		timeout = DefaultDiagTimeout
	}
	result, ok := b.Store.AwaitResult(ctx, routerID, cmdID, timeout)
	switch {
	case !ok:
		b.sendMessage(ctx, chatID, routerID+": ⌛ отчёт не пришёл вовремя — повтори 🧾 Диагностика чуть позже")
		return
	case result.Err != "":
		b.sendMessage(ctx, chatID, routerID+": ошибка diag: "+result.Err)
		return
	}
	name := fmt.Sprintf("diag-%s-%s.txt", routerID, time.Now().Format("20060102-1504"))
	caption := "🧾 диагностика " + routerID + " — секреты вырезаны, можно пересылать"
	if err := b.sendDocument(ctx, chatID, name, []byte(result.Output), caption); err != nil {
		b.logger().Printf("telegram: %v", err)
		// Better a cut report than none.
		b.sendMessage(ctx, chatID, routerID+": файл не отправился ("+err.Error()+"), начало отчёта:\n\n"+result.Output)
	}
}
