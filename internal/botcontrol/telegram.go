package botcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// telegramAPIBase is the default Bot API base URL; overridable per-bot
// (TelegramBot.APIBase) so tests can point at a local fake server instead
// of needing a real Telegram token and network access.
const telegramAPIBase = "https://api.telegram.org"

// DefaultResultTimeout is how long the bot waits for a router to answer
// a queued command before telling the chat to check back later, rather
// than blocking indefinitely on a router that's offline.
const DefaultResultTimeout = 20 * time.Second

// TelegramBot long-polls Telegram's getUpdates endpoint, authorizes
// senders against an allowlist of chat IDs, parses simple commands, and
// drives them through a Store -- enqueueing on behalf of a named router
// and (best-effort, within ResultTimeout) waiting for that router to
// answer before replying, so an online router feels synchronous even
// though the wire protocol underneath is poll-based.
type TelegramBot struct {
	Token         string
	AllowedChats  map[int64]bool
	Store         *Store        // router registry + command queues
	Fingerprint   string        // control-server cert SHA-256, echoed in `agent configure` hints
	ServerURL     string        // public URL routers dial, e.g. https://vps.example.com:8443; "" -> a placeholder in hints
	APIBase       string        // "" -> telegramAPIBase
	ResultTimeout time.Duration // 0 -> DefaultResultTimeout
	Logger        *log.Logger   // nil -> log.Default()

	client   *http.Client
	wizardMu sync.Mutex
	wizards  map[int64]*wizState // per-chat multi-step dialog state (e.g. /add_router)
}

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

type tgMessage struct {
	MessageID int    `json:"message_id"`
	Chat      tgChat `json:"chat"`
	Text      string `json:"text"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgGetUpdatesResponse struct {
	OK     bool       `json:"ok"`
	Result []tgUpdate `json:"result"`
}

// inlineKeyboard is Telegram's inline_keyboard reply markup: rows of
// buttons, each carrying opaque callback_data the bot routes on.
type inlineKeyboard struct {
	InlineKeyboard [][]inlineButton `json:"inline_keyboard"`
}

type inlineButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// Run long-polls Telegram for updates and handles each until ctx is
// cancelled, at which point it returns ctx.Err().
func (b *TelegramBot) Run(ctx context.Context) error {
	if b.client == nil {
		b.client = &http.Client{Timeout: 65 * time.Second} // > the 50s long-poll timeout used below
	}
	b.wizards = make(map[int64]*wizState)
	if err := b.setMyCommands(ctx); err != nil && ctx.Err() == nil {
		b.logger().Printf("telegram: setMyCommands: %s", b.scrubToken(err))
	}

	var offset int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		updates, err := b.getUpdates(ctx, offset)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			b.logger().Printf("telegram: getUpdates: %s", b.scrubToken(err))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}

		for _, u := range updates {
			if u.UpdateID >= offset {
				offset = u.UpdateID + 1
			}
			switch {
			case u.CallbackQuery != nil:
				b.handleCallback(ctx, *u.CallbackQuery)
			case u.Message != nil:
				b.handleMessage(ctx, *u.Message)
			}
		}
	}
}

func (b *TelegramBot) logger() *log.Logger {
	if b.Logger != nil {
		return b.Logger
	}
	return log.Default()
}

// scrubToken renders err for logging with the bot token redacted.
// Transport failures from b.client are *url.Error values whose message
// embeds the request URL, and the Telegram API carries the token in the
// URL path (/bot<token>/...), so logging such an error verbatim would
// write the token to stderr/syslog.
func (b *TelegramBot) scrubToken(err error) string {
	msg := err.Error()
	if b.Token != "" {
		msg = strings.ReplaceAll(msg, b.Token, "<redacted>")
	}
	return msg
}

func (b *TelegramBot) apiBase() string {
	if b.APIBase != "" {
		return b.APIBase
	}
	return telegramAPIBase
}

func (b *TelegramBot) resultTimeout() time.Duration {
	if b.ResultTimeout > 0 {
		return b.ResultTimeout
	}
	return DefaultResultTimeout
}

func (b *TelegramBot) getUpdates(ctx context.Context, offset int64) ([]tgUpdate, error) {
	url := fmt.Sprintf("%s/bot%s/getUpdates?timeout=50&offset=%d", b.apiBase(), b.Token, offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getUpdates: unexpected status %s", resp.Status)
	}
	var out tgGetUpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding getUpdates response: %w", err)
	}
	if !out.OK {
		return nil, fmt.Errorf("getUpdates: response ok=false")
	}
	return out.Result, nil
}

// apiPost calls one Bot API method with a JSON payload and returns the
// raw response body. A non-2xx status is an error; the caller decides
// whether that is worth logging.
func (b *TelegramBot) apiPost(ctx context.Context, method string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/bot%s/%s", b.apiBase(), b.Token, method)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, fmt.Errorf("%s: unexpected status %s", method, resp.Status)
	}
	return data, nil
}

// sendMessage sends plain text with no keyboard, best-effort.
func (b *TelegramBot) sendMessage(ctx context.Context, chatID int64, text string) {
	b.sendMessageKB(ctx, chatID, text, inlineKeyboard{})
}

// sendMessageKB sends text with an optional inline keyboard and returns
// the new message's ID (0 if the send failed).
func (b *TelegramBot) sendMessageKB(ctx context.Context, chatID int64, text string, kb inlineKeyboard) int {
	payload := map[string]any{"chat_id": chatID, "text": text}
	if len(kb.InlineKeyboard) > 0 {
		payload["reply_markup"] = kb
	}
	data, err := b.apiPost(ctx, "sendMessage", payload)
	if err != nil {
		b.logger().Printf("telegram: sendMessage: %s", b.scrubToken(err))
		return 0
	}
	var out struct {
		Result struct {
			MessageID int `json:"message_id"`
		} `json:"result"`
	}
	_ = json.Unmarshal(data, &out)
	return out.Result.MessageID
}

// editMessageText replaces an existing message's text and keyboard in
// place. Returns false if the edit failed (e.g. the message is too old);
// "message is not modified" counts as success.
func (b *TelegramBot) editMessageText(ctx context.Context, chatID int64, messageID int, text string, kb inlineKeyboard) bool {
	if messageID == 0 {
		return false
	}
	payload := map[string]any{"chat_id": chatID, "message_id": messageID, "text": text}
	if len(kb.InlineKeyboard) > 0 {
		payload["reply_markup"] = kb
	}
	data, err := b.apiPost(ctx, "editMessageText", payload)
	if err != nil {
		if bytes.Contains(data, []byte("message is not modified")) {
			return true
		}
		b.logger().Printf("telegram: editMessageText: %s", b.scrubToken(err))
		return false
	}
	return true
}

// answerCallback acknowledges a callback query so Telegram stops showing
// the button's loading spinner. Best-effort.
func (b *TelegramBot) answerCallback(ctx context.Context, callbackID, text string) {
	if callbackID == "" {
		return
	}
	payload := map[string]any{"callback_query_id": callbackID}
	if text != "" {
		payload["text"] = text
	}
	if _, err := b.apiPost(ctx, "answerCallbackQuery", payload); err != nil {
		b.logger().Printf("telegram: answerCallbackQuery: %s", b.scrubToken(err))
	}
}

// setMyCommands registers the slash commands Telegram shows in its menu.
func (b *TelegramBot) setMyCommands(ctx context.Context) error {
	payload := map[string]any{"commands": []map[string]string{
		{"command": "menu", "description": "меню управления"},
		{"command": "routers", "description": "список роутеров"},
		{"command": "add_router", "description": "добавить роутер"},
		{"command": "help", "description": "справка"},
	}}
	_, err := b.apiPost(ctx, "setMyCommands", payload)
	return err
}

func (b *TelegramBot) handleMessage(ctx context.Context, msg tgMessage) {
	if !b.AllowedChats[msg.Chat.ID] {
		return // silently ignore -- do not reveal that this bot exists to unlisted chats
	}
	text := strings.TrimSpace(msg.Text)
	if b.handleWizardText(ctx, msg.Chat.ID, text) {
		return
	}
	if text == "/start" || text == "/menu" {
		b.sendMainMenu(ctx, msg.Chat.ID)
		return
	}
	if reply := b.dispatch(ctx, text); reply != "" {
		b.sendMessage(ctx, msg.Chat.ID, reply)
	}
}

const helpText = `/menu — меню с кнопками (проще всего)
/routers — список роутеров
/add_router <id> [имя] — зарегистрировать роутер, получить строку agent configure
/remove_router <id> — убрать роутер из реестра

Дальше первым аргументом идёт id роутера:
/status <router>
/switch <router> primary|backup
/profile_list <router>
/sub_seturl <router> <url>
/sub_refresh <router>
/sub_list <router>
/sub_setprimary <router> <index>
/sub_setbackup <router> <index>`

func (b *TelegramBot) dispatch(ctx context.Context, text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	cmd, args := fields[0], fields[1:]

	switch cmd {
	case "/help":
		return helpText
	case "/routers":
		return b.listRouters()
	case "/add_router":
		return b.dispatchAddRouter(args)
	case "/remove_router":
		return b.dispatchRemoveRouter(args)
	case "/status":
		return b.runRouterCommand(ctx, args, ActionStatus, nil)
	case "/switch":
		return b.dispatchSwitch(ctx, args)
	case "/profile_list":
		return b.runRouterCommand(ctx, args, ActionProfileList, nil)
	case "/sub_seturl":
		return b.dispatchSubSetURL(ctx, args)
	case "/sub_refresh":
		return b.runRouterCommand(ctx, args, ActionSubRefresh, nil)
	case "/sub_list":
		return b.runRouterCommand(ctx, args, ActionSubList, nil)
	case "/sub_setprimary":
		return b.dispatchSubSetRole(ctx, args, ActionSubSetPrimary)
	case "/sub_setbackup":
		return b.dispatchSubSetRole(ctx, args, ActionSubSetBackup)
	default:
		return "unknown command; send /help"
	}
}

func (b *TelegramBot) listRouters() string {
	routers := b.Store.Routers()
	if len(routers) == 0 {
		return "Роутеров пока нет. Добавьте: /add_router <id> [имя]"
	}
	var sb strings.Builder
	sb.WriteString("Роутеры:\n")
	for _, r := range routers {
		line := r.ID
		if r.Name != "" {
			line += " (" + r.Name + ")"
		}
		if r.LastPollAt.IsZero() {
			line += " — ещё не подключался"
		} else {
			line += " — последний poll " + r.LastPollAt.Format("2006-01-02 15:04:05")
		}
		if r.Pending > 0 {
			line += fmt.Sprintf(", в очереди: %d", r.Pending)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (b *TelegramBot) dispatchAddRouter(args []string) string {
	if len(args) < 1 || args[0] == "" {
		return "формат: /add_router <id> [имя]"
	}
	id := args[0]
	if !ValidRouterID(id) {
		return "id роутера: латиница, цифры, _ или -, до 64 символов"
	}
	name := strings.Join(args[1:], " ")
	token, err := b.Store.AddRouter(id, name)
	if err != nil {
		return fmt.Sprintf("не добавлено: %v", err)
	}
	return b.agentConfigureHint(id, token)
}

func (b *TelegramBot) dispatchRemoveRouter(args []string) string {
	if len(args) != 1 || args[0] == "" {
		return "формат: /remove_router <id>"
	}
	if err := b.Store.RemoveRouter(args[0]); err != nil {
		return fmt.Sprintf("не удалено: %v", err)
	}
	return fmt.Sprintf("роутер %q убран из реестра. Агент на самом роутере не трогается.", args[0])
}

// agentConfigureLines is the two-command block to run on a router to bind
// it to this control server.
func (b *TelegramBot) agentConfigureLines(id, token string) string {
	url := b.ServerURL
	if url == "" {
		url = "https://<адрес-сервера>:8443"
	}
	return fmt.Sprintf("keenetic-xray agent configure %s %s %s %s\nkeenetic-xray agent enable",
		url, id, b.Fingerprint, token)
}

// agentConfigureHint is what the bot replies with just after a router is
// registered.
func (b *TelegramBot) agentConfigureHint(id, token string) string {
	return fmt.Sprintf("роутер %q добавлен.\n\nНа роутере выполните:\n%s", id, b.agentConfigureLines(id, token))
}

func (b *TelegramBot) dispatchSwitch(ctx context.Context, args []string) string {
	if len(args) != 2 {
		return "usage: /switch <router> primary|backup"
	}
	switch args[1] {
	case "primary":
		return b.runRouterCommand(ctx, args[:1], ActionSwitchPrimary, nil)
	case "backup":
		return b.runRouterCommand(ctx, args[:1], ActionSwitchBackup, nil)
	default:
		return "usage: /switch <router> primary|backup"
	}
}

func (b *TelegramBot) dispatchSubSetURL(ctx context.Context, args []string) string {
	if len(args) < 2 {
		return "usage: /sub_seturl <router> <url>"
	}
	return b.runRouterCommand(ctx, args[:1], ActionSubSetURL, []string{args[1]})
}

func (b *TelegramBot) dispatchSubSetRole(ctx context.Context, args []string, action string) string {
	if len(args) != 2 {
		return "usage: /sub_setprimary|/sub_setbackup <router> <index>"
	}
	if _, err := strconv.Atoi(args[1]); err != nil {
		return fmt.Sprintf("invalid index %q", args[1])
	}
	return b.runRouterCommand(ctx, args[:1], action, []string{args[1]})
}

// runRouterCommand enqueues action for the router named in args[0], then
// waits up to resultTimeout for that router to answer.
func (b *TelegramBot) runRouterCommand(ctx context.Context, args []string, action string, cmdArgs []string) string {
	if len(args) < 1 || args[0] == "" {
		return "usage: missing router ID"
	}
	routerID := args[0]
	if !b.Store.HasRouter(routerID) {
		return fmt.Sprintf("unknown router %q; send /routers to list registered routers", routerID)
	}

	id, err := b.Store.Enqueue(routerID, action, cmdArgs)
	if err != nil {
		return fmt.Sprintf("failed to queue command: %v", err)
	}

	result, ok := b.Store.AwaitResult(ctx, routerID, id, b.resultTimeout())
	if !ok {
		return fmt.Sprintf("command queued (id %s) but %s hasn't answered yet -- it will run on its next poll", id, routerID)
	}
	if result.Err != "" {
		return fmt.Sprintf("%s: error: %s", routerID, result.Err)
	}
	return fmt.Sprintf("%s: %s", routerID, result.Output)
}
