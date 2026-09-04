package botcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
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
	ServerURL     string        // public URL routers dial, e.g. https://vps.example.com:8443; "" -> derived from ListenAddr + the detected outbound IP
	ListenAddr    string        // the server's own listen address, used to derive a URL when ServerURL is unset
	APIBase       string        // "" -> telegramAPIBase
	ResultTimeout time.Duration // 0 -> DefaultResultTimeout
	Logger        *log.Logger   // nil -> log.Default()

	// SelfUpdatePath, if set, is the trigger file the "Обновить сервер"
	// button touches -- a systemd .path unit watches it and runs the
	// root self-update. Empty -> the button reports it isn't configured.
	SelfUpdatePath string

	client     *http.Client
	clientOnce sync.Once
	wizardMu   sync.Mutex
	wizards    map[int64]*wizState // per-chat multi-step dialog state (e.g. /add_router)

	flapMu sync.Mutex
	flap   map[string]*flapWindow // per-router failover-notification rate state
}

// Flap-mute thresholds: if a router produces flapThreshold "failover"
// events within flapWindowDur, further ones are held for flapMuteDur.
// "recovered"/"daemon_start" events always get through and clear the mute.
const (
	flapWindowDur = 15 * time.Minute
	flapThreshold = 4
	flapMuteDur   = 30 * time.Minute
)

type flapWindow struct {
	events     []time.Time
	mutedUntil time.Time
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
	b.initClient()
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

// initClient sets b.client once. Both Run and NotifyEvent (which can be
// called from a server request goroutine before Run has started) go
// through here so the two never race on the field.
func (b *TelegramBot) initClient() {
	b.clientOnce.Do(func() {
		if b.client == nil {
			b.client = &http.Client{Timeout: 65 * time.Second} // > the 50s long-poll timeout
		}
	})
}

// notify DMs every allowed chat one line about routerID, prefixed with
// the router's name. Best-effort: each send is logged on failure (inside
// sendMessage) but never retried. Safe to call from a server request
// goroutine -- initClient is sync.Once-guarded.
func (b *TelegramBot) notify(routerID, body string) {
	b.initClient()
	label := routerID
	if name := b.Store.NameFor(routerID); name != "" {
		label = name + " (" + routerID + ")"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for chatID := range b.AllowedChats {
		b.sendMessage(ctx, chatID, "🔔 "+label+"\n"+body)
	}
}

// NotifyEvent DMs every allowed chat about an unsolicited router event
// (a failover switch, the daemon starting). Called from the control
// server's /agent/event handler. "failover" events are rate-limited per
// router so a flapping primary can't bury the chat; "recovered" and
// "daemon_start" always get through and reset that limiter.
func (b *TelegramBot) NotifyEvent(routerID string, ev Event) {
	if ev.Kind == "recovered" || ev.Kind == "daemon_start" {
		b.clearFlap(routerID)
		b.notify(routerID, ev.Text)
		return
	}
	if ev.Kind == "failover" {
		drop, notice := b.flapCheck(routerID)
		switch {
		case drop:
			return
		case notice != "":
			b.notify(routerID, notice)
		default:
			b.notify(routerID, ev.Text)
		}
		return
	}
	b.notify(routerID, ev.Text)
}

// flapCheck records a failover event for routerID and decides what to do
// with it: drop it (already muted), replace it with a one-time mute
// notice (threshold just crossed), or let it through (notice == "").
func (b *TelegramBot) flapCheck(routerID string) (drop bool, notice string) {
	now := time.Now()
	b.flapMu.Lock()
	defer b.flapMu.Unlock()
	if b.flap == nil {
		b.flap = map[string]*flapWindow{}
	}
	w := b.flap[routerID]
	if w == nil {
		w = &flapWindow{}
		b.flap[routerID] = w
	}
	if now.Before(w.mutedUntil) {
		return true, ""
	}

	cutoff := now.Add(-flapWindowDur)
	kept := w.events[:0]
	for _, t := range w.events {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	w.events = append(kept, now)

	if len(w.events) >= flapThreshold {
		w.mutedUntil = now.Add(flapMuteDur)
		w.events = nil
		return false, "⚠️ нестабильно — частые переключения primary↔backup. Уведомления о failover приглушены на " + shortDur(flapMuteDur) + "."
	}
	return false, ""
}

func (b *TelegramBot) clearFlap(routerID string) {
	b.flapMu.Lock()
	if b.flap != nil {
		delete(b.flap, routerID)
	}
	b.flapMu.Unlock()
}

// NotifyOffline DMs every allowed chat when a router stops polling, and
// again when it resumes. Called by OfflineWatcher.
func (b *TelegramBot) NotifyOffline(routerID string, online bool) {
	if online {
		b.notify(routerID, "🟢 снова на связи")
		return
	}
	b.notify(routerID, "🔴 не выходит на связь")
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

// sendMessageKB sends plain text with an optional inline keyboard and
// returns the new message's ID (0 if the send failed).
func (b *TelegramBot) sendMessageKB(ctx context.Context, chatID int64, text string, kb inlineKeyboard) int {
	return b.send(ctx, chatID, text, kb, "")
}

// sendMessageHTML sends text parsed as Telegram HTML -- used for <pre>
// blocks so the client shows a per-block copy button.
func (b *TelegramBot) sendMessageHTML(ctx context.Context, chatID int64, text string, kb inlineKeyboard) int {
	return b.send(ctx, chatID, text, kb, "HTML")
}

func (b *TelegramBot) send(ctx context.Context, chatID int64, text string, kb inlineKeyboard, parseMode string) int {
	payload := map[string]any{"chat_id": chatID, "text": text}
	if len(kb.InlineKeyboard) > 0 {
		payload["reply_markup"] = kb
	}
	if parseMode != "" {
		payload["parse_mode"] = parseMode
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

// htmlPre wraps s in a Telegram <pre> block (monospace, own copy button),
// escaping the three characters that matter for HTML parse mode.
func htmlPre(s string) string {
	esc := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	return "<pre>" + esc + "</pre>"
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
	if fields := strings.Fields(text); len(fields) > 0 {
		switch normalizeCommand(fields[0]) {
		case "/start", "/menu":
			b.sendMainMenu(ctx, msg.Chat.ID)
			return
		case "/add_router":
			b.cmdAddRouter(ctx, msg.Chat.ID, fields[1:])
			return
		}
	}
	if reply := b.dispatch(ctx, text); reply != "" {
		b.sendMessage(ctx, msg.Chat.ID, reply)
	}
}

const helpText = `/menu — меню с кнопками (проще всего)
/routers — список роутеров
/add_router <id> [имя] — зарегистрировать роутер, получить строку agent configure
/remove_router <id> — убрать роутер из реестра
/rename <id> <имя> — переименовать роутер
/status — обзор всех роутеров (онлайн/оффлайн, очередь)

Дальше первым аргументом идёт id роутера:
/status <router>
/doctor <router>
/switch <router> primary|backup
/profile_list <router>
/sub_seturl <router> <url>
/sub_refresh <router>
/sub_list <router>
/sub_setprimary <router> <index>
/sub_setbackup <router> <index>
/set_primary_source <router> <vless://…|url> [селектор]
/set_backup_source <router> <vless://…|url> [селектор]
/proxy0 <router> [show|on|off]
/restart <router> — перезапустить демон
/ensure_core <router> — доустановить ядро xray
/update <router> — обновить агент (переустановить .ipk)
/failover <router> show — текущие пороги health-check
/failover <router> set <ключ> <значение> — подстроить их (перезапустит демон)`

func (b *TelegramBot) dispatch(ctx context.Context, text string) string {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	cmd, args := normalizeCommand(fields[0]), fields[1:]

	switch cmd {
	case "/help":
		return helpText
	case "/routers":
		return b.listRouters()
	case "/remove_router":
		return b.dispatchRemoveRouter(args)
	case "/rename":
		return b.dispatchRename(args)
	case "/status":
		if len(args) == 0 {
			return b.listRouters() // no router named -> overview of all
		}
		return b.runRouterCommand(ctx, args, ActionStatus, nil)
	case "/doctor":
		return b.runRouterCommand(ctx, args, ActionDoctor, nil)
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
	case "/set_primary_source":
		return b.dispatchSlotSource(ctx, args, ActionSetPrimarySource)
	case "/set_backup_source":
		return b.dispatchSlotSource(ctx, args, ActionSetBackupSource)
	case "/proxy0":
		return b.dispatchProxy0(ctx, args)
	case "/restart":
		return b.runRouterCommand(ctx, args, ActionDaemonRestart, nil)
	case "/ensure_core":
		return b.runRouterCommand(ctx, args, ActionEnsureCore, nil)
	case "/update":
		return b.runRouterCommand(ctx, args, ActionSelfUpdate, nil)
	case "/failover":
		return b.dispatchFailover(ctx, args)
	default:
		return "неизвестная команда. Откройте /menu или /help"
	}
}

// dispatchFailover routes /failover <router> show|set <key> <value>.
func (b *TelegramBot) dispatchFailover(ctx context.Context, args []string) string {
	usage := "формат: /failover <роутер> show | /failover <роутер> set <ключ> <значение>"
	if len(args) < 2 {
		return usage
	}
	routerID := args[:1]
	switch args[1] {
	case "show":
		return b.runRouterCommand(ctx, routerID, ActionFailoverShow, nil)
	case "set":
		if len(args) != 4 {
			return usage
		}
		return b.runRouterCommand(ctx, routerID, ActionFailoverSet, []string{args[2], args[3]})
	default:
		return usage
	}
}

// dispatchProxy0 routes /proxy0 <router> [show|on|off]; default is show.
func (b *TelegramBot) dispatchProxy0(ctx context.Context, args []string) string {
	if len(args) < 1 {
		return "формат: /proxy0 <роутер> [show|on|off]"
	}
	action := ActionProxy0Show
	if len(args) >= 2 {
		switch args[1] {
		case "show":
		case "on":
			action = ActionProxy0On
		case "off":
			action = ActionProxy0Off
		default:
			return "формат: /proxy0 <роутер> [show|on|off]"
		}
	}
	return b.runRouterCommand(ctx, args[:1], action, nil)
}

// normalizeCommand strips the "@botname" suffix Telegram appends to
// commands sent in group chats (e.g. "/menu@my_bot" -> "/menu").
func normalizeCommand(cmd string) string {
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		return cmd[:i]
	}
	return cmd
}

func (b *TelegramBot) listRouters() string {
	routers := b.Store.Routers()
	if len(routers) == 0 {
		return "Роутеров пока нет. Добавьте: /add_router <id> [имя]"
	}
	var sb strings.Builder
	sb.WriteString("Роутеры:\n")
	for _, r := range routers {
		line := routerDot(r.LastPollAt) + " " + r.ID
		if r.Name != "" {
			line += " (" + r.Name + ")"
		}
		switch {
		case r.LastPollAt.IsZero():
			line += " — ещё не подключался"
		case routerOnline(r.LastPollAt):
			line += " — на связи, poll " + shortDur(time.Since(r.LastPollAt)) + " назад"
		default:
			line += " — молчит с " + r.LastPollAt.Format("2006-01-02 15:04")
		}
		if r.Pending > 0 {
			line += fmt.Sprintf(", в очереди: %d", r.Pending)
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return strings.TrimRight(sb.String(), "\n")
}

// cmdAddRouter registers a router and sends back a short line plus the
// two agent-configure commands in their own copyable <pre> block. It
// sends directly (rather than returning a string) so the command block
// can carry HTML parse mode.
func (b *TelegramBot) cmdAddRouter(ctx context.Context, chatID int64, args []string) {
	if len(args) < 1 || args[0] == "" {
		b.sendMessage(ctx, chatID, "формат: /add_router <id> [имя]")
		return
	}
	id := args[0]
	if !ValidRouterID(id) {
		b.sendMessage(ctx, chatID, "id роутера: латиница, цифры, _ или -, до 64 символов")
		return
	}
	token, err := b.Store.AddRouter(id, strings.Join(args[1:], " "))
	if err != nil {
		b.sendMessage(ctx, chatID, fmt.Sprintf("не добавлено: %v", err))
		return
	}
	b.sendConfigureHint(ctx, chatID, id, token)
}

// sendConfigureHint posts the "run this on the router" block: one line of
// context, then the commands alone in a <pre> block so Telegram shows a
// copy button on the block itself.
func (b *TelegramBot) sendConfigureHint(ctx context.Context, chatID int64, id, token string) {
	b.sendMessageHTML(ctx, chatID,
		fmt.Sprintf("Роутер %s — выполните на нём:\n%s", id, htmlPre(b.agentConfigureLines(id, token))),
		routerCardKB(id))
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

func (b *TelegramBot) dispatchRename(args []string) string {
	if len(args) < 1 || args[0] == "" {
		return "формат: /rename <id> <новое имя>"
	}
	name := strings.TrimSpace(strings.Join(args[1:], " "))
	if name == "" {
		name = args[0]
	}
	if err := b.Store.RenameRouter(args[0], name); err != nil {
		return fmt.Sprintf("не переименовано: %v", err)
	}
	return "✅ теперь: " + name
}

// agentConfigureLines is the two-command block to run on a router to bind
// it to this control server.
func (b *TelegramBot) agentConfigureLines(id, token string) string {
	return fmt.Sprintf("keenetic-xray agent configure %s %s %s %s\nkeenetic-xray agent enable",
		b.serverURL(), id, b.Fingerprint, token)
}

// serverURL is what routers should dial. ServerURL (config public_url)
// wins; otherwise it's the ListenAddr port plus, when the listen host is
// a wildcard, the machine's outbound IP -- a placeholder if that can't be
// determined.
func (b *TelegramBot) serverURL() string {
	if b.ServerURL != "" {
		return b.ServerURL
	}
	host, port := "", "8443"
	if h, p, err := net.SplitHostPort(b.ListenAddr); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(b.ListenAddr, ":") {
		port = strings.TrimPrefix(b.ListenAddr, ":")
	}
	switch host {
	case "", "0.0.0.0", "::":
		if ip := detectOutboundIP(); ip != "" {
			host = ip
		} else {
			host = "<адрес-сервера>"
		}
	}
	return "https://" + net.JoinHostPort(host, port)
}

// detectOutboundIP returns the local address the kernel would use to
// reach the public internet. The UDP "connect" sends nothing; it only
// forces a route lookup and a socket bind, so it works offline-ish and
// returns "" only when there is no route at all.
func detectOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}

func (b *TelegramBot) dispatchSwitch(ctx context.Context, args []string) string {
	if len(args) != 2 {
		return "формат: /switch <роутер> primary|backup"
	}
	switch args[1] {
	case "primary":
		return b.runRouterCommand(ctx, args[:1], ActionSwitchPrimary, nil)
	case "backup":
		return b.runRouterCommand(ctx, args[:1], ActionSwitchBackup, nil)
	default:
		return "формат: /switch <роутер> primary|backup"
	}
}

func (b *TelegramBot) dispatchSubSetURL(ctx context.Context, args []string) string {
	if len(args) < 2 {
		return "формат: /sub_seturl <роутер> <url>"
	}
	return b.runRouterCommand(ctx, args[:1], ActionSubSetURL, []string{args[1]})
}

func (b *TelegramBot) dispatchSubSetRole(ctx context.Context, args []string, action string) string {
	if len(args) != 2 {
		return "формат: /sub_setprimary|/sub_setbackup <роутер> <индекс>"
	}
	if _, err := strconv.Atoi(args[1]); err != nil {
		return fmt.Sprintf("неверный индекс %q", args[1])
	}
	return b.runRouterCommand(ctx, args[:1], action, []string{args[1]})
}

// dispatchSlotSource handles /set_primary_source|/set_backup_source
// <router> <vless|url> [selector]. The source value is redacted in the
// router's reply.
func (b *TelegramBot) dispatchSlotSource(ctx context.Context, args []string, action string) string {
	if len(args) < 2 {
		return "формат: /set_primary_source|/set_backup_source <роутер> <vless://…|http(s)://…> [селектор]"
	}
	cmdArgs := []string{args[1]}
	if len(args) > 2 {
		cmdArgs = append(cmdArgs, strings.Join(args[2:], " "))
	}
	return b.runRouterCommand(ctx, args[:1], action, cmdArgs)
}

// runRouterCommand enqueues action for the router named in args[0], then
// waits up to resultTimeout for that router to answer.
func (b *TelegramBot) runRouterCommand(ctx context.Context, args []string, action string, cmdArgs []string) string {
	if len(args) < 1 || args[0] == "" {
		return "формат: не указан id роутера"
	}
	routerID := args[0]
	if !b.Store.HasRouter(routerID) {
		return fmt.Sprintf("нет такого роутера %q. Список: /routers", routerID)
	}

	out, answered, errText := b.enqueueAndWait(ctx, routerID, action, cmdArgs)
	switch {
	case errText != "" && !answered:
		return fmt.Sprintf("%s: %s", routerID, errText)
	case !answered:
		return fmt.Sprintf("%s: %s", routerID, queuedNote(b.Store.LastPollAt(routerID)))
	case errText != "":
		return fmt.Sprintf("%s: ошибка: %s", routerID, errText)
	default:
		return fmt.Sprintf("%s: %s", routerID, out)
	}
}

// queuedNote phrases a "command queued, no answer yet" outcome by whether
// the router looks online.
func queuedNote(lastPoll time.Time) string {
	if !routerOnline(lastPoll) {
		return "🔴 роутер офлайн — команда в очереди, выполнится, когда он снова выйдет на связь"
	}
	return "команда в очереди, ещё не ответил — выполнится при следующем poll"
}

// enqueueAndWait queues one command and blocks up to resultTimeout for
// the router to answer. answered is false on a queue error (errText set)
// or a timeout (errText empty); on an answered command errText carries
// Result.Err. If the router is plainly offline it skips the wait
// entirely -- the command stays queued for when it reconnects. The
// wizard uses this to chain steps.
func (b *TelegramBot) enqueueAndWait(ctx context.Context, routerID, action string, args []string) (out string, answered bool, errText string) {
	id, err := b.Store.Enqueue(routerID, action, args)
	if err != nil {
		return "", false, "не удалось поставить команду в очередь: " + err.Error()
	}
	if !routerOnline(b.Store.LastPollAt(routerID)) {
		return "", false, "" // offline -- don't burn ResultTimeout waiting; command is queued
	}
	result, ok := b.Store.AwaitResult(ctx, routerID, id, b.resultTimeout())
	if !ok {
		return "", false, ""
	}
	return result.Output, true, result.Err
}
