package botcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	KnownRouters  []string // "" / nil -> don't validate router IDs against a registry
	Store         *Store
	APIBase       string        // "" -> telegramAPIBase
	ResultTimeout time.Duration // 0 -> DefaultResultTimeout
	Logger        *log.Logger   // nil -> log.Default()

	client *http.Client
}

type tgUpdate struct {
	UpdateID int64      `json:"update_id"`
	Message  *tgMessage `json:"message"`
}

type tgMessage struct {
	Chat tgChat `json:"chat"`
	Text string `json:"text"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgGetUpdatesResponse struct {
	OK     bool       `json:"ok"`
	Result []tgUpdate `json:"result"`
}

// Run long-polls Telegram for updates and handles each until ctx is
// cancelled, at which point it returns ctx.Err().
func (b *TelegramBot) Run(ctx context.Context) error {
	if b.client == nil {
		b.client = &http.Client{Timeout: 65 * time.Second} // > the 50s long-poll timeout used below
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
			if u.Message == nil {
				continue
			}
			b.handleMessage(ctx, *u.Message)
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

func (b *TelegramBot) sendMessage(ctx context.Context, chatID int64, text string) {
	body, err := json.Marshal(map[string]any{"chat_id": chatID, "text": text})
	if err != nil {
		return
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", b.apiBase(), b.Token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		b.logger().Printf("telegram: sendMessage: %s", b.scrubToken(err))
		return
	}
	defer resp.Body.Close()
}

func (b *TelegramBot) handleMessage(ctx context.Context, msg tgMessage) {
	if !b.AllowedChats[msg.Chat.ID] {
		return // silently ignore -- do not reveal that this bot exists to unlisted chats
	}
	if reply := b.dispatch(ctx, msg.Text); reply != "" {
		b.sendMessage(ctx, msg.Chat.ID, reply)
	}
}

const helpText = `commands (all take a router ID as the first argument):
/routers -- list known router IDs
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
	case "/start", "/help":
		return helpText
	case "/routers":
		return b.listRouters()
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
	if len(b.KnownRouters) == 0 {
		return "no routers configured"
	}
	return "known routers:\n" + strings.Join(b.KnownRouters, "\n")
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
	if !b.knownRouter(routerID) {
		return fmt.Sprintf("unknown router %q; send /routers to list known routers", routerID)
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

func (b *TelegramBot) knownRouter(id string) bool {
	if len(b.KnownRouters) == 0 {
		return true
	}
	for _, k := range b.KnownRouters {
		if k == id {
			return true
		}
	}
	return false
}
