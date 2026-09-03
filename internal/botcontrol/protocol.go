// Package botcontrol implements the protocol between a router's polling
// agent and the VPS control-server, and (agent.go) the router-side
// client. The control-server itself (Telegram bot, HTTP server, command
// queue) is a separate binary -- it runs on different infrastructure with
// different concerns, so it doesn't belong in the router's single binary
// the way the agent does.
package botcontrol

import "time"

// Action names a unit of work an agent can execute. Kept as plain
// strings (not run through a Go type per action) since both sides only
// ever need to route on the string and log it -- a heavier action
// registry would be premature for the command set this project has.
const (
	ActionStatus        = "status"
	ActionDoctor        = "doctor"
	ActionSwitchPrimary = "switch_primary"
	ActionSwitchBackup  = "switch_backup"
	ActionProfileList   = "profile_list"
	ActionSubSetURL     = "sub_seturl"
	ActionSubRefresh    = "sub_refresh"
	ActionSubList       = "sub_list"
	ActionSubSetPrimary = "sub_setprimary"
	ActionSubSetBackup  = "sub_setbackup"
	ActionProxy0Show    = "proxy0_show"
	ActionProxy0On      = "proxy0_on"
	ActionProxy0Off     = "proxy0_off"
	ActionDaemonRestart = "daemon_restart"
	ActionEnsureCore    = "ensure_core"
	ActionSetupLink     = "setup_link" // args[0] = a raw vless:// URI -> becomes the sole profile
)

// Command is a single unit of work queued for a router by the control
// server, to be fetched and executed by that router's agent.
type Command struct {
	ID     string    `json:"id"`
	Action string    `json:"action"`
	Args   []string  `json:"args,omitempty"`
	Queued time.Time `json:"queued"`
}

// Result is what the agent posts back after executing a Command.
type Result struct {
	CommandID string    `json:"command_id"`
	Output    string    `json:"output"`
	Err       string    `json:"error,omitempty"`
	Completed time.Time `json:"completed"`
}

// PollResponse carries at most one queued command -- the agent executes
// it, posts the Result, and polls again for the next one rather than
// being handed a batch.
type PollResponse struct {
	Command *Command `json:"command,omitempty"`
}

// Event is an unsolicited notification the agent pushes to the control
// server (POST /agent/event) when something on the router is worth
// telling the operator about -- a failover switch, the daemon starting.
// Text is already rendered and human-readable; the server/bot only
// prefixes the router ID and forwards it to the chat.
type Event struct {
	Kind string    `json:"kind"` // "failover", "daemon_start", ...
	Text string    `json:"text"`
	Time time.Time `json:"time"`
}

// RouterIDHeader identifies which router a /agent/poll or /agent/result
// request is for. A header, not a JSON body field: the server's auth
// middleware needs it before (and regardless of) parsing any body, and
// /agent/poll has no body at all.
const RouterIDHeader = "X-Router-Id"
