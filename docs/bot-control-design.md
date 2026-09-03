# Bot control design

Remote/automatic control of a router's failover setup via a Telegram bot,
built as a VPS control-server plus a polling agent on each router (the
same shape the reference `keenetic_xray_installer` project uses,
reimplemented fresh here -- see `internal/botcontrol`). Full-variant only
(see `docs/full-vs-mini.md`).

## Why polling, not a router-facing listener

The router agent (`keenetic-xray agent`, wired into `keenetic-xray
daemon` -- see below) polls the control server for work; the control
server never connects to the router. Home routers are typically behind
CGNAT or a firewall with no forwarded inbound port, so the control server
having to reach the router would need port-forwarding or a relay the
router doesn't otherwise need. A router able to make one outbound HTTPS
request every few seconds needs neither.

## Two binaries, two trust boundaries

- **`keenetic-xray`** (the router binary) gains no new process: the
  agent runs as a goroutine inside `keenetic-xray daemon`, started when
  `config.json`'s `agent.enabled` is true (see `cmdDaemon` in
  `cmd/keenetic-xray/main.go`). It shares the same in-memory
  `*failover.Daemon` and `*config.Config` the daemon already has --
  commands run through the exact same `Actions`/state machine the local
  CLI does, via `failover.Daemon`'s serialized command channel (see
  `internal/failover/daemon.go`), not a second code path.
- **`keenetic-xray-control-server`** (`cmd/keenetic-xray-control-server`)
  is a separate binary for a VPS, built for `linux/amd64` and
  `linux/arm64` (ordinary VPS architectures -- not the router's
  mipsel/aarch64 pair). It never runs on a router and shares no process
  or config file with `keenetic-xray`.

This matters for trust: the router→control-server link is a real network
boundary (self-signed TLS + bearer token), unlike the in-process
CLI↔daemon relationship on the router side, which is just a Go function
call.

## Wire protocol (`internal/botcontrol`)

Both sides speak plain JSON over HTTPS. `protocol.go` defines the shapes:

```
Command  { id, action, args[], queued }
Result   { command_id, output, error, completed }
PollResponse { command? }   // at most one command per poll
```

- `POST /agent/poll` -- router asks for its next queued command. Empty
  body; the response's `command` field is omitted (`null`) if nothing is
  queued. The agent executes at most one command per poll and always
  posts a `Result` before polling again -- no batching.
- `POST /agent/result` -- router posts the `Result` of the command it
  just ran, as the raw JSON body (no wrapper type).
- `POST /agent/event` -- router pushes an unsolicited `Event`
  (`{kind, text, time}`) when something happens the operator should hear
  about without asking: a failover switch, the daemon starting. `text`
  is already rendered (in Russian, by `renderFailoverEvent`); the server
  hands it to `ServerConfig.OnEvent`, which the control-server wires to
  the bot's `NotifyEvent` -- one Telegram message per allowed chat,
  prefixed with the router's name. Best-effort both ways: the daemon's
  event channel is buffered and lossy, and a failed POST is dropped.
- `GET /fingerprint` -- unauthenticated, serves the server's certificate
  fingerprint in plaintext for first-trust bootstrapping (see below).

Events originate in `failover.Daemon`: the state machine's `onTransition`
hook feeds both the `status` history ring and `Daemon.Events()`;
`botcontrol.FailoverEvents` renders each to an `Event` and the agent's
`Run` loop forwards it.

Offline detection is server-side and needs no agent cooperation:
`OfflineWatcher` (a goroutine in the control server) scans the registry
every 30s and calls `bot.NotifyOffline` when a router that had been
polling goes silent past `DefaultOfflineThreshold` (90s), and again when
it resumes. Its first scan only seeds state, so a control-server restart
doesn't spray messages; a router that has never polled is "not set up
yet", not offline, and is skipped.

**Router identity is a header, not a body field**
(`RouterIDHeader = "X-Router-Id"`, in `protocol.go`): the server's auth
middleware needs to know which router's token to check *before* parsing
any body, and `/agent/poll` has no body at all to put it in. Both
authenticated endpoints require `X-Router-Id` plus `Authorization: Bearer
<token>`.

## Trust: fingerprint pinning + constant-time token comparison

The control server's TLS certificate is self-signed
(`GenerateSelfSignedCert`/`LoadOrGenerateCert` in `tls.go`, ECDSA P-256,
long validity since it's never checked for expiry) -- there's no CA to
validate against, so the agent doesn't try. Instead it pins the
certificate's SHA256 fingerprint, SSH-host-key style: `newPinnedClient`
in `agent.go` sets `InsecureSkipVerify: true` and does the real check
itself in `VerifyPeerCertificate`, comparing `SHA256(leaf)` against the
fingerprint from `keenetic-xray agent configure` via
`crypto/subtle.ConstantTimeCompare`. An operator gets that fingerprint
once, out of band, by hitting the unauthenticated `/fingerprint` endpoint
directly (`curl -k https://vps:8443/fingerprint`) when first setting up
an agent.

Router tokens are compared the same way, constant-time, in the server's
auth middleware (`authenticated` in `server.go`) -- a plain `==` would
leak timing information about how many leading bytes matched, in
principle usable to brute-force a valid token faster than guessing it
outright.

The certificate is regenerated only if both `cert_path` and `key_path`
are missing; reusing the same key/cert across control-server restarts
matters because the fingerprint is what every already-configured agent
has pinned -- regenerating it on every start would lock out every router
until each one is manually reconfigured.

## Command queue and persistence (`queue.go`)

`Store` holds one FIFO of pending commands and one most-recent `Result`
per router ID, persisted to a JSON file via write-temp-then-rename on
every mutation -- a control-server crash or restart mid-command can't
lose a queued command or leave a truncated file behind. `AwaitResult`
polls the in-memory store every 200ms for a specific command ID to
appear as some router's latest result: cheap and simple for what is a
low-traffic, personal-scale control server, and correct by construction
(no missed-wakeup window the way a subscribe-after-the-fact channel
could have).

## Telegram bot (`telegram.go`, `telegram_menu.go`, `telegram_wizard.go`)

Long-polls `getUpdates` (not a webhook -- no inbound port needed on the
VPS side either, beyond the agent-facing HTTPS port). Messages *and
callback queries* from chat IDs outside `allowed_chat_ids` are silently
ignored -- no error reply, so an unlisted chat can't even confirm the bot
exists.

### Inline menu

`/menu` (also `/start`) opens a button UI: main menu -> router list ->
per-router card. `setMyCommands` registers `/menu /routers /add_router
/setup /help` so Telegram shows them in its command list.

A card's buttons (`📊 Статус`, `🩺 Doctor`, `⬆️ primary`, `⬇️ backup`,
`📋 Профили`, `⚙️ Настроить`, `🔄 Подписка`, `📄 Список`, `🌐 Proxy0
вкл/выкл`, `♻️ Рестарт демона`) enqueue the matching command, edit the
same message to `⏳ команда в очереди…`, then a goroutine waits up to
`ResultTimeout` (default 20s) and edits it again with the result (or a
"not answered, will run on its next poll" note). `📦 Установка агента`
re-shows the `agent configure` line; `🗑 Удалить роутер` asks for
confirmation before `RemoveRouter`. Callback data is a short `kind:arg`
string routed by `handleCallback`.

`➕ Добавить роутер` starts a two-step text dialog (`telegram_wizard.go`):
id, then display name. `⚙️ Настроить` (or `/setup <router>`) starts a
longer one: paste a `vless://` link or subscription URL, then -- for a
subscription -- pick primary and backup by number from the fetched list.
Each step drives the router through the existing `setup_link` /
`sub_seturl` / `sub_refresh` / `profile_list` / `sub_setprimary` /
`sub_setbackup` actions. `✏️ Переименовать` (or `/rename <id> <name>`) is
a one-step dialog over `Store.RenameRouter`. State is per-chat; any
`/command` other than `/cancel` aborts it and still runs.

The router list and every list button carry a status dot -- 🟢 polled
within `DefaultOfflineThreshold`, 🔴 silent longer, ⚪ never connected
(`routerDot`, shared with `OfflineWatcher`). `/status` with no router
named returns that same overview; `🔄 Обновить` on a card just
re-renders it.

### Text commands

Everything the menu does is also a text command, and a few argument-taking
ones are text-only:

```
/add_router <id> [name]    register a router; the bot replies with its agent configure commands in a copyable <pre> block
/remove_router <id>        unregister a router (the agent on the router is left alone)
/setup <router>            step-by-step: paste a source, then pick primary/backup
/rename <id> <name>        change a router's display name
/routers                   list registered routers with a status dot
/status                    overview of all routers (dot, last poll, queue depth)
/status <router>           rich snapshot: failover state + live profile, uptime, last switch, listening ports, proxy0, subscription age
/doctor <router>           pass/fail health checks (profiles, config, xray-core runnable, proxy0 upstream, free disk)
/switch <router> primary|backup
/profile_list <router>
/sub_seturl <router> <url>
/sub_refresh <router>
/sub_list <router>
/sub_setprimary <router> <index>
/sub_setbackup <router> <index>
/proxy0 <router> [show|on|off]   point Keenetic's Proxy0 at the local inbound (on/off also rebind xray)
/restart <router>               restart the failover daemon (detached; the replacement emits daemon_start)
/ensure_core <router>           (re)install the xray-core binary -- vendored build, opkg fallback
```

`proxy0 on`/`off` and `restart` are also router-card buttons.

A text command enqueues and then blocks up to `ResultTimeout` for the
router to answer before replying (an online router, default poll interval
5s, feels synchronous); the menu path never blocks the update loop.

## Configuring a router's agent

```sh
keenetic-xray agent configure <control-server-url> <router-id> <fingerprint-sha256> <token>
keenetic-xray agent enable   # requires the Full variant; see docs/full-vs-mini.md
```

The token is written to its own 0600 file (`agent.token_file` in
`config.json`, defaulting to `/opt/etc/keenetic-xray/agent-token.secret`)
-- never into `config.json` itself, so it can never leak through
`keenetic-xray status`/`doctor` output or an accidental `cat
config.json`.

## Running the control server

### Installer (systemd hosts)

```sh
curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
```

`server-install.sh` downloads the latest release binary for the host's
architecture into `/usr/local/bin`, creates a `keenetic-xray` system
user, installs `packaging/server/keenetic-xray-control-server.service`
(hardened: `ProtectSystem=strict`, `NoNewPrivileges`, writable only under
its config and state dirs), runs the `setup` wizard, and
`systemctl enable --now`s the service. systemd only -- there's no
OpenRC/sysvinit path.

### The `setup` wizard

```sh
keenetic-xray-control-server setup
```

Interactive, and usable with or without the installer -- it only writes
`config.json` and generates the TLS certificate, it never touches
systemd. It prompts for the bot token, the chat allowlist, the listen
address, and the public URL routers dial, writes the config at mode
0600, and prints the certificate fingerprint. Routers are added later
from the chat with `/add_router`. Re-run it to reconfigure, then
`systemctl restart keenetic-xray-control-server`.

### Config file

```json
// /etc/keenetic-xray-control-server/config.json, 0600
{
  "listen_addr": ":8443",
  "public_url": "https://vps.example.com:8443",
  "telegram_token": "<bot token from @BotFather>",
  "allowed_chat_ids": [123456789]
}
```

`cert_path`/`key_path`/`queue_path` all have working defaults (see
`cmd/keenetic-xray-control-server/config.go`) and don't need to be set
explicitly. `public_url` is optional -- if unset, the bot's `agent
configure` hints use the `listen_addr` port plus the machine's detected
outbound IP (a `<адрес-сервера>` placeholder only if there's no route);
set it when the server is behind NAT or should be reached by hostname.
`telegram_token` and `allowed_chat_ids` are the only required fields:
there's no sensible "not configured yet" mode for a Telegram bot with no
token or chat allowlist, so a missing or incomplete config file is a
startup error, not a default. A `routers` object is still accepted as a
one-time bootstrap -- its entries are copied into the runtime registry
at startup and then the registry is authoritative.

### Without the installer

```sh
KEENETIC_XRAY_CS_CONFIG=/etc/keenetic-xray-control-server/config.json \
  keenetic-xray-control-server
```

Whether it replaces or runs alongside an existing control server from
`keenetic_xray_installer` is a deployment decision, not a protocol one;
the agent side works identically either way.
