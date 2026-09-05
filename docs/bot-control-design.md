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
- `POST /agent/heartbeat` -- every `HeartbeatInterval` (30s) the agent
  pushes a `Heartbeat` (`{status, time}`) whose `status` is the rendered
  `keenetic-xray status` text (active profile, failover state, agent and
  xray-core version, uptime, Proxy0, subscription age). The server stores
  it on the router record; the router card shows it verbatim, so the card
  is live without queuing a `status` command and waiting. Opt-in on the
  agent: `AgentOptions.StatusFunc` supplies the text, and is nil (no
  heartbeat) in minimal deployments and tests.
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
/help` so Telegram shows them in its command list.

Most card buttons (`📊 Статус`, `🩺 Doctor`, `⬆️ primary`, `⬇️ backup`,
`🔄 Обновить подписку`, `♻️ Рестарт демона`) enqueue the matching command,
edit the message to `⏳ команда в очереди…`, then a goroutine waits up to
`ResultTimeout` (default 20s) and edits it again with the result (or a
"not answered" note). `📦 Установка агента` re-shows the `agent configure`
line; `🔁 Обновить агент` (`upd:` -> confirm -> `self_update`, re-runs
`install.sh` on the router) and `🗑 Удалить роутер` ask for confirmation
first. Callback data is a short `kind:arg` string routed by
`handleCallback`.

Proxy0 has no card button -- it's on by default (`config.Default`,
`install.sh --no-proxy0` opts out) and the daemon asserts it at startup;
`/proxy0 <router> [show|on|off]` is still there as a text command.

`🔗 Источники` (`srcm:`) opens a two-button screen -- `⬆️ Основная`
(`srcp:`) / `⬇️ Резервная` (`srcb:`) -- each starting a one-step dialog:
paste a `vless://` link or an `http(s)://` subscription URL, optionally
followed by a selector (an index or a name substring for a multi-profile
subscription). Applied via `set_primary_source` / `set_backup_source`,
which resolve the source to one profile, merge it into `Config.Profiles`,
repoint the slot index and rebind xray. The two slots can be fed from
independent sources; `Config.PrimarySource` / `BackupSource` remember
where each came from (URL kept in the 0600 config, redacted from every
reply alongside `Subscription.URL`). Setting one slot's source never
fills in an empty other slot -- see internal/botcontrol/commands.go's
setSlotSource; it only warns when the other slot still needs its own.

There used to be a `📋 Профили` card button (an interactive screen for
picking among *already loaded* profiles by index, `pfp:`/`pfb:`
callbacks). Removed as low-value next to `🔗 Источники` -- it invited
pointing a slot at whatever a subscription happened to currently
contain instead of an explicit source, which is more fragile. The
underlying commands are still text-only: `/profile_list <router>` to
see indices, then `/sub_setprimary <router> <index>` / `/sub_setbackup
<router> <index>`.

`🐕 Вотчдог` (`wdm:`) opens a four-button screen -- `📊 Статус` /
`✅ Включить` / `⛔ Выключить` / `📜 Лог` (`wd_show`/`wd_enable`/
`wd_disable`/`wd_log`, all parameterless so they go through the same
`act:` + `callbackAction` path as `📊 Статус`/`🩺 Doctor` above, not a
dedicated dialog). Controls the cron entry that restarts the daemon if
rc.func ever finds it not running (see `docs/architecture.md`);
`✅ Включить` calls `internal/install.EnsureCron` first, so a router
that's never had a cron package installed gets one via opkg rather than
silently writing an entry nothing will read. `📜 Лог` shows
`watchdogLogPath()`'s tail -- restart events only, not routine ticks, so
an empty log means the watchdog has never had to step in. All four are
also `/watchdog <router> show|enable|disable|log` as text commands.

`⚙️ Порты` (`ports:`) starts a one-step text wizard (`wizPorts`, same
shape as the 🔗 Источники dialogs): paste two numbers separated by a
space, `SOCKS HTTP`. Unlike the CLI setup wizard, the control server has
no direct view of a router's current config to show as defaults --
`📊 Статус` has that ("xray: слушает :N"). Applied via `set_ports`; also
`/ports <router> <socks> <http>` as a text command.

`➕ Добавить роутер` starts a two-step text dialog (`telegram_wizard.go`):
id, then display name. `✏️ Переименовать` (or `/rename <id> <name>`) is
one step over `Store.RenameRouter`. State is per-chat; any `/command`
other than `/cancel` aborts it and still runs.

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
/set_primary_source <router> <vless://…|url> [selector]   feed the primary slot from its own source
/set_backup_source  <router> <vless://…|url> [selector]
/proxy0 <router> [show|on|off]   point Keenetic's Proxy0 at the local inbound
/restart <router>               restart the failover daemon (detached; the replacement emits daemon_start)
/ensure_core <router>           (re)install the xray-core binary -- vendored build, opkg fallback
/update <router>                re-run install.sh (whole keenetic-xray package)
/failover <router> show                        current health-check thresholds
/failover <router> set <key> <value>           tune one (restarts the daemon to apply)
```

`restart` and `update` are also router-card buttons (`update` behind a confirm).

`sub_refresh`, `sub_setprimary`, `sub_setbackup`, `set_primary_source`,
`set_backup_source`, `proxy0 on`/`off`, `failover_set` and `set_ports`
all call `RouterHandler.rebindXray` after saving. If the daemon is
already in its Run loop, that calls `failover.Daemon.ReloadConfig`
-- since `h.Config` is the exact `*config.Config` the Daemon already
holds (wired once in `cmdDaemon`), this refreshes the two fields only
computed at startup (`realActions.socks`, `Machine`'s own copy of the
tunable failure/recovery counts) in addition to re-applying the current
live role, so it regenerates `xray-production.json` and restarts the
supervised xray process -- **without a full daemon restart and without
touching the Proxy0 interface**. `failover_set` used to skip straight to
a full detached restart instead (the state machine's tunables were fixed
at construction, so nothing shorter would've picked up a changed
threshold); `set_ports` is why that got fixed -- a changed SOCKS port
needs `realActions.socks` refreshed too, or health-check probes would
keep dialing the old one. If the daemon is still idling (it starts idle
until *both* primary and backup are set) and the config now has both,
`rebindXray` instead kicks a detached `init.d restart` so a setup done
entirely from the bot actually starts serving, with no SSH step.

`set_ports` (`/ports <router> <socks> <http>`, or `⚙️ Порты` on a card,
a one-step text wizard) additionally re-points Proxy0's own upstream
binding via `proxy0Set` if Proxy0 is currently enabled -- otherwise LAN
traffic routed through it would keep hitting the port it was last
pointed at. That step is best-effort: reported alongside the port
change's own success, not as an overall failure, since the port change
itself already took effect either way.

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

### Self-update from the bot

The main menu's **⬆️ Обновить сервер** button re-runs `server-install.sh`.
The control-server process is unprivileged and can't swap its own binary
or restart itself, so the update goes through systemd: `server-install.sh`
also installs `keenetic-xray-control-server-update.path` (watches
`/var/lib/keenetic-xray-control-server/update.request`, which the service
user *can* create) and `keenetic-xray-control-server-update.service` (a
root `oneshot` running `control-server-self-update.sh`). The bot touches
the trigger file (`TelegramBot.SelfUpdatePath`); the `.path` unit fires
the root oneshot; the oneshot clears the trigger and pipes
`server-install.sh` into `sh`.

The *old* process is killed mid-flight by that restart, so it can never
announce its own successful replacement -- the message the button's own
reply gives ("переустановка и рестарт через несколько секунд") is only
ever "queued", never "done". `notifyIfUpdated`
(`cmd/keenetic-xray-control-server/versioncheck.go`) is how completion
gets reported instead: on every startup, the *new* process compares its
own `version.String()` against what a small file next to the queue
recorded last run, and DMs every allowed chat -- "✅ Сервер обновлён: vX
→ vY" when they differ, "✅ Сервер запущен: vX" when there's no prior
version recorded (missing or empty file: not just a genuinely fresh
install, but also -- confirmed live -- what an *existing* server's very
first run of this feature looks like, since nothing wrote the file
before it existed; staying silent there instead, the original behavior,
was the actual bug: it meant nobody saw a confirmation on exactly the
update that mattered most). Silent only on an unchanged version -- a
plain restart (a reboot, `systemctl restart` for some unrelated reason)
is not an update and must not be reported as one.

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
