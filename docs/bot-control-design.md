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
- `GET /fingerprint` -- unauthenticated, serves the server's certificate
  fingerprint in plaintext for first-trust bootstrapping (see below).

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

## Telegram bot (`telegram.go`)

Long-polls `getUpdates` (not a webhook -- no inbound port needed on the
VPS side either, beyond the agent-facing HTTPS port). Messages from chat
IDs outside `allowed_chat_ids` are silently ignored -- no error reply,
so an unlisted chat can't even confirm the bot exists.

Every command takes a router ID as its first argument (one control
server can front several routers):

```
/routers                                list known router IDs
/status <router>
/switch <router> primary|backup
/profile_list <router>
/sub_seturl <router> <url>
/sub_refresh <router>
/sub_list <router>
/sub_setprimary <router> <index>
/sub_setbackup <router> <index>
```

The bot enqueues the command, then waits up to `ResultTimeout` (default
20s) for that router to answer before replying -- an online router
(default poll interval 5s) feels synchronous even though the transport
underneath is poll-based. A router that doesn't answer in time gets a
"queued, will run on its next poll" reply instead of the bot blocking
indefinitely.

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
wget -qO- https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
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
systemd. It prompts for the bot token and chat allowlist, asks how many
routers this server fronts, generates a bearer token per router itself
(32 random bytes, hex), writes the config at mode 0600, then prints the
certificate fingerprint and a ready-to-paste
`keenetic-xray agent configure <url> <router-id> <fingerprint> <token>`
line for each router. Re-run it to reconfigure, then
`systemctl restart keenetic-xray-control-server`.

### Config file

```json
// /etc/keenetic-xray-control-server/config.json, 0600
{
  "listen_addr": ":8443",
  "telegram_token": "<bot token from @BotFather>",
  "allowed_chat_ids": [123456789],
  "routers": { "router-1": "<bearer token, shared with that router's `agent configure`>" }
}
```

`cert_path`/`key_path`/`queue_path` all have working defaults (see
`cmd/keenetic-xray-control-server/config.go`) and don't need to be set
explicitly. `telegram_token`, `allowed_chat_ids`, and `routers` are
required -- unlike the router's `config.json`, there's no sensible
"not configured yet" mode for a Telegram bot with no token or chat
allowlist, so a missing or incomplete config file is a startup error,
not a default.

### Without the installer

```sh
KEENETIC_XRAY_CS_CONFIG=/etc/keenetic-xray-control-server/config.json \
  keenetic-xray-control-server
```

Whether it replaces or runs alongside an existing control server from
`keenetic_xray_installer` is a deployment decision, not a protocol one;
the agent side works identically either way.
