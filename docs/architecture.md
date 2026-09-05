# Architecture

## One binary, dispatched by subcommand

`cmd/keenetic-xray` is the only binary this project ships *for the
router*. There is no separate CLI/daemon/agent binary split on that side:
a stdlib-only Go binary is roughly the same size (~5-6MB stripped,
measured directly) regardless of which features are compiled in, since Go
statically links its runtime either way -- splitting into multiple
binaries would buy little and would reintroduce, at the binary level, the
"many near-duplicate artifacts" problem this project deliberately avoids
at the installer level (see below). `cmd/keenetic-xray-control-server` is
a genuinely separate binary, but deliberately so -- see
`docs/bot-control-design.md` for why the VPS side isn't part of this
split.

Current subcommands: `version`, `setup`, `daemon`, `profile`,
`subscription`, `status`, `doctor`, `variant`, `agent` (configure/enable/
disable/status for the control-server polling loop -- Full variant only,
see `docs/bot-control-design.md`), `proxy0`, `failover`, `watchdog`
(show/enable/disable the cron entry that restarts the daemon if it's not
running -- rc.func doesn't do this on its own, unlike the
control-server's systemd unit's `Restart=on-failure`), and the hidden
`internal postinst-setup` / `internal prerm-cleanup` used only by the
`.ipk`'s packaging scripts.

## Package layout

| Package | Responsibility |
|---|---|
| `internal/config` | `Config`/`Profile` types, `config.json` load/save/validate, `vless://` URI parsing and formatting, Xray-core JSON config generation |
| `internal/subscription` | Fetching, base64-decoding, and parsing V2Ray-style subscription URLs; remark-based re-matching of the previously-selected primary/backup across a refresh |
| `internal/xrayctl` | `Supervisor` (start/stop/restart an xray-core process, crash-restart with backoff) and `Probe` (health check through the live SOCKS5 proxy, including a minimal hand-rolled SOCKS5 CONNECT client -- this project has zero third-party Go dependencies, and `net/http.Transport` doesn't speak SOCKS5 on its own). `Probe` tries a list of URLs in order (`HealthCheckURL` then `HealthCheckFallbackURLs`) and retries each (`CheckRetries`, `CheckRetryDelaySeconds`) before giving up -- one flaky/rate-limited check endpoint or one sub-second blip shouldn't by itself read as "primary is down" |
| `internal/failover` | The failover state machine (`state.go`, pure logic, no I/O, driven via an `Actions` interface so it's unit-testable with fakes) and its wiring to real `xrayctl`/`config` (`daemon.go`) |
| `internal/diskspace` | Resolves the real filesystem behind a path (Entware routinely symlinks `/opt` to a USB mount, not the internal flash overlay) and reports free space via `statfs` |
| `internal/xraycore` | Ensures a runnable xray-core binary: fetch the vendored, size-optimised build from this repo's `xray-core/<tag>` releases (sha256-verified, smoke-tested), fall back to `opkg install xray-core` |
| `internal/keenetic` | Drives the router CLI (`ndmc`) to detect the LAN IP (LAN bridge only, never a loopback fallback) and point Keenetic's `Proxy0` interface at the local inbound, with a read-back check that the change took |
| `internal/install` | The `.ipk` postinst/prerm logic: directory setup, the Mini/Full decision, and the "never overwrite an existing config.json" upgrade guarantee |
| `internal/botcontrol` | The router agent (`agent.go`, TLS-fingerprint-pinned polling client) and its command handlers (`commands.go`, thin wrappers over `internal/config`/`internal/subscription`/`internal/failover`); the control-server pieces the router never uses -- HTTP API (`server.go`), self-signed cert generation (`tls.go`), the persisted command queue (`queue.go`), and the Telegram bot (`telegram.go`) -- see `docs/bot-control-design.md` |

## Why one unified `.ipk` instead of a `curl \| sh` script

Xray installers for Keenetic commonly ship as a `curl | sh` one-liner
that fetches and runs a shell script. This project ships a single
compressed `.ipk` per architecture instead, installed with `opkg install
<file-or-url>` -- no hosted package feed required, since `opkg` can
install directly from a local file or a URL.

The Xray core is not an `opkg` dependency. The control file used to
declare `Depends: xray-core` and let `opkg` pull it from Entware's feed,
but that feed doesn't always carry a current `xray-core` for both arches,
and its ~30 MB unpacked footprint is a problem on a small internal-flash
`/opt`. Instead the postinst runs `keenetic-xray internal
ensure-xray-core`, which installs a size-optimised (UPX-packed) build
from this repo's own `xray-core/<tag>` releases -- verified against its
published sha256 and smoke-tested with `xray version` before it's put in
place -- and falls back to `opkg install xray-core` if that can't be
fetched or won't run. The pinned upstream tag and the build workflow live
in `packaging/xray-core/` and `.github/workflows/xray-core.yml`.

`packaging/build-ipk.sh` builds the `.ipk` by hand: a single
gzip-compressed tar containing `./debian-binary`, `./data.tar.gz`, and
`./control.tar.gz`, in that order. **This is not the `ar`-wrapped format
`.deb` uses**, despite that being the commonly-documented convention for
`.ipk` too -- real Entware's own feed doesn't use it. That wrong
assumption originally shipped here and cost five failed real-hardware
install attempts to find: `ar t` on a real Entware-served `.ipk`
(`xray-core`'s own package, fetched directly from `bin.entware.net`)
fails with "invalid ar magic", while `tar tzf` lists its three members
directly. This is deliberately the primary path, not a fallback behind
`nfpm`: it's now verified end-to-end on real router hardware (`opkg
install` succeeds, the daemon starts via the generated init.d script),
not just structurally inspected.

## Failover state machine

Four states: `ACTIVE_PRIMARY`, `ACTIVE_BACKUP` (reached only after a
failed recovery confirmation, waiting out a backoff), `TESTING_RECOVERY`,
`COOLDOWN`. Health checks are a real HTTP GET through the live SOCKS5
proxy, never bare ICMP or a raw TCP connect -- those don't prove the
VLESS/TLS/auth path actually works, and ICMP is frequently filtered
independently of tunnel health anyway.

The mechanism is deliberately **asymmetric** even though the trigger
counts are symmetric (3 consecutive results, matching the original
spec): failing away from primary happens immediately on 3 consecutive
live-probe failures, with no pre-test, since there's nothing to protect
by double-checking a path already known to be bad. Failing back to
primary requires 3 consecutive successes against an *isolated, zero-risk*
throwaway `xray` instance before production traffic is touched at all,
then one live confirmation check -- and rolls back with a 5-minute
backoff if that confirmation fails, rather than retrying against a
flapping primary every 30 seconds.

## What this project deliberately does not do

- **No geoip/geosite routing data.** Outbound selection is just
  primary-vs-backup; there's no domain/IP-based split-tunneling. Routing
  all LAN traffic through the local proxy port is Keenetic's own
  Policy-Based Routing feature, configured separately in the router's
  web UI -- this project never touches `iptables`/TPROXY.
- **No query IPC.** `status`/`doctor` read `config.json` directly; they
  report saved configuration, not live daemon state (uptime, current
  role, transition history). The bot-control agent doesn't need this
  either -- it runs *inside* `daemon` as a goroutine (see
  `docs/bot-control-design.md`), sharing the same in-memory
  `*failover.Daemon` rather than talking to it over IPC. There *is* a
  minimal one-way channel for the opposite direction, applying a change
  rather than reading state: `setup`/`subscription`/`proxy0`/`failover
  set` all signal a running daemon's pidfile with SIGHUP after saving,
  which reloads config.json and re-applies the current live role
  (`failover.Daemon.ReloadConfig`) -- restarting only the supervised
  xray-core child, not the daemon process. A future version could still
  add a full request/response protocol (a Unix socket) for the query
  direction, but it wasn't needed to make the CLI/wizard genuinely
  useful, so it wasn't built speculatively.
