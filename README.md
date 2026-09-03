# keenetic-xray-go

A single Xray (VLESS) failover installer and manager for Keenetic routers
running Entware, targeting **mipsel** and **aarch64** only.

Status: install, configure, run automatic failover, and remote control via
a Telegram bot all work end to end. See `docs/architecture.md` for how it
fits together, `docs/full-vs-mini.md` for the Mini/Full variant split, and
`docs/bot-control-design.md` for the remote-control design.

## What this is

- One Go binary (`keenetic-xray`), one `.ipk` per architecture — no
  generated multi-script installer pipeline.
- Automatic failover between a primary and backup VLESS profile, health
  checked with a real HTTP request through the live proxy (not bare
  ICMP), with an isolated pre-test before failing back to primary.
- Accepts either a raw `vless://` link or a subscription URL, both from
  the CLI (`keenetic-xray setup`) and the remote bot.
- Installs the Xray core itself: by default a size-optimised (UPX-packed,
  ~7–10 MB vs ~30 MB unpacked) build published from this project's own
  releases and pinned to an upstream tag (see `packaging/xray-core/`),
  with `opkg install xray-core` from the Entware feed as the fallback.
  `install.sh --xray-core=entware` forces the feed;
  `keenetic-xray doctor` reports which core is active. Ships no
  geoip/geosite routing data — whole-LAN redirection through the local
  proxy port is handled by Keenetic's own Policy-Based Routing, not by
  this project.
- Optional remote control via a Telegram bot (Full variant only): a
  separate `keenetic-xray-control-server` binary runs on a VPS, and each
  router polls it for queued commands (`/status`, `/switch`,
  subscription management) — see `docs/bot-control-design.md`.

## Installing

Run this on the router (over SSH) — it detects the router's architecture
via `opkg` itself and installs the matching `.ipk` from the latest
release:

```sh
wget -qO- https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/install.sh | sh
```

### Manual install

If you'd rather install a specific `.ipk` yourself: grab the one
matching your router's architecture from the
[latest release](https://github.com/kuzzrus/keenetic-xray-go/releases/latest)
— no package feed to add first, `opkg` can install straight from a URL:

```sh
opkg install https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_aarch64-3.10.ipk   # newer, ARM-based models
opkg install https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_mipsel-3.4.ipk     # older, MIPS-based models
```

If your `opkg` build doesn't handle the release CDN's HTTPS redirect,
download first and install the local file instead:

```sh
wget https://github.com/kuzzrus/keenetic-xray-go/releases/download/v0.1.1/keenetic-xray_0.1.1-1_aarch64-3.10.ipk -O /opt/keenetic-xray.ipk
opkg install /opt/keenetic-xray.ipk
```

(Substitute the filename/version for whatever's on the
[latest release](https://github.com/kuzzrus/keenetic-xray-go/releases/latest)
page once newer versions ship — `install.sh` above does this for you
automatically.)

Either way, the package's postinst fetches the Xray core (vendored build
by default, Entware feed as fallback — see the bullet above). Once
installed:

```sh
keenetic-xray setup     # paste a vless:// link or a subscription URL
keenetic-xray daemon    # run the failover daemon in the foreground
```

(An init.d script starts the daemon automatically on boot/install --
`daemon` above is for running it in the foreground, e.g. to watch logs.)

## CLI reference

```
keenetic-xray version
keenetic-xray setup
keenetic-xray daemon
keenetic-xray profile {add <vless-uri>|list|remove <index>}
keenetic-xray subscription {set-url <url>|refresh|list|set-primary <i>|set-backup <i>}
keenetic-xray status
keenetic-xray doctor
keenetic-xray variant {show|set mini|set full}
keenetic-xray agent {configure <url> <router-id> <fingerprint> <token>|enable|disable|status}
```

`status`/`doctor` currently report saved configuration only (`config.json`),
not live daemon state -- there's no CLI↔daemon IPC layer yet. `agent enable`
requires the Full variant; see `docs/bot-control-design.md`.

## Remote control (Telegram bot)

`keenetic-xray-control-server` is a separate binary that runs on a VPS,
independent of the router installer. It queues commands from a Telegram
bot and serves them to polling router agents over self-signed,
fingerprint-pinned TLS. See `docs/bot-control-design.md` for the full
design.

Install it on a systemd host (as root):

```sh
wget -qO- https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
```

This downloads the latest release binary for the host's architecture,
installs a hardened systemd unit, and runs an interactive wizard
(`keenetic-xray-control-server setup`) that writes
`/etc/keenetic-xray-control-server/config.json` (bot token, chat
allowlist, and the public URL routers dial) and generates the
certificate. To reconfigure later, run `keenetic-xray-control-server
setup` again and `systemctl restart keenetic-xray-control-server`.

Routers are then managed from the Telegram chat itself — no restart, no
config edit. `/menu` opens a button UI (main menu → router list →
per-router card with status / primary·backup switch / subscription /
agent-install / delete). `➕ Добавить роутер` (or `/add_router
home-router Дом`) registers one: the bot generates a bearer token,
stores it, and replies with the exact
`keenetic-xray agent configure <url> <id> <fingerprint> <token>` line to
run on that router.

<details>
<summary>Manual setup (no installer)</summary>

Build or download `keenetic-xray-control-server`, write
`/etc/keenetic-xray-control-server/config.json` by hand (mode 0600) —
`docs/bot-control-design.md` has the format — and run it directly:

```sh
KEENETIC_XRAY_CS_CONFIG=/etc/keenetic-xray-control-server/config.json \
  keenetic-xray-control-server
```

`keenetic-xray-control-server setup` still works without the installer: it
only writes the config and generates the certificate, it doesn't touch
systemd.
</details>

## Relationship to `keenetic_xray_installer`

This is a separate, from-scratch project by the same author. It does not
share code with `keenetic_xray_installer`; that project remains a useful
reference for proven patterns (build flags, CI shape, failover safety
design) but nothing here is copied from it.

## Building

```sh
go build -o keenetic-xray ./cmd/keenetic-xray
go build -o keenetic-xray-control-server ./cmd/keenetic-xray-control-server
```

Cross-compiling for the router architectures:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64  go build -trimpath -ldflags "-s -w" -o dist/keenetic-xray-linux-arm64  ./cmd/keenetic-xray
CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags "-s -w" -o dist/keenetic-xray-linux-mipsle ./cmd/keenetic-xray
```

`keenetic-xray-control-server` targets ordinary VPS architectures
(`linux/amd64`, `linux/arm64`), not the router pair above -- it never runs
on a router.

Building a `.ipk` locally (see `docs/architecture.md` for why this script
exists instead of relying solely on goreleaser's `nfpm` integration):

```sh
sh packaging/build-ipk.sh <version> aarch64-3.10 dist/keenetic-xray-linux-arm64 keenetic-xray_<version>_aarch64-3.10.ipk
```

## License

MIT — see `LICENSE`.
