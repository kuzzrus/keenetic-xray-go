# Handoff — Susanin adaptive routing addon

Kickoff brief for a fresh session with no access to a previous session's
`.claude/memory/` files. Written 2026-09-13, repo at `v0.30.0` / `main`.

For what this project is and the general working conventions ("делай и
сразу сливай" flow, CI checks, versioning, commit/PR trailers, language,
the `parse_test.go` CRLF gotcha), see
[`docs/HANDOFF-naive.md`](HANDOFF-naive.md) §1-2 — identical here, not
repeated.

## The task — an `internal/addons` wrapper for R17a/Susanin.Keenetic

[Susanin.Keenetic](https://github.com/R17a/Susanin.Keenetic) (MIT, C,
~v0.3.6) is a conntrack-based **adaptive router**: it watches
`/proc/net/nf_conntrack` for silent-block signals (TCP SYN retried with no
reply, a stalled TCP flow, QUIC with no reply), routes just that
destination IP through a VPN tunnel, remembers what worked (persists
across reboots), and falls back to direct if the tunnel goes down. No
domain list needed for the adaptive part -- genuinely different from this
project's own `routes`/preset-catalogue model (which needs a human, or the
daily cron, to have already decided a domain belongs in a list).

User asked (2026-09-13) whether this could run alongside/feed into our own
xray egress. Two-phase answer, full reasoning in
`.claude/memory/susanin-adaptive-routing-plan.md` (and the read-notes
`susanin-keenetic-study.md` next to it) if this session has memory access;
condensed version below if not.

### Phase 1 (this is what's being built first) — stock binary as an addon

Mirror upstream's own release tarball (not opkg-packaged, so the vendoring
model is `naive-core`'s -- fetch/verify/re-host -- not `nfqws2`'s opkg
feed), wrap it as an `internal/addons` component the same shape as
unbound/dnscrypt/nfqws2: install lays the files down and runs upstream's
own `install.sh` (it has a documented offline-from-extracted-archive mode,
see its `DEPLOY.md`), configure edits `susanin.conf`
(`KEY=value` shell format, same shape `shellConfSet` in `nfqws2.go`
already handles) plus the `vpn_always.txt`/`vpn_never.txt` lists, status/
remove wrap upstream's own `susanin.sh` control script.

**Two hard preconditions, both must be surfaced clearly to the operator,
not silently assumed:**
1. **WG-transport must be enabled** (`config.WGTransportConfig.Enabled` +
   `.Iface`) -- Susanin needs a real L3 interface to route into via
   `ip route ... dev <egress>`; Proxy0 has no such interface (NDM's own
   domain-triggered redirect, not a routable one). WG-transport gives us
   exactly that (xray is the WG server, `WGTransportConfig.Iface` e.g.
   `"Wireguard4"` is the Keenetic-side peer interface) -- pointing
   Susanin's `egress_interface` at it should, per how WG-transport already
   works, land Susanin-routed traffic in the currently-live vless/naive
   profile with zero new xray code. **The addon's first cut asks the
   operator for the OS-level interface name directly** (`egress=` config
   key) rather than resolving `WGTransportConfig.Iface` (the NDM name,
   e.g. "Wireguard4") automatically -- that resolution is possible (RCI's
   `show interface <iface>` has an `interface-name:` field, confirmed in
   `internal/keenetic/rci_reformat.go`; the value the operator needs is
   right there) but was deliberately deferred to keep the first PR small.
   The operator can find it themselves: `ndmc -c show interface
   Wireguard4` (or whatever `WGTransportConfig.Iface` is) → the
   `interface-name:` line.
2. **Keenetic's own DNS-based routing must be off** while this addon is
   active, per upstream's own README -- that's the exact mechanism our
   `routes`/Proxy0/preset-catalogue system depends on. Not automated
   (deciding to disable unrelated router config isn't this addon's call);
   the addon's `About()`/install flow must say so plainly.

### Phase 2 (bigger, NOT started, don't build until Phase 1 has proven out)

Port the classifier (`FAST`/`SOFT`/`JUDGE` thresholds,
`untested -> test -> ok` + `cooldown` states) to Go, feed it into xray's
own `dokodemo-door` inbound (`followRedirect: true`, config JSON shape
verified directly against `infra/conf/dokodemo.go` at our pinned
`xraycore.DefaultTag` -- `{"network":"tcp,udp","followRedirect":true}`, no
routing block needed, same no-routing-config default-outbound design
`GenerateXrayConfig` already has) via `iptables -t nat ... -j REDIRECT`
into our own mangle/ipset chain. Removes both Phase 1 preconditions (works
with any transport/outbound, doesn't fight `routes` since it only acts on
traffic that reached DIRECT unmatched) but needs real hardware recon first
(REDIRECT+FASTNAT interaction, UDP/QUIC REDIRECT reliability, legacy
iptables target availability) -- same discipline as the DNS/RCI/WG/nfqws2
arcs. See the plan file for the full risk list.

### Vendoring facts (verified against the real upstream repo, not guessed)

- Release assets: `susanin-keenetic-deploy-<upstream-arch>.tar.gz`
  (`aarch64`/`mipsel`/... naming, upstream's own convention) + one shared
  `SHA256SUMS` (standard `sha256sum` format, all arches). Tarball is flat
  (`./susanin-agent`, `./install.sh`, `./susanin.sh`, `./datapath.sh`,
  `./update.sh`, `./uninstall.sh`, `./config.example.conf`,
  `./vpn_always.txt`, `./vpn_never.txt`, `./DEPLOY.md`) -- no subdirectory.
- `susanin-agent` (mipsel v0.3.6): 827 KB, statically linked, not
  stripped. `.github/workflows/susanin-core.yml` re-tars the whole layout
  **unmodified** -- deliberately **not** UPX-packed: a real attempt at it
  (`--lzma` on the aarch64 build) produced a SIGILL under
  `qemu-aarch64-static` specifically (plain UPX on mipsel packed and ran
  fine), caught by actually dispatching the workflow, not assumed. Not
  worth chasing down for what a ~800 KB binary would save; xray-core/
  naive-core UPX-pack because their unpacked sizes (tens of MB) actually
  matter.
  `susanin-agent version` prints a bare version string and exits 0
  (confirmed from `src/main.c`) -- the smoke-test / `Version()` hook.
- Upstream's `install.sh` supports a fully offline, non-interactive mode:
  run it from the extracted tarball directory (it detects
  `susanin-agent` next to itself and skips downloading) with `--yes`.
  LAN interfaces/subnets auto-detect from `ip route` (looks for `br*`
  first) even non-interactively -- **`--egress` does not auto-detect
  usably for us** (its regex looks for `nwg`/`wg[0-9]*`/`amnezia`/`ovpn`-
  named interfaces and falls back to an interactive `/dev/tty` picker,
  which `die`s with no tty -- exactly the case when driven by our own
  addon/bot automation), so it must always be passed explicitly.
- `susanin.conf` is `KEY=value` shell format (`egress_interface`,
  `lan_interfaces`, `lan_subnets`, `health_probe`, `ok_ttl`,
  `vpn_always_file`, `vpn_never_file`, ... -- full list in upstream's
  README "Конфиг" table). Existing config/lists are never overwritten on
  reinstall unless `--force`.

## Current position

**Phase 1 shipped in one PR.** `.github/workflows/susanin-core.yml` +
`packaging/susanin-core/{version,README.md}` (mirror workflow, run for
real -- verify it's green before trusting `susanincore.PinnedVersion`
points at a real release). `internal/susanincore` (`Ensure` -- fetch,
verify, extract to a scratch dir, smoke-test `susanin-agent version`;
deliberately does *not* manage a fixed install location or know about
install.sh -- that split mirrors internal/naivecore's own scope, just one
level earlier since this asset is a tarball with its own installer inside).
`internal/addons/susanin.go` (`Addon` impl: `Install` runs upstream's
`install.sh --yes --no-start --prefix=/opt/susanin` from the extracted
scratch dir then discards it; `Configure` requires `egress=` and writes
`susanin.conf` via the existing `shellConfSet` helper nfqws2 already uses,
then restarts via `susanin.sh restart`; `Remove` gates on `susaninVersion`
succeeding -- consistent with `naiveCoreAddon`'s idempotent-remove
precedent -- and runs `uninstall.sh`; `Status`/`Detect` read
`egress_interface` out of the config to report "not configured yet" before
ever shelling out to `susanin.sh status`).

**No separate CLI command was added** (no `ensure-susanin-core` mirroring
`ensure-naive-core`) -- deliberately: naive-core needed one because
`internal/failover`'s sidecar manager references the bare binary directly
and points operators at that exact command in its own error text; nothing
in this project's own code needs susanin-agent present outside the addon's
own `Install`, so the already-generic `addon install susanin` /
`internal/botcontrol`'s 🧩 Дополнения screen (both dispatch over
`addons.All()`/`addons.Find()`, confirmed by reading `cmd/keenetic-xray/
addon.go` and `internal/botcontrol/telegram_addons.go` -- neither needed
any change) is the whole interface, on both CLI and bot, with zero
susanin-specific wiring beyond the `Addon` implementation itself.
Confirmed (by reading `openAddonScreen`/`addonScreenKB` in
`telegram_addons.go`) that the bot's component screen shows `About()` --
and therefore both hard preconditions -- *before* the "⬇️ Установить"
button is ever reachable, not just documented somewhere separate.

Tests throughout (`internal/susanincore`, `internal/addons`) pass; full
repo `go build`/`go vet`/`go test` green as of this PR.

Not done, not attempted: anything from Phase 2 (still just the plan in
memory); real-hardware verification of the whole Phase 1 flow (mipsel is
QEMU-smoke-tested via the mirror workflow same as xray-core/naive-core,
but installing via the bot end-to-end, resolving a real `egress=` value,
and confirming Susanin-routed traffic actually reaches the live
vless/naive egress through WG-transport has not been tried on the user's
actual router yet -- flag this the same way naive's mipsel path was
flagged before its own hardware confirmation).
