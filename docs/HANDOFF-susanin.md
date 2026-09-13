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
`install.sh --yes --no-start --prefix /opt/susanin` (two args -- upstream's
arg parser is a plain `case "$1" in --prefix) PREFIX="$2"; shift ;; ...`,
no GNU `--flag=value` support, see the 2026-09-13 bug note below) from the
extracted scratch dir then discards it; `Configure` requires `egress=` and
writes `susanin.conf` via the existing `shellConfSet` helper nfqws2 already
uses, then runs `susanin.sh install` (data plane: iptables chain, ip
rules/routes, ipsets -- idempotent, distinct from the daemon process) and
only then `susanin.sh restart`; `Remove` gates on `susaninVersion`
succeeding -- consistent with `naiveCoreAddon`'s idempotent-remove
precedent -- and runs `uninstall.sh` (which itself tears the data plane
down via `datapath.sh down`); `Status`/`Detect` read `egress_interface`
out of the config to report "not configured yet" before ever shelling out
to `susanin.sh status`).

**Three live bugs found and fixed post-ship (2026-09-13, on real hardware),
all from the same root mistake -- trusting the wrapper's own shape instead
of checking upstream's actual scripts/parsers byte-for-byte:**
1. `--prefix=/opt/susanin` (one combined arg) hit upstream's `unknown arg`
   fallback -- its case-statement parser only accepts `--prefix DIR` as two
   separate args. The shipped test had asserted the same wrong combined
   form as "expected", so it never caught this.
2. `Configure` only ever ran `susanin.sh restart` (daemon process only).
   `susanin.sh install` (-> `datapath.sh up` + `$BIN setup`) is a *separate*
   upstream command that actually creates the data plane, and nothing in
   Phase 1 ever called it -- so the daemon ran (or tried to) against a data
   plane that never existed. Fixed by calling `install` before `restart` in
   `Configure`.
3. `Remove` (🗑 Удалить in the bot) stopped the daemon and tore down the
   data plane, but never actually deleted anything -- looked like a no-op.
   Cause: upstream's `uninstall.sh` runs under `set -e` and, unconditionally
   (not inside an `if`), does `[ -f "$INITD" ] && rm -f "$INITD" && say
   ...` where `INITD=/opt/etc/init.d/S94susanin`. Confirmed against the
   real upstream deploy tarball (`tar -tzf` on the actual release asset)
   that it does **not** contain `S94susanin` at all -- that file lives only
   in the git checkout's `init/entware`/`init/openwrt`, for someone
   following the full manual DEPLOY.md flow by hand. So `install.sh`'s own
   `[ -f "$DIR/S94susanin" ]` copy-if-present guard never fires for us
   either, `$INITD` never exists on a router this addon installed, and
   that bare `[ -f ... ] && ...` statement's non-zero exit aborts
   `uninstall.sh` right there -- before it ever reaches the real `rm -rf
   "$PREFIX/bin" "$PREFIX/tools"` a few lines down. Fixed by having
   `Remove` touch an empty placeholder at `$INITD` before calling
   `uninstall.sh` -- upstream's own script then removes it as part of its
   normal cleanup, no patch to upstream's file needed.

**Known, not yet fixed**: bug #3's root fact -- `S94susanin` is never
present on a router this addon installed, at all, ever -- means susanin
currently has **no boot-time start of any kind**, not "starts but doesn't
reassert the data plane" as previously (incorrectly) noted here. A router
reboot leaves susanin fully stopped until the operator manually reopens
🧩 Дополнения → Susanin and reconfigures. Candidate fixes: hook susanin's
presence+data-plane into this project's existing `routerReconcileLoop`/
ndm-event self-heal (same mechanism that already re-asserts MSS clamp/
routes/WG-transport) rather than trying to install upstream's own
`init/entware/S94susanin` (which itself would still need the same `install`
step #2 fixed for, so reconcile-loop is likely the more complete fix
either way). Not built yet.

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
repo `go build`/`go vet`/`go test` green.

**Mirror workflow dispatched for real and confirmed green (v0.30.1),
after two real bugs found by actually running it rather than trusting the
YAML on paper** (PRs #139, #140): the re-tar step originally packed
archive members as `./susanin-agent` (from `tar -czf out.tar.gz .` inside
the extracted dir), but the smoke-test step's named-member extraction
needed an exact `susanin-agent` match -- fixed by globbing (`tar -czf
out.tar.gz *`) instead. Then UPX `--lzma` on the aarch64 build produced a
SIGILL under `qemu-aarch64-static` (mipsel's plain UPX packed and ran
fine) -- not worth chasing for an 827 KB binary, so UPX packing was
dropped entirely; the workflow now re-hosts upstream's tarball verbatim.
`susanin/v0.3.6` has all 6 assets (both arches) as of this note. **Phase 1
is now actually done, not just merged.**

Not done, not attempted: anything from Phase 2 (still just the plan in
memory); real-hardware verification of the whole Phase 1 flow (mipsel is
QEMU-smoke-tested via the mirror workflow same as xray-core/naive-core,
but installing via the bot end-to-end, resolving a real `egress=` value,
and confirming Susanin-routed traffic actually reaches the live
vless/naive egress through WG-transport has not been tried on the user's
actual router yet -- flag this the same way naive's mipsel path was
flagged before its own hardware confirmation).
