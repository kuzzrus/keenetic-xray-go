# Handoff — Susanin adaptive routing addon

Kickoff brief for a fresh session with no access to a previous session's
`.claude/memory/` files. Written 2026-09-13, repo at `v0.30.0` / `main`;
updated same day at `v0.30.12` after **Phase 1 was confirmed working
end-to-end on real hardware for the first time** -- see "Current
position" at the bottom for the full bug chain that took to get there.

For what this project is and the general working conventions ("делай и
сразу сливай" flow, CI checks, versioning, commit/PR trailers, language,
the `parse_test.go` CRLF gotcha), see
[`docs/HANDOFF-naive.md`](HANDOFF-naive.md) §1-2 — identical here, not
repeated.

## The task — an `internal/addons` wrapper for R17a/Susanin.Keenetic

[Susanin.Keenetic](https://github.com/R17a/Susanin.Keenetic) (MIT, C,
~v0.3.8) is a conntrack-based **adaptive router**: it watches
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
1. **WG-transport must be enabled.** Susanin needs a real L3 interface to
   route into via `ip route ... dev <egress>`; Proxy0 has no such
   interface (NDM's own domain-triggered redirect, not a routable one).
   WG-transport gives us exactly that (xray is the WG server, the
   Keenetic-side peer interface is what carries the traffic) -- pointing
   Susanin's `egress_interface` at it lands Susanin-routed traffic in the
   currently-live vless/naive profile with zero new xray code.
   **Auto-resolved as of the same-day follow-up (no longer a manual
   step when this holds)**: `Install()` calls `internal/keenetic.
   ActiveWGIface` (finds the interface carrying `WGIfaceMarker` without
   allocating a new slot the way `FreeWireguardIface` would) then
   `InterfaceOSName` and, if both resolve, writes `egress_interface` and
   brings the data plane up itself -- best-effort, any failure anywhere in
   that chain just falls back to today's manual path silently (Install
   must never fail over a convenience step). `internal/addons` deliberately
   has no access to `*config.Config` (established pattern -- addons are
   decoupled from keenetic-xray's own config, same as nfqws2's
   `isp_interface=`), so this discovers the marked interface directly off
   the router's own running config rather than reading
   `WGTransportConfig.Iface`. Manual `addon configure susanin
   egress=<iface>` remains the fallback/override for WG-transport-not-yet-
   enabled, or a different intended egress.
   **`InterfaceOSName` does NOT read the `interface-name:` field of `show
   interface` anymore** (it did originally; confirmed wrong on real
   hardware, see the bug chain below) -- it reads the interface's own
   `address:` field and finds which real kernel device currently carries
   that exact address via a new `ip -o addr show` scan
   (`kernelIfaceByAddress` in `internal/keenetic/wireguard.go`).
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
- `susanin-agent` (mipsel v0.3.8): 827 KB, statically linked, not
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

## 2026-09-13 live debugging arc -- Phase 1 confirmed on real hardware

Same day as the doc's initial write, the operator actually installed and
configured Susanin on a real router (aarch64, KeeneticOS, WG-transport
already active) via the bot. **Six more real bugs** surfaced in quick
succession -- each found by reading upstream's actual scripts/source
end-to-end against live command output, never guessed, same discipline
as the three bugs above. End state: `susanin.sh status` shows the data
plane fully `OK` (chain, PREROUTING jump, both `ip rule`s, default route
in table) and `daemon: RUNNING` with a populated cache
(`susanin_ok_tcp`/`_udp` in the hundreds from `vpn_always.txt`
resolving) -- **the first genuine end-to-end confirmation of Phase 1**,
not just QEMU/mirror-verified.

1. **(#150) Install unreachable on an already-installed router** --
   `addonInstall` in both dispatchers (`cmd/keenetic-xray/addon.go`,
   `internal/botcontrol/addons.go`) short-circuited on `Detect().Installed`
   before ever calling `Install()`. Harmless for opkg-based addons, but
   made the egress auto-resolve above unreachable for a router that
   already had the binary -- exactly the case that needed it. Every
   addon's own `Install` is already safe to re-run, so both dispatchers
   now always call it, keeping "already installed" only in the message.
2. **(#150) `ipset`/`conntrack` never installed** -- upstream's own README
   lists both as hard Entware requirements; neither upstream's scripts nor
   this addon ever installed them, so the data plane died with "ipset not
   found" the first time anything tried to bring it up. `Install()` now
   `opkgInstall`s both first.
3. **(#151) `looksLikeNDMName` heuristic was itself wrong** -- shipped in
   #148 on the assumption that a Keenetic WireGuard interface's kernel
   device name always differs from its NDM name (e.g. `nwg0` vs
   `Wireguard3`). Disproven on real hardware: `ndmc -c show interface
   Wireguard3` came back with `interface-name: Wireguard3` -- the
   identical string -- on this router/firmware. The heuristic was
   rejecting a manually-typed value that was actually correct. Removed;
   a manual `egress=` value is now accepted as typed, `datapath.sh`'s own
   bring-up is the only real judge.
4. **(#152) `interface-name:` isn't reliably the kernel name at all** --
   one step further: on this same router, `ip addr show Wireguard3`
   answered "can't find device" despite `show interface` reporting
   `interface-name: Wireguard3`. The real kernel device (found via
   `ip -o link show`, cross-checked by MTU 1280 + `UP,LOWER_UP`) was
   `nwg3` -- a completely different string. `InterfaceOSName` no longer
   trusts that field at all; it resolves the interface's `address:` field
   and finds which real kernel device currently holds that exact address
   (`kernelIfaceByAddress`, a new `ip -o addr show` scan) -- correct by
   construction, independent of NDM's naming convention for a given
   firmware/interface type.
5. Ruled out, for the record (each verified, each a dead end): `ip route
   add default dev nwg3 table 100` run *by hand* always succeeded cleanly
   -- table 250 vs 100 made no difference, installing Entware's `ip-full`
   (real iproute2, confirmed via the actual package index) over the base
   busybox `ip` made no difference, `nwg3`'s kernel flags were confirmed
   `UP,LOWER_UP` throughout. None of these were the bug -- but each was a
   real, necessary elimination, not wasted motion, because the eventual
   root cause (#6) meant *every* automated attempt failed identically to
   every manual isolation test succeeding, which is what pointed at "the
   invocation path itself must differ" rather than at the interface/table.
6. **(#153) THE root cause -- upstream's own `tools/susanin.sh` `install`
   case doesn't thread its own config through:**
   `install) sh "$TOOLS/datapath.sh" up; "$BIN" setup ;;` -- two commands.
   Only the second (`$BIN setup`, `backend_provision`/`set_env()` in
   `src/backend.c`) exports `SUSANIN_EGRESS`/`SUSANIN_LAN` from the loaded
   `susanin.conf`. The first, bare `datapath.sh up` call sees neither and
   silently falls back to `datapath.sh`'s own hardcoded default (egress
   `nwg0`) -- regardless of what's configured. `susanin.sh` runs under its
   own `set -eu`, so when that first call fails, it aborts right there,
   never reaching the second command that would have gotten it right.
   Live, `nwg0` existed but was administratively down (confirmed via
   `ip -o link show`: no `UP`/`LOWER_UP`), so "RTNETLINK answers: Network
   is down" was a true, honest error -- just about the wrong interface.
   Reproduces identically for a manual `sh susanin.sh install`, which is
   why #5's isolation tests kept coming back clean: it was never about
   automated vs. manual invocation. Fixed without touching upstream's
   file: `susaninApply` now calls a new `runScriptEnv` (sets
   `SUSANIN_EGRESS`/`SUSANIN_LAN`, read back from `susanin.conf`, in the
   child's own environment before running `susanin.sh install`/`restart`)
   -- a shell script's children inherit its environment, so the bare
   `datapath.sh up` call *inside* `susanin.sh` sees them too.

**Non-issue, for the record**: `engine_run` (`src/engine.c`) logs
`ERR: datapath provisioning failed` once at daemon startup if its own
redundant `backend_provision` call loses a race (seen once, likely
coincident with unrelated WireGuard handshake retry activity in `dmesg`
during this same debugging session) -- confirmed from source this is
non-fatal (`slogf` only, no exit) and self-heals via the engine's own
15-second `backend_ready`/re-provision reconcile loop either way.

**Corrected by a later PR (#155, same day)**: boot-time persistence is no
longer "not fixed" -- `EnsureSusaninRunning` hooks into
`cmd/keenetic-xray`'s existing periodic router-reconcile loop and starts
the daemon if it's installed+configured but not running. Superseded the
note that used to be here.

**Still known, not yet fixed**: manual `vpn_always.txt`/`vpn_never.txt`
list editing (currently SSH-only, no bot/CLI convenience).

Not done, not attempted: anything from Phase 2 (still just the plan in
memory).

## 2026-09-14 -- health-check is structurally incompatible with this project's WG-transport, forced off

Continuing the same live-hardware session (one day later). With Phase 1
confirmed working end-to-end, the operator hit a real, reproducible "works
for ~20 seconds after every restart, then goes back to doing nothing"
pattern -- traced fully before touching any code, same discipline as the
six bugs above.

**Root cause, confirmed against real upstream source (`src/health.c`,
`src/engine.c`) and real hardware (`ping -I <egress> 1.1.1.1`: 100% loss;
`curl --interface <egress>`: 200, full speed, same tunnel)**: upstream's
health-check is a raw ICMP ping to `health_probe`'s targets. This
project's WG-transport egress is xray's own WireGuard *inbound*
implementation (userspace, not a kernel WG pair) -- it proxies real
TCP/UDP application traffic fine but never replies to ICMP through the
tunnel at all. `engine_run`'s main loop calls `health_probe()` every
`health_interval` regardless of state; each miss increments a counter,
and once it reaches `health_miss_debounce` (upstream default 4, so ~20s)
the engine sets `tunnel_up = 0`, logs `"tunnel DOWN, fail-open DIRECT"`,
and flushes every ipset (`backend_ipset_flush`). Critically, `tunnel_up`
also gates the *entire* per-destination classifier
(`clr_fast`/`clr_soft`/`clr_judge` in the main loop all check it, not
just whether to route already-confirmed destinations) -- and recovery
requires a *successful* ICMP reply, which this tunnel will never produce,
so once tripped it never self-heals. Net effect: since `tunnel_up` starts
at 1 on daemon start, susanin classifies and routes correctly for the
first ~20 seconds after every restart, then permanently stops doing
anything until the next manual restart. This explains both the "empty
ipsets whenever anyone checks" symptom and the "brief flash of a working
preview, then nothing" one the operator described -- both are the same
fail-open cycle, not two different bugs.

**Fix**: `susaninApply` (shared by `Configure` and `Install`'s
auto-configure) now unconditionally forces `health_miss_debounce=999999`
into every write to `susanin.conf`, regardless of what the caller's own
`set` asked for. This isn't a per-router tunable -- it's a structural
mismatch between upstream's ICMP-based health-check and how *this
project's* WG-transport is implemented, so it applies to every
installation using it, not just misconfigured ones. Verified live: after
applying manually and restarting, `susanin.log` showed continuous
`AUTO-SUSANIN: FAST/CONFIRMED` classifier activity for 9+ minutes with no
further `tunnel DOWN`, and `susanin_ok_tcp` went from empty to 300+
real entries (Telegram's `149.154.x.x`, Meta's `31.13.72.x`/`157.240.x.x`,
plus a large stretch of Google ranges from `vpn_always.txt`). Telegram and
Instagram access were confirmed working end-to-end on the phone afterward.

**Separate, non-bug finding from the same test**: YouTube video playback
and Speedtest still didn't work even with the classifier running
correctly. Not a bug -- both serve their actual payload from a large,
per-session-dynamic pool of server IPs (YouTube: per-edge hostnames like
`rr3---sn-xyz.googlevideo.com`, resolved fresh per session; Speedtest:
geographically-distributed third-party test servers, chosen per run).
Susanin's reactive per-IP classifier can only ever catch up to *already
observed* destinations -- it structurally cannot pre-empt a pool this
large and this dynamic. This project's own domain-based routing
(`routes`/`presets` -- `youtube` and `speedtest` are already in the
catalogue, see the geo-presets arc in [[bot-feature-roadmap]]) doesn't
have this limitation: it snoops the live DNS *query* for any subdomain
matching the object-group's pattern, so a never-before-seen
`rr3---sn-xyz.googlevideo.com` is caught the moment it's looked up, not
after the fact. `About()` now says this plainly: Susanin is for the
unpredictable long tail not already in a domain list, not a replacement
for domain-based routing on large, well-known CDN-backed services.

## 2026-09-14 -- mirrored v0.3.8, which restores a real classifier regression relevant to the YouTube/Speedtest finding above

Checked upstream for updates past the v0.3.6 pin: v0.3.7 (2026-09-13) was
already confirmed text/docs-only (`gh api .../compare/v0.3.6...v0.3.7`,
matches the entry above). **v0.3.8** (2026-09-14) is not cosmetic --
`src/classifier.c` diff (+99/-6) restores `TCP-LATE-STALL`/
`QUIC-LATE-STALL` detection (a flow that got a reply and then went quiet
-- the classic DPI-throttle pattern) that had been *removed* as part of
v0.3.5's "tightened candidate logic" (only fully silent flows qualified as
candidates from v0.3.5 through v0.3.7). Upstream's own changelog names the
exact regression this caused: YouTube preview/video and x.com/Instagram
media auto-learning stopped working between v0.3.5 and v0.3.8.

This directly touches the "YouTube video/Speedtest -- not a bug,
structural" finding in the section above, which was tested against the
v0.3.6 pin -- i.e. *with* this regression still in place. The "large,
per-session-dynamic IP pool" reasoning likely still holds for full video
playback (no per-IP pin helps against an edge IP never seen before), but
some of what was actually observed (previews specifically, and the
x.com/Instagram media symptom) may have been this regression rather than
a structural limit. Not re-tested on hardware yet -- worth doing once this
pin is live, before restating the earlier finding as settled.

Mirrored and smoke-tested (both arches, QEMU): `susanin/v0.3.8` has all 6
assets. `susanin-agent` size essentially unchanged (827168 B mipsel,
851088 B arm64) despite the classifier diff -- the UPX-packing conclusion
above still holds. `PinnedVersion`/`packaging/susanin-core/version`
bumped v0.3.6 -> v0.3.8 in the same PR.
