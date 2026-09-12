# Handoff — NaiveProxy support

Kickoff brief for a fresh session (possibly a different account, so it has
**no access to the previous session's `.claude/memory/` files**). Everything
needed to continue is here. Written 2026-09-08, repo at `v0.27.2` /
`main@7e3d4b3`.

---

## 1. What this project is

`keenetic-xray-go` — a single Go binary (`keenetic-xray`) that installs and
manages **Xray (VLESS)** on **Keenetic** routers with **Entware**, with
automatic **failover** between a primary and a backup server, domain-based
routing, secure DNS (DoT/DoH), an in-router WireGuard transport, and full
remote control from a **Telegram bot** (a separate `keenetic-xray-control-server`
binary runs on a VPS). One `.ipk` per arch — **`aarch64` and `mipsel` only**.

Docs: `docs/architecture.md`, `docs/bot-control-design.md`, `docs/routing.md`,
`docs/dns.md`, `docs/full-vs-mini.md`, `packaging/xray-core/README.md`.

## 2. Working conventions (follow these)

- **Flow: "делай и сразу сливай"** — branch → PR → wait for green CI → squash-merge
  → `git checkout main && git pull` → `git tag vX.Y.Z && git push origin vX.Y.Z`
  → `release.yml` publishes. Minimal pause between.
- **CI checks** that must pass before merge: `test`, `build (arm64, qemu-aarch64-static)`,
  `build (mipsle, softfloat, qemu-mipsel-static)`.
- **Versioning**: patch bump for fixes/small feats, minor bump (`v0.X.0`) at a
  notable feature milestone. Tag drives the release (`-ldflags -X version.Version`).
- **Language**: all user-facing prose (chat replies, PR/commit *bodies* in
  Russian is fine but this repo's commits/PRs have been **English subject +
  Russian-or-English body**; recent PRs use Russian bodies). Code, identifiers,
  comments: **English**.
- **Commit trailer**: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`
- **PR body trailer**: `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- **Known gotcha**: `internal/subscription/parse_test.go` picks up a CRLF
  artifact on this Windows checkout — **never stage it**; `git add` files
  explicitly, don't `git add -A` blindly if it shows modified.
- **Test/build locally**: `go build ./...`, `go vet ./...`, `go test ./...`.
  `internal/botcontrol` tests take ~37 s. Windows AV occasionally locks the
  botcontrol test binary — `go vet` + CI cover it.
- Respond to the user in **Russian**.

## 3. Recently shipped (context for the current codebase)

An arc of borrows from the parallel project `BROadmin/BROray` (shell + WebUI
Keenetic-Xray manager), plus an xray-core bump:

| ver | PR | what |
|---|---|---|
| v0.26.6 | #109 | `Profile.ImportKey()` — subscription slot anchored to a connection fingerprint, not list position (a provider reorder silently repointed a slot). `SlotSource.ImportKey`, `subscription.ResolveSourcePinned`. |
| v0.26.6 | #110 | `subscription.ApplyResult` never loses the active server on refresh — adopts a renamed node by ImportKey, else keeps last-good. |
| v0.27.0 | #111 | **periodic quality sweep** — `failover.quality_sweep_minutes` (0/15..1440); `internal/health` `Sweeper` probes *every* saved profile through a scratch xray on `PretestPort+1`; result in `<logdir>/quality.json`, shown in `status`. Never touches live/pretest xray. |
| v0.27.1 | #112 | **self-update rollback** — `internal/selfupdate`: `selfUpdate` drops a marker (prev version + release `.ipk` URL, arch via `opkg print-architecture`); `cmd/keenetic-xray/selfupdate.go` `watchPostUpdate` waits ≤2 min for the failover machine to steady, emits ✅ or ⚠️ (naming `keenetic-xray internal self-rollback`); `internal self-rollback` = download marked `.ipk` + `opkg install --force-downgrade --force-reinstall`. `botcontrol.Merge(ctx, …)` fan-in. |
| v0.27.2 | #113/#114 | xray-core `PrereleaseTag` `v26.7.28` → **`v26.9.8`** (upstream stable = `v26.3.27`, that's `DefaultTag`, unchanged). Vendored build run + README sync. |
| — | #115 | README neon SVG banner + repo About/topics. |

`internal/health` (quality sweep) and `internal/selfupdate` are the two most
recent new packages — study them; the Naive sidecar reuses the same patterns
(scratch process on a `PretestPort+N` port, seams for tests, opt-in binary).

## 4. THE TASK — NaiveProxy via a vendored `naive` sidecar

### Scope decision (locked with the user)

Add **NaiveProxy** support. **VLESS + Naive only.** VMess / Trojan / SOCKS /
Hysteria2 are **dropped** ("прошлый век" — user). So `Profile.Protocol` needs
only `""` (= vless, back-compat) and `"naive"`.

### Why this shape (rejected alternatives — don't relitigate)

- **Fork xray-core + compile Naive in** — NO. Naive is C++/Chromium-net;
  there's no Go impl to lift, you'd reimplement the h2 padding protocol from
  scratch inside a hard fork → rebase every upstream release, security lag,
  breaks the "rebuild XTLS/Xray-core@tag verbatim + provenance" trust model.
  XTLS considered it (2023, [discussion #1993](https://github.com/XTLS/Xray-core/discussions/1993))
  and built `xhttp`/`splithttp` instead.
- **XHTTP** — xray's *native* answer to "browser-like traffic + padding vs
  DPI", and **already supported here** (incl. the `xhttp_extra` blob: `xmux`,
  `scMaxEachPostBytes`, `xPaddingBytes`). Real Naive is only for **interop**
  with an existing Caddy + `forward_proxy` server a provider gave the user.
- **naive-lite** (xray `http` outbound + uTLS chrome fp + h2 ALPN) — cheap,
  but no frame padding. A fallback, not the plan.
- **sing-box as a 2nd engine** — BROray-scale pivot, not worth it.

### Architecture — `naive` as a separate egress process (NOT an xray outbound)

```
LAN → Keenetic Proxy0/WG
      → xray  (our inbound; geo-routing; MSS; the health-probe)
          └─ outbound "proxy" = socks 127.0.0.1:<naivePort>   (xray socks outbound, no auth)
      → naive --listen=socks://127.0.0.1:<naivePort>
              --proxy=https://user:pass@host:443 --log
          └─ HTTP/2 CONNECT + uTLS Chrome + frame padding → Caddy forward_proxy server
```

xray keeps the LAN inbound, routing, MSS and the health probe. The existing
`xrayctl.Probe` (through xray's inbound) tests the whole chain — **no probe
changes**. A "naive profile" is `Profile.Protocol=="naive"`, so
failover primary=vless / backup=naive works for free.

### Phased plan

Split into **3 PRs** (the memory doc said 2; PR 1 is cleanly splittable and
smaller PRs merge faster — but 2 is fine too):

#### PR 1a — `Profile` fields + `ParseNaiveURI` (config layer, inert)
- `config.Profile`: add `Protocol string` (`json:"protocol,omitempty"`, `""`→vless),
  `User string` (`json:"user,omitempty"`), `Password string` (`json:"password,omitempty"`).
- `Profile.Validate()` — branch on `Protocol`:
  - `""`/`"vless"` → current checks unchanged.
  - `"naive"` → require `Address`, valid `Port`, `User`, `Password`; `UUID` **not**
    required (naive has no UUID); ignore the vless `Network`/`Security`/reality checks.
- `Profile.ImportKey()` — prepend `lc(p.Protocol)` (empty → `"vless"`) to the
  `fields` slice so a vless and a naive endpoint on the same host:port don't
  collide. `User`/`Password` stay **out** of identity (rotation = same server).
- `Config.Redacted()` — in the `d.Profiles` loop also `p.User = mask(p.User)`
  and `p.Password = mask(p.Password)`.
- New `internal/config/naiveuri.go`: `ParseNaiveURI(raw string) (Profile, error)`
  — accept `naive+https://user:pass@host:port#remark` (also bare `naive://…`?
  decide; klzgrad share links are usually `naive+https://`). `quic://` proxy →
  return a clear "quic not supported yet" error. Mirror `vlessuri.go`'s style
  (`net/url`, percent-decoded fragment as `Remark`, `Remark==""` → `Address`).
  Also a `Profile.NaiveURI()` round-tripper if cheap.
- Tests: `internal/config/naiveuri_test.go`, `Profile.ImportKey`/`Validate`/
  `Redacted` cases for `Protocol=="naive"`.
- **Not** wired into `subscription.Parse` or `buildOutbound` yet — those stay
  as-is, so this PR changes zero runtime behavior.

#### PR 1b — `internal/naivecore` + build/mirror workflow + `ensure-naive-core`
Mirror `internal/xraycore` (read it first — `xraycore.go` is 283 lines), but
**simpler**: no opkg fallback, no version-wrong-detection.
- `internal/naivecore/naivecore.go`:
  - `const PinnedVersion = "v150.0.7871.63-1"` (klzgrad's tag format) — kept in
    sync with `packaging/naive-core/version` (add a test like
    `xraycore_test.go`'s `TestDefaultTag_MatchesPackagingPin`).
  - `const defaultBaseURL = "https://github.com/kuzzrus/keenetic-xray-go/releases/download/naive-core"`
  - `Ensure(ctx, Options{Dest, Version, BaseURL, HTTP, Force, smoke})` — fetch
    `naive-<ver>-linux-<goarch>` + `.sha256`, verify, smoke `<bin> --version`
    (naive exits 0 for `--version`), atomic rename into `Dest`
    (`/opt/sbin/naive` default). Reuse the download/verify helpers from
    `xraycore` — either copy `fetchExpectedSum`/`downloadVerified`/`httpGet`
    (~60 lines) or extract them to a shared `internal/vendorbin`. Copy is
    lower-risk for a first cut.
- `packaging/naive-core/version` — file containing `v150.0.7871.63-1`.
- `packaging/naive-core/README.md` — mirror `packaging/xray-core/README.md`.
- `.github/workflows/naive-core.yml` — `workflow_dispatch` (input: `naive_version`).
  **No compilation.** Per arch (arm64, mipsle):
  1. `curl -fL` klzgrad's asset:
     `https://github.com/klzgrad/naiveproxy/releases/download/<ver>/naiveproxy-<ver>-openwrt-<TAG>.tar.xz`
     where `<TAG>` = `aarch64_generic-static` (arm64) / `mipsel_24kc-static` (mipsle).
     **Use the `-static` openwrt builds** — no libc dependency, safest for Entware.
  2. `tar -xJf`, take the `naive` binary.
  3. `upx -9 --lzma` (arm64) / `upx -9` NRV (mipsle — LZMA doesn't cover mips ELF);
     also keep a raw `.xz` fallback. Exactly like `xray-core.yml`.
  4. Write `naive-<ver>-linux-<goarch>.provenance.txt` (upstream URL, both
     sha256s, Chromium/naive version).
  5. `gh release upload naive-core/<ver> --clobber` the packed binary + `.xz` +
     `.sha256` + `.provenance.txt`.
  Model the whole file on `.github/workflows/xray-core.yml`.
- `cmd/keenetic-xray/internal.go` — add `case "ensure-naive-core": return cmdEnsureNaiveCore(args[1:])`.
  Small `cmd/keenetic-xray/naivecore.go` wrapping `naivecore.Ensure` (dest =
  a new `naiveBinaryPath()` in `paths.go`, e.g. `/opt/sbin/naive`, env
  `KEENETIC_XRAY_NAIVE_BINARY`).
- Postinst: do **not** fetch `naive` by default. Fetch it only when a naive
  profile exists (PR 2 wires that) or on explicit `ensure-naive-core`.
- **Run the `naive-core` workflow for `v150.0.7871.63-1` and confirm green +
  release assets before merging anything that references it.**

#### PR 2 — sidecar lifecycle in failover (the meat)
- `config.XrayConfigOptions.SidecarSOCKS int`. In `internal/config/xray.go`
  `buildOutbound`, when `p.Protocol=="naive"` → return
  `{Tag:"proxy", Protocol:"socks", Settings:{servers:[{address:"127.0.0.1", port:opts.SidecarSOCKS}]}}`
  (no streamSettings). `GenerateXrayConfig` must reject `Protocol=="naive"` with
  `SidecarSOCKS==0` (a clear "naive egress port not set" error).
- `internal/failover/realActions` — a naive-process manager. `xrayctl.Supervisor`
  is hardcoded to `xray run -c <config>` (`supervisor.go` ~line 143); give it an
  `Args []string` mode, **or** write a thin `naivectl` supervisor. `naive` is
  configured by flags only (`--listen=socks://127.0.0.1:<port>
  --proxy=https://<User>:<Password>@<Address>:<Port> --log`), no config file.
  Wire start/stop into:
  - `SwitchLiveTo(role)` — selected profile is naive → ensure production naive
    on `PretestPort+2`, pass its port as `SidecarSOCKS` into
    `GenerateXrayConfig`; leaving a naive profile → `Stop()` it.
  - `StartIsolatedPretest` — `Primary()` is naive → pretest naive on
    `PretestPort+3` + the scratch pretest xray points at it.
  - `internal/health` sweep — a naive profile → scratch naive on `PretestPort+4`
    (in `internal/health/sweep.go`, alongside the scratch xray).
- `naive` stderr → daemon log via `applog.Tee` (see how the xray Supervisor's
  `Stderr` is fed in `cmd/keenetic-xray/main.go`).
- `subscription.Parse` (`internal/subscription/parse.go`) — stop skipping
  `naive+https://` / `naive://` lines; route them to `config.ParseNaiveURI`.
- `status` (`internal/botcontrol/commands.go` `RouterHandler.status` +
  `cmd/keenetic-xray/status.go`): line `egress: naive → <host> (сайдкар ✅/⚠️)`.
  `doctor`: a "naive process alive" check when the active profile is naive.
- Tests: `ParseNaiveURI` (in 1a), config-gen naive branch, the sidecar
  lifecycle with a fake supervisor, a failover cycle with a naive backup.

### Size (measured, klzgrad `v150.0.7871.63-1`)

- `naive` unpacked: **arm64 12.2 MB, mipsel 13.9 MB** (`.tar.xz` ~3.3 MB).
  After UPX ≈ **~4 MB arm64 / ~7–8 MB mipsel**. (xray-core for comparison:
  31 MB → 7.5 MB.)
- Our `keenetic-xray` binary / `.ipk`: **~+15–25 KB** (pure Go stdlib, no deps).
  `naive` is **not** in the `.ipk` — separate `naive-core/<ver>` release,
  opt-in download.
- **RSS ~20–40 MB** while `naive` runs (Chromium-net stack). On 64–128 MB
  routers this is the real cost. Transient pretest/sweep naive processes must
  always be killed (ctx-cancel + `Process.Kill`, like `internal/health`).

### Risks / verify on hardware

1. **mipsel `naive` actually starts on Keenetic MIPS** (MediaTek/Realtek
   mips32 LE). The `-static` openwrt build removes the libc question, and
   both arches now smoke-test clean under **QEMU** user-mode emulation
   (`naive-core.yml`, run for `v150.0.7871.63-1` -- see section 7). QEMU is
   not the real thing, though -- still needs a live-router test before this
   risk is closed.
2. RSS budget on small routers (above).
3. v1 = `https://` proxy (h2, TCP) only. `quic://` needs open UDP egress — defer.
4. `xrayctl.Supervisor` is `-c <config>`-bound — needs an args mode or a sibling.
5. Two long-lived processes (xray + naive) + transient ones — teardown discipline.

## 5. How xray-core vendoring works (the model `naivecore` mirrors)

- `packaging/xray-core/version` = `v26.3.27` (the stable pin) — a test enforces
  `== xraycore.DefaultTag`.
- `xraycore.DefaultTag` (stable, auto-installed) / `xraycore.PrereleaseTag`
  (`v26.9.8`, opt-in only via `--tag=` / bot).
- `.github/workflows/xray-core.yml` — `workflow_dispatch`, checks out
  `XTLS/Xray-core@<tag>`, `go build ./main` with `-trimpath -ldflags "-s -w
  -buildid="`, UPX-packs per arch, QEMU smoke-tests `xray version`, uploads to
  a `xray-core/<tag>` release (binary + `.xz` + `.sha256` + `.provenance.txt`).
- `xraycore.Ensure` — fetch `xray-<tag>-linux-<goarch>` from
  `releases/download/xray-core/<tag>`, sha256-verify, smoke-test in a temp
  file, atomic rename over `/opt/sbin/xray`; opkg fallback. `Force` = the
  "upgrade to `<tag>`" path.
- `naive-core.yml` is the same shape **minus the `go build`** — it downloads a
  prebuilt binary instead.

## 6. NaiveProxy reference facts

- **Wire protocol**: HTTP/2 (or HTTP/3 QUIC) CONNECT tunnels to a server
  running Caddy + the `forward_proxy` plugin (NaiveProxy's padding fork), with
  Chrome's real TLS stack + frame padding (payload / RST_STREAM / HEADERS) on
  the first 8 reads/writes. The padding + Chrome-identical h2 IS the value over
  a plain HTTP-CONNECT-over-TLS proxy.
- **Client**: one self-contained `naive` binary. Config via flags
  (`naive --listen=… --proxy=…`) or a small `config.json`. No runtime dirs.
  Listen URI `socks|http|redir://[user:pass@]addr:port` (default
  `socks://0.0.0.0:1080`). Proxy URI `http|https|quic|socks://[user:pass@]host[:port]`.
- **Official prebuilt releases** (`github.com/klzgrad/naiveproxy/releases`) —
  cover our arches: `naiveproxy-<ver>-linux-arm64.tar.xz`,
  `…-linux-mipsel.tar.xz`, and `…-openwrt-aarch64_generic-static.tar.xz` /
  `…-openwrt-mipsel_24kc-static.tar.xz` (use the **static openwrt** ones for
  Entware). Latest as of writing: `v150.0.7871.63-1` (Chromium 150).
- **Not in xray-core** (`XTLS/Xray-core/main/distro/all/all.go` registers
  vless/vmess/trojan/shadowsocks/wireguard/socks/http — no naive, no hysteria2).

## 7. Current position (updated 2026-09-12)

- **PR 1a done — #129, released as v0.28.6.** `config.Profile.Protocol`/`User`/
  `Password`, `Validate()` split into `validateVLESS`/`validateNaive`,
  `ImportKey()` folds in Protocol, `Redacted()` masks User/Password,
  `internal/config/naiveuri.go` `ParseNaiveURI`. Inert -- nothing calls it yet.
- **PR 1b done — #130, released as v0.28.7.** `internal/naivecore` (mirrors
  `xraycore`'s Ensure shape, no opkg fallback, no version-drift auto-upgrade),
  `.github/workflows/naive-core.yml`, `keenetic-xray internal ensure-naive-core
  [--force]`, `packaging/naive-core/{version,README.md}`.
  **The mirror workflow has been run for real** for `v150.0.7871.63-1` and
  succeeded on the first try -- both arches mirrored, UPX-packed (arm64
  12.2MB→3.3MB; mipsle 13.9MB→4.9MB), and **QEMU-smoke-tested `naive --version`
  successfully**. Release `naive-core/v150.0.7871.63-1` exists with both
  binaries + `.xz` fallbacks + `.sha256` + `.provenance.txt`. This is
  QEMU-verified, not yet confirmed on real Keenetic hardware -- risk #1 in
  section 4 above still stands.
- **PR "2a" done — #132, released as v0.28.8.** Split out of PR 2's original
  scope because it turned out cleanly separable: `config.ParseProfileURI(raw)`
  is now the one dispatch point (`vless://` → `ParseVLESSURI`, `naive+` →
  `ParseNaiveURI`), swapped in at all 5 places that used to hardcode
  `ParseVLESSURI` -- `profile add`, `setup --from=`/the interactive wizard,
  `subscription.Parse`, `subscription.ResolveSource(Pinned)`. So
  **`subscription.Parse` no longer skips `naive+https://` lines** -- step 5
  below is already done, don't redo it. Also added a safety guard in
  `buildOutbound` (superseded by PR 2, see next bullet): reject
  `Protocol=="naive"` up front rather than silently falling through to a
  vless outbound built from empty fields.
- **PR 2 done — #133 (the sidecar lifecycle itself).** `xrayctl.Supervisor`
  gained an `Args []string` field (`nil` -> today's `xray run -c <config>`
  unchanged; non-nil replaces it -- naive is flags-only, no config file).
  `config.XrayConfigOptions.SidecarSOCKS`; `buildOutbound`'s naive branch (the
  PR 2a reject-guard) now emits a real `socks` outbound to
  `127.0.0.1:<SidecarSOCKS>`, still erroring clearly if that's `0`.
  `internal/failover/realActions` gained `prodNaive`/`pretestNaive` +
  `ensureNaiveSidecar(existing, profile, port, name)`, wired into
  `SwitchLiveTo` (`PretestPort+2`), `StartIsolatedPretest` (`PretestPort+3`),
  `StopIsolatedPretest`, and `Daemon.Run`'s shutdown defer. `Paths.NaiveBinary`
  wired to the existing `naiveBinaryPath()` in `cmd/keenetic-xray/main.go`.
  **Deviation from the plan below worth knowing**: `ensureNaiveSidecar` always
  stops the *existing* sidecar before starting the replacement (not the other
  way around) -- each role has one fixed local port, so an old and new
  sidecar can never both be bound to it at once; matches how `a.prod.Restart()`
  already works for the xray process itself (stop, then start). Confirmed via
  `state.go` that `SwitchLiveTo`/`StartIsolatedPretest` only fire on actual
  state transitions, not every tick, so this doesn't flap the sidecar in
  steady state. **Deferred as follow-up polish, not done in #133**:
  `status`/`doctor` naive-health lines (step 6 below), `internal/health`
  sweep's own scratch-naive probe on `PretestPort+4` (part of step 4 below),
  port-overlap validation in `config.Validate()`.
- `main` is past `7e3d4b3` -- don't rely on that commit hash below; check
  `git log --oneline -5` and `gh pr list --state open`.
- **Naive is now fully functional end-to-end** (parse a `naive+https://` link
  → `profile add`/`setup`/subscription → failover primary or backup → real
  sidecar process → xray egress through it). What's left is the polish items
  just above, plus real-hardware verification (risk #1).
- **v0.29.1 (unreleased-number-TBD as of writing) — two fixes/additions found
  by the user actually testing on a live router, right after #133 shipped:**
  1. `internal/health`'s quality sweep (separate from live failover, informational
     `/status` block) called `config.GenerateXrayConfig` with no `SidecarSOCKS`
     for every profile it swept -- always erroring for a naive profile and
     showing it as a false "⚠️ недоступен", even though the real failover path
     (with its sidecar) worked fine. Fixed by skipping naive profiles in the
     sweep (`SweepOnce`) rather than misreporting them; a real sweep probe via
     a transient scratch sidecar is still the deferred item above, now with a
     concrete reason it matters.
  2. `internal/addons` gained a `naive-core` addon (`internal/addons/naivecore.go`,
     wrapping `naivecore.Ensure`/`Version`/a plain file remove) -- so the bot's
     🧩 Дополнения screen and `keenetic-xray addon install naive-core` are now
     an alternative to SSH + `internal ensure-naive-core` for getting the
     binary onto the router. Both call sites already drove entirely off
     `addons.All()`/`addons.Find()`, so registering the addon was the whole
     feature -- no bot/CLI code needed touching beyond a couple of doc-comment
     and blurb-text mentions.
     **While wiring this up, found a real, separate bug**: the bot's own 🔗
     Источники wizard (`internal/botcontrol/telegram_wizard.go`,
     `wizardSetSlotSource`) had its *own* hardcoded `vless://`/`http(s)://`
     prefix check, independent of (and never updated alongside) PR "2a"'s
     `config.ParseProfileURI` sweep -- a pasted `naive+https://` link was
     rejected by the control server before ever reaching the router. This is
     why "5 places" in the PR 2a note above turned out to be 6; the bot
     wizard lives in a different package tree (`internal/botcontrol`, control
     server) from the other 5 (router/shared), which is exactly why it got
     missed. Fixed the prefix check and the prompt text.

## 8. First concrete steps (for the deferred polish, if picked up)

```bash
git checkout main && git pull
git checkout -b feat/naive-polish   # or whatever the actual next piece is called
```
Everything in section 4/7's "PR 2" scope is done (see §7 above) except:
1. `internal/health`'s sweep (`internal/health/sweep.go`) -- when a saved
   profile being swept is `Protocol=="naive"`, start a scratch naive sidecar
   on `PretestPort+4` alongside the scratch xray, same
   start/probe/kill-in-defer shape the sweep already uses for xray. Study
   `realActions.ensureNaiveSidecar` in `internal/failover/daemon.go` first --
   same stop-then-start reasoning applies if the sweep ever reuses a sidecar
   across ticks (it currently doesn't; every sweep tick is a fresh scratch
   process for xray too, so a naive sidecar would naturally follow the same
   fully-transient pattern with no reuse to reason about).
2. `status`/`doctor` -- an "egress: naive → host (сайдкар ✅/⚠️)" line
   (`cmd/keenetic-xray/status.go` + `internal/botcontrol/commands.go`'s
   `RouterHandler.status`). Read `d.actions.prodNaive` (or expose a small
   accessor) for `.Running()`.
3. Decide whether `config.Validate()` should cross-check
   `Failover.PretestPort+{2,3}` against `SOCKSPort`/`HTTPPort`/`PretestPort`
   for accidental overlap -- currently unchecked, consistent with how those
   existing ports aren't cross-checked against each other either.
4. `go build ./... && go vet ./... && go test ./...`
5. PR. Green CI → merge. Tag + release if it touches compiled code (all of
   the above does).

The `naive-core` mirror workflow has already been run for `v150.0.7871.63-1`
(see section 7) -- no need to run it again unless bumping the pinned version.
