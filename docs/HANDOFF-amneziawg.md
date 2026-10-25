# Handoff — AmneziaWG (AWG) egress support

Kickoff brief for a fresh session with no access to a previous session's
`.claude/memory/` files. Written 2026-09-17, repo at `v0.32.30` / `main`.

For what this project is and the general working conventions ("делай и
сразу сливай" flow, CI checks, versioning, commit/PR trailers, language,
the `parse_test.go` CRLF gotcha), see
[`docs/HANDOFF-naive.md`](HANDOFF-naive.md) §1-2 — identical here, not
repeated.

**Status (updated 2026-09-17, later the same day): the xray-core patch for
`v26.9.9` is CONFIRMED WORKING END TO END on real router hardware, this
project's own config/URI/bot integration is built and shipped, a `.conf`
file can be uploaded as a Telegram document (not just pasted as a
`vpn://` link), and the real production `xray-core/v26.9.9` release now
carries the patched binary** (promoted for real — any router pulling
`PrereleaseTag` gets AmneziaWG support automatically now, no manual
dev-binary swap needed). **A `v26.3.27` patch also exists, builds clean,
and has a dev/test build published** (`xray-core-awg-dev/v26.3.27`) —
not yet hardware-tested, not yet promoted. Real AmneziaWG handshake, real HTTP/2
traffic through the tunnel to a real remote server (`curl` through the
patched core's SOCKS inbound, `HTTP/2 301` back from Cloudflare, `curl
exit=0`), plus independent confirmation from the AWG server's own admin
panel showing the test client online — that was the first end of this
arc. Everything after that (own plumbing, file upload, production
promotion, the second core tag) happened in a follow-up session; see
"What's actually built" below for the precise, current cut line. **Only
remaining gap**: nobody has yet configured an AWG profile *through the
bot* (paste or upload) and confirmed it connects on real hardware — every
hardware test so far, including the one that found the `bind.go` root
cause, used a hand-written JSON config against the patched binary
directly, deliberately bypassing this project's own layer (see "What's
actually built" for why that separation was deliberate and worth
keeping). See "2026-09-17 real-hardware debugging arc" near the end of
this document for the full account of finding that root cause — three
real bugs found that way, none of them anticipated by the original plan
below, most of them relegated to their own long detour before the actual
(surprisingly simple) fix turned up.

**Update 2026-10-03: `v26.9.30` is promoted alongside `v26.9.9`.** The
re-derived patch (see the 2026-10-03 section below) was confirmed working
on real hardware -- an aarch64 router, the arm64 *dev* build, an AWG
profile -- so the tag is in `AWG_CONFIRMED_TAGS` (workflow and `xraycore`)
and `xraycore.PrereleaseTag` is `v26.9.30`. The production arm64 build is
`CGO_ENABLED=0` while the dev one is the CGO diagnostic flavor, so one
on-router check of the production flavor (`ensure-xray-core --tag=v26.9.30`
with no base-URL override) gates cutting a keenetic-xray release that
carries the new `PrereleaseTag`.

## The task

User's provider tooling (`kuzzrus/3x-ui-awg`, a fork of 3x-ui) issues
`vpn://` links for AmneziaWG-obfuscated WireGuard servers. Wants VPN
*profiles* (not the existing LAN-side `transport wg`, which is local-only
— client to the router's own local xray `wireguard` inbound — and never
crosses the ISP, so obfuscating it is pointless) that can use them, up to
AWG protocol/library version **3.1**.

## Investigated three approaches — chose the third

1. **A per-model kernel module**
   (`amneziawg-linux-kernel-module`) — one `.ko` per specific Keenetic
   hardware model (28 models → 10 build groups). **Rejected**: an
   ongoing per-model compatibility matrix this project has never taken
   on, and a structural mismatch with every binary vendored today (all
   pure userspace, architecture-only).
2. **Vendor `amnezia-vpn/amnezia-xray-core` as a sidecar** (the
   naive-sidecar shape) — the first plan this landed on. It's a real,
   actively-maintained MPL-2.0 fork of `XTLS/Xray-core` that swaps in
   `amnezia-vpn/amneziawg-go` as its WireGuard library. **Rejected after
   reading its actual source**: `proxy/wireguard/client.go`'s UAPI
   config-string builder (`private_key=`/`public_key=`/`endpoint=`/
   `allowed_ip=`/`persistent_keepalive_interval=`) only carries vanilla
   WireGuard fields — it never writes `jc=`/`jmin=`/`h1=`/etc. at all.
   `proxy/wireguard/config.proto`'s `DeviceConfig`/`PeerConfig` have no
   AWG-specific fields either. The fork swapped the library but never
   wired the obfuscation parameters through its own config — using it
   as-is would just be a WireGuard client with dead weight, not real
   AmneziaWG. The library itself (`amneziawg-go`'s `device/uapi.go`)
   *does* fully parse every 3.1 key — the gap is entirely in the fork's
   own xray-side glue code, not the library.
3. **Chosen: patch our own already-vendored xray-core directly.**
   Diffed `XTLS/Xray-core:v26.7.28` (the tag amnezia-xray-core last
   merged from) against `amnezia-vpn/amnezia-xray-core:master`: only 9
   commits, 19 files, and the AWG-relevant slice is tiny —
   `go.mod`/`go.sum` (dependency swap) plus 6 files in
   `proxy/wireguard/` at 1-2 lines each (pure import-path changes,
   `golang.zx2c4.com/wireguard/...` → `github.com/amnezia-vpn/
   amneziawg-go/...`). The rest of that diff (`proxy/vless/inbound/*`,
   an "unknown_user" feature) is unrelated to AWG. Since the library
   already understands every field needed, closing the gap ourselves is
   the same tiny import swap + a handful of new optional
   `config.proto` fields + ~20-30 lines extending `client.go`'s
   UAPI-string builder to actually emit them.

**Why option 3 wins**: smaller and more contained than it first looked,
and — unlike option 2 — it actually produces working AmneziaWG. It also
eliminates the sidecar entirely: once the one vendored xray-core binary
has a working AmneziaWG-capable `wireguard` outbound, `buildOutbound`
(`internal/config/xray.go`) is directly the right place for a new
branch — no second process, no second vendored binary, no
port/lifecycle plumbing to build or maintain.

## Confirmed AWG 3.1 field set

Read directly from the user's own `kuzzrus/3x-ui-awg`'s
`frontend/src/pages/clients/amneziawgConfig.ts` — the authoritative
list — **and cross-checked against two real `vpn://` links from the
user's own panel** (one 2.0-only, one with the full 3.0/3.1 set):

- `[Interface]`: `PrivateKey`, `Address`, `DNS` (optional), `MTU`
- AWG 1.0: `Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`-`H4` (H1-H4 default to
  1/2/3/4 when blank)
- AWG 2.0: `S3`, `S4`, `I1`-`I5` (all optional)
- AWG 3.0: `HeaderProtectionKey`, `ContentPaddingAddition`,
  `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`,
  `KeepaliveTimeout`, `MaxHandshakeAttempts` (all optional)
- AWG 3.1: `RandomTrailers`, `DisableCookies` — serialized as the
  literal string `on`, not `true` (`awg`'s own `parse_bool` rejects
  `true`)
- `[Peer]`: `PublicKey`, `PresharedKey` (optional), `AllowedIPs`,
  `Endpoint`, `PersistentKeepalive` (optional)

`amneziawg-go`'s UAPI key names for these are lowercase/underscored
(`jc`, `header_protection_key`, `random_trailers`, ...) — confirmed by
reading `device/uapi.go`'s own `case` list directly.

**The `vpn://` link format**: `vpn://` + plain standard base64 (NOT
base64url) of the `.conf` text above, decoding cleanly to
`[Interface]`/`[Peer]` sections. `#`-prefixed comment lines can appear
(one real sample had one before `[Peer]`).

### Critical finding only visible from real samples, not docs

Almost every "numeric" AWG field is actually a `min-max` **range
string**, not a bare integer — confirmed for `H1`-`H4`
(`463296050-486280248`) *and*, from the second real sample, every 3.0
timing/padding field too: `ContentPaddingAddition` (`5-60`),
`RekeyAfterTime` (`113-145`), `RekeyTimeout` (`4-5`), `RejectAfterTime`
(`166-192`), `KeepaliveTimeout` (`5-16`), `MaxHandshakeAttempts`
(`14-21`).

`I1`-`I5` are a small domain-specific notation, not a value at all:
`<b 0xHEX><r N>` sequences, e.g. `<b 0xc0000000...1080><r 28><b
0x...><r 32><r 16>` (`b` = a literal byte blob, `r` = N random bytes,
concatenated into the actual decoy-packet payload).

### Design decision this leads to

Don't type any of these as `int32` or build a range/DSL parser at all.
Every AWG obfuscation field (`Jc` through `DisableCookies`, `I1`-`I5`
included) is stored on `AmneziaWGParams` as a plain **string**,
captured verbatim from the `.conf` line, and relayed unmodified all the
way to the patched core's UAPI write (`jc=<string>\n`, same for every
other key). `amneziawg-go`'s own UAPI parser already understands
single values, ranges, and the `<b .../<r ...>` notation for whichever
fields take it — this project has no reason to parse, validate, or
reinterpret any of it, only to carry it through faithfully. This
simplifies both the `config.proto` addition (every new field is
`string`) and the UAPI-string-builder extension (one uniform "if
non-empty, write key=value" per field, no per-type formatting logic).

## Implementation plan

### Step 1 — The xray-core patch itself

Base it on a real xray-core checkout (whichever of `DefaultTag`/
`PrereleaseTag` is more convenient), done as a normal git workflow, not
by hand-copying diffs:

1. Add `amnezia-vpn/amnezia-xray-core` as a remote, cherry-pick its
   9-commit AWG-relevant range (the `go.mod`/`go.sum` + 6-file import
   swap only — skip the unrelated `proxy/vless/inbound`
   "unknown_user" commits) onto our pinned tag. Expect real merge
   conflicts: amnezia's last sync point (`v26.7.28`) sits between this
   project's `DefaultTag`/`PrereleaseTag`, so `proxy/wireguard/` may
   have moved on either side since — bounded, ordinary conflict
   resolution given how small the diff is.
2. Extend `proxy/wireguard/config.proto`'s `DeviceConfig`/`PeerConfig`
   messages with the new optional fields (names matching the UAPI keys
   above, all `string`), regenerate `config.pb.go` (needs `protoc` +
   the Go plugin locally). Also check `infra/conf/` for a plain-JSON-
   facing config struct that builds the protobuf `DeviceConfig` for the
   existing `wireguard` inbound/outbound — **not confirmed whether one
   exists separately from `config.proto` itself**; if it does, the new
   fields need adding there too for JSON config to actually reach the
   protobuf struct.
3. Extend `client.go`'s `init()` — the `cfg.WriteString(...)` block
   building the `IpcSet` UAPI string — with the new optional lines
   (`if h.conf.Jc != "" { cfg.WriteString(fmt.Sprintf("jc=%s\n",
   h.conf.Jc)) }` and so on). Mechanical, ~20-30 lines.
4. Smoke-test locally: does a plain (non-AWG) vless-carrying build off
   this patched source still behave identically? Regression risk on
   the always-shipped binary matters more here than it would for an
   opt-in sidecar.

Keep the result as a maintained patch/branch in this repo (e.g.
`packaging/xray-core/amneziawg.patch`, or a small long-lived branch
this project rebases per xray-core version bump) — not a permanent
fork repository, mirroring how the naive/susanin vendoring already
established "maintain a thin layer on someone else's upstream,
tracked explicitly."

### Step 2 — Wire into the existing build, not a new one

Modify `.github/workflows/xray-core.yml` (no new workflow file): add
an "apply the AmneziaWG patch" step between the upstream checkout and
`go build`. Bakes into the same single binary every router already
gets — the new proto fields are inert for any profile that isn't
`Protocol == "amneziawg"`. Everything else (UPX packaging, QEMU smoke
test, checksum/provenance, upload) stays as-is.

### Step 3 — Config fields + parser

- `internal/config/profile.go`: `Profile.Protocol` gains
  `"amneziawg"` alongside `""`/`"vless"`/`"naive"`. Add a nested
  struct — `Profile.AWG *AmneziaWGParams` — mirroring
  `WGTransportConfig`'s own precedent (AWG has 20+ fields vs. naive's
  2). `Validate()` gains a `validateAmneziaWG()` case; `Redacted()`
  masks `PrivateKey`/`PresharedKey` the way `WGTransport`'s
  `XraySecretKey`/`PSK` already are.
- New `internal/config/amneziawguri.go`, `ParseAmneziaWGURI(raw
  string) (Profile, error)` — base64-decode (plain std encoding,
  confirmed against real links) then parse the wg-quick-style INI
  `[Interface]`/`[Peer]` text into `AmneziaWGParams`/`Profile`,
  mirroring `ParseNaiveURI`'s shape. Skip `#`-prefixed comment lines.
  Per the "everything is a string" decision, this parser does plain
  `key = value` line splitting into string fields only — no range
  parsing, no `<b .../<r ...>` tokenizing, no int conversion. Split
  lines, split each on the first `=`, trim, assign to the matching
  struct field by key name, done.
- `internal/config/parseuri.go`, `ParseProfileURI`: new `case
  strings.HasPrefix(trimmed, "vpn://"):` branch — the one dispatch
  point every caller already goes through.
- **Also fix the one place that bypasses `ParseProfileURI`**:
  `internal/botcontrol/telegram_wizard.go`'s own hand-rolled
  `strings.HasPrefix(src, "vless://") || strings.HasPrefix(src,
  "naive+")` check in the bot's 🔗 Источники wizard — this exact gap
  already bit the naive rollout once (see `docs/HANDOFF-naive.md`);
  add `vpn://` there too, or better, make that wizard call
  `ParseProfileURI` directly instead of hand-checking prefixes a
  second time.

### Step 4 — `buildOutbound`'s new branch (the actual payoff)

`internal/config/xray.go`, `buildOutbound`: new branch alongside the
existing naive one, emitting a **direct** `protocol: "wireguard"`
outbound — no socks passthrough, no sidecar:

```go
if p.Protocol == "amneziawg" {
    peer := map[string]any{
        "publicKey": p.AWG.PeerPublicKey, "allowedIPs": p.AWG.AllowedIPs,
        "endpoint": p.AWG.Endpoint,
    }
    if p.AWG.PresharedKey != "" { peer["preSharedKey"] = p.AWG.PresharedKey }
    settings := map[string]any{
        "secretKey": p.AWG.PrivateKey, "peers": []map[string]any{peer},
        "jc": p.AWG.Jc, "jmin": p.AWG.Jmin, "jmax": p.AWG.Jmax,
        // ...s1-s4, h1-h4, i1-i5, the 3.0/3.1 fields, same map-literal shape
    }
    return xrayOutbound{Tag: "proxy", Protocol: "wireguard", Settings: settings}, nil
}
```

Exact key spelling (`jc` vs `Jc` vs `jC`) needs to match whatever JSON
tags Step 1's `infra/conf/` translation (if any) or protobuf `jsonpb`
mapping actually expects — confirm against the patched core's own
behavior, not assumed here.

### Step 5 — CLI / bot polish (deferred, same as naive shipped with)

- `internal/health/sweep.go` — skip amneziawg profiles in the quality
  sweep for now; a scratch probe can come later.
- Status/doctor lines (`cmd/keenetic-xray/status.go`,
  `internal/botcontrol/commands.go`'s `RouterHandler.status`) — can
  defer, naive shipped without these initially too.

## What this plan does NOT need (dropped from the earlier sidecar version)

No `internal/amneziacore` vendoring package, no new
`.github/workflows/amnezia-core.yml`, no `ensureAmneziaSidecar` in
`internal/failover`, no extra `Supervisor`/port-offset/
JSON-satellite-config plumbing, no separate opt-in
"ensure-amnezia-core" fetch path. All of that existed only to run a
*second* binary — once the AWG outbound lives in the one binary this
project already vendors and always ships, none of it is needed.

## Open risks, stated plainly

- Whether `infra/conf/` needs its own matching field additions
  (separate from `config.proto`) for the JSON config to actually
  reach the new protobuf fields — not confirmed, first thing to check
  once actually patching.
- The cherry-pick's merge-conflict surface against this project's
  specific pinned tag(s) — small diff, but unverified until attempted
  for real.
- Patch maintenance going forward: every future xray-core tag bump
  needs this patch re-applied/re-verified — the same ongoing cost
  `amnezia-xray-core`'s own maintainers already carry for their whole
  fork, just scoped to a much smaller diff here.
- Whether the patched core's own UAPI plumbing accepts `I1`-`I5`'s
  `<b 0xHEX><r N>` string verbatim (this project would just relay it
  unmodified) or expects something re-encoded — assumed verbatim
  passthrough works since the notation almost certainly originates
  from `amneziawg-tools`' own config-parsing convention in the first
  place, but not independently confirmed.
- Whether the "everything is a string, relayed verbatim" design holds
  all the way through Step 1's protobuf fields too, or whether
  `jsonpb`/xray-core's own JSON-unmarshaling conventions push back on
  a bare numeric-looking JSON value needing to be typed `string` in
  the wire format — worth confirming against the patched core's
  actual behavior, not assumed.
- The 3.0/3.1-only fields were originally trusted from docs only —
  **resolved**: a second real sample link (from a 3.1-configured
  server on the user's own panel) confirmed every 3.0/3.1 field,
  including that they're ranges too, not just H1-H4.

## Verification, once building starts

- `go build ./... && go vet ./... && gofmt -l . && go test ./...`
  after each step, cross-compiled for `linux/arm64` and
  `linux/mipsle` (`GOMIPS=softfloat`).
- Step 1: before touching CI, build the patched core locally/in a
  scratch checkout and confirm a plain vless profile still
  round-trips correctly — regression safety on the always-shipped
  binary matters more here than for an opt-in sidecar.
- Step 2: dispatch the modified workflow once, confirm the QEMU smoke
  test and UPX-packed binary both still pass on both arches.
- Step 3: unit tests for `ParseAmneziaWGURI` against the user's own
  real `vpn://` link (redacted/regenerated if it carries live key
  material) plus a hand-built one covering every 3.0/3.1 field.
- Step 4: real-hardware confirmation (does a profile actually
  establish an AmneziaWG session to a real server) is the
  acknowledged gap until the user tests it live — same as every other
  protocol this project has added.

## What's actually built (as of 2026-09-17) vs. still just planned

**Built, committed, and confirmed working on real hardware** —
`packaging/xray-core/amneziawg-v26.9.9.patch` (668→731 lines across the
session as bugs got found and fixed), applying cleanly to a fresh
`v26.9.9` checkout:
- The library swap + all 25 new `DeviceConfig` fields + `client.go`'s
  UAPI-string additions + `infra/conf/wireguard.go`'s JSON bridge, all
  exactly per the original plan below.
- A fork, `kuzzrus/amneziawg-go` (commit `58a3db1` on top of the
  `v3.1.20260828` tag this project pins), with upstream's own open
  `amnezia-vpn/amneziawg-go#169` applied — a real fix for a real race
  (stale S1-S4 transport padding on the first post-configuration
  packet), wired in via an ordinary `go.mod` `replace` directive. Kept
  even though it turned out not to be *this* debugging arc's root cause
  — it's still a legitimate, worthwhile fix on its own merits.
- `.github/workflows/xray-core.yml`'s `awg_dev` dispatch input,
  publishing to `xray-core-awg-dev/<tag>` (never the real
  `xray-core/<tag>`) — including, as a diagnostic that turned out to be
  a dead end but stayed since it's harmless and free, an `awg_dev`+
  `arm64`-only `CGO_ENABLED=1` path (statically linked via
  `-linkmode external -extldflags -static`, `gcc-aarch64-linux-gnu`).
- The critical fix, in `proxy/wireguard/bind.go` (see the debugging arc
  below) — this is the one that actually made it work.

**Built and shipped in the follow-up session** — what the plan below
originally called Step 3/4/5, deliberately deferred until the raw patch
proved out (it did): `internal/config/profile.go`'s `Profile.AWG`/
`"amneziawg"` protocol, `internal/config/amneziawguri.go`'s
`ParseAmneziaWGURI` (handles both base64 alphabets real links came back
in), `ParseProfileURI`'s `vpn://` case, `internal/subscription/
resolve.go`'s `ResolveSourcePinned` (a *second* hardcoded prefix gate,
independent of the wizard's own, that also needed the same fix —
found by tracing what `/set_primary_source` actually calls, not
assumed), `internal/botcontrol/telegram_wizard.go`'s prefix-check gap,
`internal/config/xray.go`'s `buildAmneziaWGOutbound` branch. Shipped as
PR #216, released `v0.32.31`. On top of that, `internal/botcontrol/
telegram.go`/`telegram_wizard.go` gained a `.conf`-as-Telegram-document
path: `TelegramBot.downloadFile` (getFile + a GET against Telegram's
*separate* file-serving base path) feeds an uploaded file's raw bytes
into the exact same `wizardSetSlotSource` a pasted `vpn://` link uses,
by re-deriving the equivalent `"vpn://"+base64(...)` string — no second
parser to keep in sync.

Every test through the *own-plumbing* layer so far is unit-level
(`internal/config/amneziawguri_test.go`, `internal/botcontrol/
telegram_wizard_test.go`'s `TestTelegramBot_SlotSourceWizard_
PrimaryFromConfFile`) — nobody has yet configured a profile through the
bot (link or file) and confirmed it connects on real hardware. Every
hardware test so far, including the one that found `bind.go`'s root
cause, used a hand-written JSON config against the patched binary
directly, deliberately bypassing this project's own layer entirely (see
the original plan's own "Verification, staged to isolate variables"
reasoning for why — it paid off exactly as intended: every bug found in
the first round was in the *patch*, none of them would have been any
easier to find with this project's own plumbing in the loop too, and
several rounds would have needed disentangling "is this xray-core or is
this our own code" on top of everything else). That gap is now the only
thing standing between "the patch works" and "a profile can be set up
the normal way and it works" being fully closed.

**Also done, and actually dispatched**: `.github/workflows/xray-core.yml`
gained an `AWG_CONFIRMED_TAGS` workflow-level env var (currently just
`v26.9.9`) — a tag listed there always gets its patch applied and always
publishes to the real `xray-core/<tag>`, regardless of `awg_dev`. **The
real `xray-core/v26.9.9` release has been promoted for real** (dispatched
`xray_version=v26.9.9, awg_dev=false` after this landed on `main`) — its
title/notes now say "AmneziaWG support" and all 8 assets (`arm64`/
`mipsle` × binary/`.xz`/`.sha256`/`.provenance.txt`) were rebuilt with
the patch applied. Any router that updates its core via the bot's
⚙️ Ядро → "Пререлиз" button (which pulls `PrereleaseTag = v26.9.9`) now
gets the patched binary automatically — no manual dev-binary swap
needed for this tag anymore. `awg_dev` keeps its original meaning for
any tag NOT in `AWG_CONFIRMED_TAGS` — right now, that's `v26.3.27`.

**`v26.3.27`'s own patch now exists** —
`packaging/xray-core/amneziawg-v26.3.27.patch` — derived independently
(not copy-pasted) since `proxy/wireguard/client.go` and `config.proto`
are structurally quite different at this tag (confirmed, not assumed):
`DeviceConfig` ends at field 9 here (no field 10 yet — v26.9.9 already
had `dns` at 10), so the 25 new fields land at **10-34**, not 11-35;
`client.go` has no `Handler.init()` at all — the client-side UAPI
string is built by `createIPCRequest()` via `fmt.Sprintf`+
`request.WriteString`, not `cfg.WriteString("literal"+var)`, so every
insertion line has a different (but equivalent) shape; only 4 files need
the import-path swap here, not 7-8, and `proxy/tun/tun_freebsd.go`
doesn't exist yet at this tag so is correctly omitted, while a
`gvisortun` subpackage and a monolithic `tun.go` do exist here and don't
at v26.9.9. **The `bind.go` bug is confirmed present at this tag too**,
in `netBindClient.connectTo()` rather than `Open()`'s batched closure —
same unconditional zeroing, same fix (`len(bind.reserved) == 3`, which
already exists as `Send`'s own guard in the very same file, same as at
v26.9.9). Verified so far: `git apply --check` clean against two
independent fresh `v26.3.27` clones, and the patched clone cross-compiles
for both `linux/arm64` and `linux/mipsle` (`CGO_ENABLED=0`) plus builds
natively and passes `go vet`. A dev/test build **has been dispatched and
published** (`xray_version=v26.3.27, awg_dev=true` →
`xray-core-awg-dev/v26.3.27`, all 8 assets present) — one gofmt-check bug
was found and fixed along the way (the "Apply AmneziaWG patch" step's
post-apply `gofmt -l` had `v26.9.9`'s touched-file list hardcoded; fixed
to read the list from the patch's own `diff --git` lines instead, see
git log). **Not yet done for this tag**: real-hardware verification (the
dev build has never actually been tried against a live AWG server, only
compiled/cross-compiled) — until that happens, do not add `v26.3.27` to
`AWG_CONFIRMED_TAGS`.

## 2026-09-17 real-hardware debugging arc — the actual bug hunt

Once the patch was written and locally verified (patch applies clean,
cross-compiles for both arches, a hand-written JSON config passes `xray
run -test`), it went through **six** real-hardware rounds before genuinely
working — a useful record of what did and didn't matter, since most of
the plausible-sounding theories along the way turned out to be dead ends,
and the real fix was almost anticlimactically small.

**Round 1 — config validates, handshake times out completely.** First
real test against a `vpn://`-decoded config (secretKey/peers/jc/jmin/...
straight into a hand-written JSON, `xray run -config`) produced total
silence: `Sending handshake initiation` on repeat, zero response, ever.
Root cause, found by reading `amneziawg-go`'s actual `device/uapi.go` at
the pinned tag: **two fields needed conversion, not verbatim passthrough,
contradicting the plan's own "everything is a string, relay as-is"
design**:
- `header_protection_key` — UAPI does `key.FromHex(value)`, the same
  treatment as `private_key`/`public_key`/`preshared_key` (it's a real
  32-byte key, not a tunable parameter). The `.conf` carries it as
  base64 like every other WG key. Fixed by routing it through the
  existing `ParseWireGuardKey` (base64-or-hex → hex) instead of a raw
  copy.
- `random_trailers`/`disable_cookies` — UAPI does
  `strconv.ParseBool(value)`, Go's boolean spellings only. The `.conf`
  (and this document, originally) use `on`/`off`. Fixed with a small
  `onOffToBool()` converting the `.conf` spelling to what `ParseBool`
  actually accepts.

This alone wasn't the endpoint's fault either, as it turned out: the
*first* real `vpn://` link tested resolved its `Endpoint` to
**this router's own WAN IP** (confirmed later via `ip route get`) — an
unrelated red herring that made Round 1's total silence look consistent
with a config bug for longer than it should have. A second, independently
confirmed-working (tested on the operator's phone with the official
client) `vpn://` link, resolving to a genuinely different remote server,
is what the rest of this arc actually debugged against.

**Round 2 — config now clean, but `Received message with unknown type`
on every attempt.** With both field fixes in place, UAPI accepted every
line with zero errors — real progress, but the handshake still didn't
complete, now failing at classification instead of parsing. Two
plausible-looking upstream bugs were tried and **both were dead ends**:
- `amnezia-vpn/amneziawg-go#169` (open, unmerged) — fixes a real race
  where `RoutineReadFromTUN` snapshots S1-S4 transport padding before
  its first blocking TUN read, so a UAPI update landing mid-read leaves
  packets at a stale offset. Forked, applied, verified via the fork's
  own test suite. **Did not change the symptom** — this bug affects
  *transport* (data) packets specifically; the failure here was at
  *handshake* time, a different code path entirely.
- `amnezia-vpn/amneziawg-go#110` ("arm64: outbound H4 header corrupted
  in transport packets", `CGO_ENABLED=0`, "embedded Linux (Keenetic OS,
  Entware)" — this project's exact platform, described independently)
  looked like an extremely close match. Built a whole `CGO_ENABLED=1`
  diagnostic path (cross-`gcc`, static linking so the binary stays
  portable) to test it. **Also did not change the symptom.**

**Round 3 — the decisive diagnostic: `tcpdump` on the router itself**
(`opkg install tcpdump`, none of the config-tweaking rounds before this
had actual wire-level evidence). Captured on the real egress interface
during a full handshake-retry cycle: **zero packets ever arrived back
from the server** — every packet on the wire was outbound only (the I1-I5
decoy burst plus the real handshake-init, all visible in cleartext in the
capture, e.g. literal `mail.ru`/`vk.com`/`OPTIONS sip:ozon.ru` ASCII
matching the config's own decoy payloads exactly). Yet the client kept
logging "received" something. That contradiction — a receive-side claim
with no corresponding wire-level receive — is what actually narrowed the
search: whatever was misclassifying packets had to be **local to this
project's own code**, not the network, and not amneziawg-go's own
(otherwise-correct) classification logic, which never even runs on data
that was never received.

**Root cause, `proxy/wireguard/bind.go`** (this project's own bridge
between amneziawg-go's `conn.Bind` interface and xray-core's
dialer/transport — confirmed untouched by amnezia-xray-core's own
upstream patch, which only ever changes import paths in this file):

```go
if n > 3 {
    bufs[0][1] = 0
    bufs[0][2] = 0
    bufs[0][3] = 0
}
```

Unconditional, on every received packet. Harmless for vanilla WireGuard
(message type is one byte; this only matters at all for peers using the
separate "reserved bytes" connection-switching convention, which `Send`'s
own mirror of this correctly guards with `if len(b.reserved) == 3`, a
condition the receive side never had). Fatal for AmneziaWG: bytes 0-3
*together* are the 32-bit H1-H4 magic-header marker used to identify
message type at all — zeroing 3 of those 4 bytes on every single receive
guarantees misclassification, regardless of how correct every other AWG
parameter is. Fixed by giving the receive side the same
`len(b.reserved) == 3` guard `Send` already had. One-line diagnosis once
found, but took two full dead-end rounds and a packet capture to actually
locate, because every symptom up to that point (config accepted, decoys
sent correctly, "received" something, "unknown type") was consistent with
several *other*, more exotic-sounding theories first.

**Round 4 — confirmed working, end to end**, immediately after the
`bind.go` fix: `Received handshake response` (not "unknown type"),
`Receiving keepalive packet`, and a `curl` through the patched core's own
SOCKS inbound completing a real TLS handshake + HTTP/2 request against
`1.1.1.1`, getting a genuine `301` back from Cloudflare (`curl exit=0`).
Independently corroborated server-side: the test client showed "online"
in the AWG server's own admin panel both times the tunnel came up.

**Lesson for next time** (`v26.3.27`'s own patch, or any future
xray-core/amneziawg-go bump): when a *received* message is misbehaving
and every config-level theory has been exhausted, get a packet capture
before spending more rounds on library-internals theories — "does
anything real actually arrive on the wire" is a question no amount of
log-reading answers as fast or as conclusively, and it would have
short-circuited two dead-end rounds (#169, CGO) straight to the actual
bug in this project's *own* 15-line bridge file.

## 2026-10-03 — `v26.9.30`: patch re-derived, loopback-verified, awaiting hardware

Upstream `v26.9.30` (2026-09-30, 36 commits / 263 files after `v26.9.9`) is
the next candidate. `amneziawg-v26.9.9.patch` does **not** apply to it --
`git apply --check` fails on go.mod, go.sum, `infra/conf/wireguard.go` and
`proxy/wireguard/{client,config.pb,netstack,tun_linux}.go` with real
context drift (a CR-stripped copy fails identically) -- so
`packaging/xray-core/amneziawg-v26.9.30.patch` was re-derived rather than
rebased, the same way `v26.3.27`'s was. What moved under the old patch:

- **#6771** dropped `domainStrategy` and the `remoteDNS: "local"` mode from
  the WireGuard outbound (a reshuffle of the conf struct our AWG block sits
  after; this project never emitted either key, and `remoteDNS` as an IP
  list is still valid).
- **#6852** reordered `Handler.init()`: the bind is now fully built *before*
  `device.NewDevice`, then `bind.setDownFunc(dev.Down)`. The AWG UAPI block
  still goes right after `private_key=`, and the AWG-05 `dev.Close()` on
  `IpcSet`/`Up` failure is **still needed** -- upstream still returns
  without closing the device there. `bind.go`'s receive-side
  `len(b.reserved) == 3` guard (the Round-3 root cause above) is untouched
  upstream and applies as-is.
- **#6754** moved UDP dialing onto Finalmask (`FinalMask.DialUDP`).
- **New `proxy/masque`** gets its `tun.Device` from `wireguard.CreateNetTUN`,
  i.e. the two packages exchange `tun.Device` values. With `proxy/wireguard`
  on the fork's `tun`, masque's three files (`client.go`, `server.go`,
  `server_test.go`) must swap to it too, or it is a type mismatch at
  compile time. The patch is therefore **15 files, not 12**. For any future
  tag, after applying, `grep -rn 'golang.zx2c4.com/wireguard/\(tun\|device\|conn\)' --include='*.go' .`
  must come back empty.
- go.mod/go.sum were regenerated with a real `go mod edit` + `go mod tidy`
  against the same fork commit as `v26.9.9`'s patch (`9f61425`, the AWG-04
  fix), not hand-edited.

Verified, all without hardware: (1) the CI recipe on a fresh checkout --
`git apply`, the workflow's own protoc regeneration with
`protoc-gen-go@latest`, `gofmt -l` on every touched file, `go build ./...`;
(2) `linux/arm64` and `linux/mipsle` softfloat builds of `./main` (32.1 /
36.8 MB unpacked, vs 31.6 / 36.1 for `v26.9.9`); (3) upstream's own scenario
tests on the patched tree -- `TestWireguard` and `TestMasque*`, the latter
being what proves the shared-`tun` swap; (4) the loopback harness below.
(On this Windows dev box clone with `-c core.autocrlf=false` *persisted*
into the clone -- `git -c ... clone` only applies it to the clone command
itself, and `git apply` then writes CRLF files that make `gofmt -l` flag
everything.)

**Loopback AmneziaWG harness** -- `packaging/xray-core/awgloop/main.go`
(build-ignored; the run recipe is in its header comment). It runs an AWG
*server* peer in userspace (the fork + gVisor netstack, an HTTP server
inside the tunnel), points the patched xray at it with a config shaped like
`buildAmneziaWGOutbound`'s output, and fetches a page through xray's SOCKS
inbound. Five scenarios: plain WG, AWG classic, AWG 2.0 style (s3/s4, h
ranges, i1), and two negative controls (server AWG + client plain;
mismatched h4) that must fail. It has teeth: with the old `bind.go` bug put
back it goes red with `Received message with unknown type` -- the exact
Round-2/3 symptom -- so a green run means the receive path and the
parameter wiring both work. **Run it on every future tag bump before
dispatching the dev build.** It cannot reproduce a real AWG server's
quirks, so it does not replace the hardware step.

Then the usual order: dispatch `xray_version=v26.9.30 awg_dev=true`
(publishes `xray-core-awg-dev/v26.9.30`, which no release path installs),
test that on a router, and only then promote. That was done on 2026-10-03:
the dev build was hardware-confirmed (aarch64 router, AWG profile), so the
tag went into `AWG_CONFIRMED_TAGS` (workflow *and*
`xraycore.AWGConfirmedTags`), `xraycore.PrereleaseTag` moved to it, and the
real `xray-core/v26.9.30` is built by dispatching `xray_version=v26.9.30`
without `awg_dev` -- `CGO_ENABLED=0` on both arches, unlike the arm64 dev
build.

## 2026-10-11 — `v26.10.10`: patch re-derived with `--3way`, verified, dev build staged

Upstream `v26.10.10` (2026-10-10, 23 commits / 97 files after `v26.9.30`;
the release page carries no changelog, so this is read from the commits).
VLESS / REALITY / XHTTP / TCP / freedom are untouched. What moved under or
beside the patch:

- **go.mod / go.sum**: new `gopher-lua` + `gopher-luar` (a Lua `script` for
  `dns` and `routing`, #6823) and `x509roots/fallback` (the TLS client now
  verifies against a built-in root bundle by default; `tlsSettings.useSystemCA`
  brings the OS pool back, #7105).
- **`proxy/wireguard`**: a new `icmp.go` (fake pong, #6855), `tun.go` (idle
  UDP flows hold less memory, #6856) and `tun_linux.go` (kernelTun IPv6 table
  index, #6881 -- the `sync` import became `sync/atomic`).
- The MASQUE client speaks Cloudflare WARP (#6878).

`amneziawg-v26.9.30.patch` does not apply with a plain `git apply` (go.sum
and the `tun_linux.go` context), but `git apply --3way` does nearly all of
it, **provided the old tag's blobs are in the clone**:

```
git clone -c core.autocrlf=false --depth 1 --branch v26.10.10 https://github.com/XTLS/Xray-core
cd Xray-core
git fetch --depth 1 origin tag v26.9.30        # the old patch's base blobs
git apply --3way <this repo>/packaging/xray-core/amneziawg-v26.9.30.patch
```

`tun_linux.go` merges by itself; the only conflict is `go.sum`, where both
sides added lines at the same spot (upstream's gopher-lua entries, the
patch's `go.uber.org/atomic`) -- keep both, `git add go.sum`, then
`git diff --cached > amneziawg-v26.10.10.patch`. The result is the same 15
files as `v26.9.30`'s. (`-c core.autocrlf=false` on `git clone` persists
into the clone, which is what keeps `gofmt -l` quiet on Windows.)

Verified without hardware: plain `git apply` on a pristine checkout (what CI
runs); `gofmt -l` clean on every touched file; no leftover
`golang.zx2c4.com/wireguard/{tun,device,conn}` imports; `go build ./...`;
`linux/arm64` and `linux/mipsle` softfloat builds of `./main`; the loopback
harness above (5/5); upstream's own `TestWireguard` and `TestMasque*`
scenario tests and the `infra/conf` Masque / Wireguard tests on the patched
tree. The workflow's own protoc regeneration is the one CI step not run
locally.

**Size**, the CI recipe (CGO off, `-trimpath`, `-s -w -buildid=`, UPX 4.2.2
`-9`, `--lzma` on arm64 only). A local rebuild of `v26.9.30` reproduced the
published unpacked sizes byte for byte (UPX within 0.1 %), so the two columns
compare like with like:

| bytes | `v26.9.30` | `v26.10.10` |
|---|---|---|
| arm64 unpacked / UPX / xz | 32,112,764 / 7,624,708 / 7,930,128 | 33,226,876 / 7,968,676 / 8,282,516 |
| mipsle unpacked / UPX / xz | 36,765,851 / 11,097,852 / 7,371,464 | 38,011,035 / 11,545,012 / 7,693,616 |

What a router downloads grows by +0.34 MB (arm64) and +0.45 MB (mipsle),
the unpacked image by +1.1 / +1.2 MB. By symbol size (arm64) the Lua stack is
about 0.45 MB (gopher-lua ~0.33, gopher-luar ~0.08, Xray's glue ~0.04), the
root-CA bundle about 0.13 MB, MASQUE-WARP about 8 KB; the rest is Go
metadata. No build tag switches either of the first two off. The dev build's
arm64 is the CGO diagnostic flavor, so *its* provenance sizes do not compare
-- use this table.

Next, as before: dispatch `xray_version=v26.10.10 awg_dev=true` (publishes
`xray-core-awg-dev/v26.10.10`, which no release path installs), test it on a
router, and only then promote.

**Superseded on 2026-10-25: upstream withdrew `v26.10.10`** (see the next
section). The tag no longer exists, `amneziawg-v26.10.10.patch` is deleted, and
the dev build `xray-core-awg-dev/v26.10.10` must not be installed: its built-in
root-CA bundle carries the roots upstream pulled.

## 2026-10-25 — `v26.10.21`: patch re-derived again, dev build staged

Upstream `v26.10.21` (2026-10-21, marked **Latest**, 58 commits / 225 files
after `v26.9.30`) is an emergency release. The private keys of eight Indian
intermediate certificates turned out to be guessable (XTLS/Xray-core#7212); the
built-in root bundle that `v26.10.10` introduced (#7105) carried three roots
that are now distrusted, so upstream **withdrew `v26.10.10` and `v26.10.17`**
and shipped `v26.10.21` without those roots, built with Go 1.27.3 (whose own
distrust list drops the certificates even where the OS bundle is stale). Its
notes say the full stable release follows at the end of the month. The commit
of the withdrawn `v26.10.10` (`701af607`) stays reachable from `v26.10.21`,
which is what keeps a `--3way` merge of the old patch possible.

What moved under the patch:

- **gVisor is gone (#7130, #7156, #7179).** The TUN inbound, the WireGuard
  proxy and the MASQUE proxy now run on Xray's own lightweight TCP/IP stack
  (`proxy/tun/{stack,tcp_lightweight,packet}.go`); no Go file imports gVisor
  any more (go.mod keeps it as an indirect requirement). On Linux the TUN
  device is opened with `IFF_VNET_HDR` + `TUNSETOFFLOAD`, so TCP segments of up
  to 64 KiB cross the device per syscall. `proxy/wireguard` was rewritten around
  it: `icmp.go`, `icmp_test.go`, `queue_bench_test.go` and `tun_test.go` are
  gone, `tun.go` fell from 381 lines to a 35-line interface-name helper,
  `netstack.go` now sits on `proxy/tun`'s stack, and two test files arrived --
  `netstack_test.go` imports the wireguard-go `tun` package and needs the same
  import swap as the rest, so the patch is **16 files, not 15**. The unpacked
  binary shrinks as a side effect (below).
- **#7151, "WireGuard outbound: keep the device when its setup fails".**
  `NewClient` now creates the device once; `up()` retries `IpcSet`/`Up` on the
  next connection and keeps the config string until both succeed. That is the
  very leak AWG-05's `dev.Close()` hunk worked around, so the hunk is
  **dropped**: `NewClient` has no failing return after `device.NewDevice`, and
  `Handler.Close` closes the device. The AWG UAPI block therefore moved into
  `NewClient` (as `conf.Jc`, ...), still right after `private_key=` and before
  the first `public_key=`.
- `bind.go` (the receive-side `len(b.reserved) == 3` guard), `config.proto`,
  `config.pb.go` and `infra/conf/wireguard.go` are byte-identical upstream since
  `v26.10.10` and carry over as they were. The TUN inbound's JSON schema
  (`infra/conf/tun.go`, `proxy/tun/config.proto`) did not change for Linux.

Derivation (`git clone -c core.autocrlf=false --filter=blob:none
--no-checkout`, then `git checkout 701af607` once so the old patch's base blobs
are local, then `git checkout v26.10.21` and `git apply --3way` of the old
patch): nine files merged by themselves; the six conflicts were go.mod, four
files whose import blocks lost the gVisor lines the patch used to sit next to
(`server.go`, `netstack.go`, `masque/server_test.go`, `tun/tun_freebsd.go`) and
`client.go`, whose AWG hunks lost their context because the `init()` they
patched no longer exists. Each was resolved by taking the pristine upstream file
and swapping the three wireguard-go import paths mechanically (`sed` +
`gofmt -w`); `client.go` also got its AWG block re-inserted into `NewClient`;
go.mod / go.sum were regenerated from a pristine copy with a real `go mod edit
-require/-replace` + `go mod tidy` against the same fork commit as before
(`9f61425`, the AWG-04 fix). The new `netstack_test.go` got the same swap.

Verified without hardware: plain `git apply` on a pristine `v26.10.21` checkout
(what CI runs) gives a tree identical to the working one (`git write-tree`);
`gofmt -l` clean on every touched file; no leftover
`golang.zx2c4.com/wireguard/{tun,device,conn}` imports; `go build ./...`;
`linux/arm64` and `linux/mipsle` softfloat builds of `./main`; unit tests of
`proxy/wireguard` and `proxy/masque` and the `infra/conf` Masque / Wireguard
tests; upstream's own `TestWireguard` + `TestMasque*` scenario tests (20 s); the
loopback harness (5/5 -- its client side is the new built-in stack, since
Windows has no kernel TUN). `go vet` reports only two findings that sit in
untouched upstream code (`proxy/masque/client.go` copies a lock into
`NewXmuxManager`, `infra/conf/xray.go` unreachable code). The workflow's own
protoc regeneration is the one CI step not run locally.

What none of that exercises: the **kernel-TUN path** (`createKernelTun` in
`tun_linux.go`, the one a router uses for the AWG outbound unless `noKernelTun`
is set -- unchanged since `v26.10.10`), a real AWG server's quirks, and whether
a Keenetic kernel accepts the new TUN inbound's `TUNSETOFFLOAD`. Those are what
the router test is for.

**Size**, unpacked, the CI recipe (CGO off, `-trimpath`, `-s -w -buildid=`)
built locally with Go 1.27.0:

| bytes | `v26.9.30` | `v26.10.10` | `v26.10.21` |
|---|---|---|---|
| arm64 unpacked | 32,112,764 | 33,226,876 | 29,753,468 |
| mipsle unpacked | 36,765,851 | 38,011,035 | 34,406,555 |

That is about 2.36 MB (7.3 % / 6.4 %) less than `v26.9.30` and 3.5-3.6 MB less
than `v26.10.10` -- the gVisor removal outweighs the Lua stack and the root
bundle that `v26.10.10` added. UPX / xz figures come from the CI provenance of
the dev build.

**A caution for rebuilding older tags.** `v26.10.17` carries #7176, "XTLS
Vision: Compatible with Go 1.27.3+": Vision reaches into `tls.Conn` / REALITY's
`Conn` through `unsafe` field offsets, and issue #7162 is a SIGSEGV on a
REALITY+Vision server once the buffers moved. The workflow resolves
`go-version-file` + `check-latest` to the newest Go 1.27.x, so **re-dispatching
`v26.9.9` or `v26.9.30` would now build them with a Go that upstream says needs
the fix those tags lack**. Their published `xray-core/` assets are unaffected
(built earlier); if a rebuild is ever needed, pin Go 1.27.1/1.27.2 for it and
test Vision.

Next, as before: dispatch `xray_version=v26.10.21 awg_dev=true` (publishes
`xray-core-awg-dev/v26.10.21`, which no release path installs), test it on a
router, and only then promote. The router test has three parts: an AWG profile
through the patched core (the kernel-TUN path), a plain `security=tls` profile
(the TLS client now trusts only the built-in roots unless `useSystemCA` is set),
and -- since the TUN inbound is new -- the TUN transport's throughput and
fallback (`docs/routing.md`, "Routing through an OpkgTun interface").

## How to resume

Everything the original plan called for is now built (see "What's
actually built"). What's left is verification and one more tag:

1. **Real-hardware test of a bot-configured profile** — the one gap
   called out repeatedly above. Paste a real `vpn://` link (or upload a
   `.conf`) via 🔗 Источники on a router running `xray-core/v26.9.9`
   (already the patched build, promoted — see "What's actually built"),
   confirm it actually connects, the same way the raw patch was
   confirmed working directly. Nothing code-side is expected to need
   changing for this — `buildAmneziaWGOutbound`'s JSON output is
   unit-tested against the exact key spellings the patch's
   `infra/conf/wireguard.go` expects — but it hasn't been run for real
   yet.
2. **`v26.3.27`**: the dev/test build already exists
   (`xray-core-awg-dev/v26.3.27`, dispatched and published — see "What's
   actually built"). What's left is the same real-hardware verification
   the `v26.9.9` arc went through (a packet capture early if anything
   looks like Round 1-3 of that arc again — see "Lesson for next time"
   above). Only once that's confirmed: add `v26.3.27` to
   `AWG_CONFIRMED_TAGS` in the workflow and dispatch again with
   `awg_dev=false` (or just omit it) to promote it for real.
3. **`v26.9.30`**: promoted (see the 2026-10-03 section above). What's
   left is one on-router check of the *production* arm64 flavor
   (`CGO_ENABLED=0`; the dev build that was hardware-tested is the CGO
   diagnostic one): `keenetic-xray internal ensure-xray-core
   --tag=v26.9.30` with no base-URL override, restart, confirm an AWG
   profile still passes traffic -- then cut a keenetic-xray release that
   carries the new `PrereleaseTag`.
4. **`v26.10.21`** (`v26.10.10` was withdrawn upstream): patch in the repo,
   dev build staged (see the 2026-10-25 section). Left: run it on a router
   (an AWG profile through the patched core, a plain `security=tls` profile
   to confirm it still verifies its server against the built-in roots, and
   the TUN transport's speed), and only then add the tag to
   `AWG_CONFIRMED_TAGS` (workflow *and* `xraycore.AWGConfirmedTags`), move
   `xraycore.PrereleaseTag`, build the real `xray-core/v26.10.21` without
   `awg_dev`, and ship the app release right after (the bot offers a real
   `xray-core/` release at once, and an app build that lacks the tag in
   `AWGConfirmedTags` warns "no AWG in this core").
5. If re-entering Plan Mode for any of these, re-read this document
   plus the current code first — don't assume an old plan-file survived
   (Plan Mode's plan file gets reused for whatever's being planned at the
   time).
