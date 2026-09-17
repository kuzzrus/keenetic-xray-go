# Handoff — AmneziaWG (AWG) egress support

Kickoff brief for a fresh session with no access to a previous session's
`.claude/memory/` files. Written 2026-09-17, repo at `v0.32.30` / `main`.

For what this project is and the general working conventions ("делай и
сразу сливай" flow, CI checks, versioning, commit/PR trailers, language,
the `parse_test.go` CRLF gotcha), see
[`docs/HANDOFF-naive.md`](HANDOFF-naive.md) §1-2 — identical here, not
repeated.

**Status: fully researched, plan written, never started.** No code exists
for this yet. Plan Mode's own plan file (`.claude/plans/*.md`) held this
plan at one point but has since been overwritten by a different feature
(Russian-IP adaptive-route exclusion) the user asked to build first — this
document is the durable copy.

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

## How to resume

Re-enter Plan Mode, re-read this document plus the current code
(`internal/config/xray.go`'s `buildOutbound`, `internal/config/
profile.go`, this project's pinned xray-core tag) since code may have
moved on since this was written, then write a fresh plan-file draft
from this document rather than assuming an old plan-file survived (it
won't have — Plan Mode's plan file gets reused for whatever's being
planned at the time).
