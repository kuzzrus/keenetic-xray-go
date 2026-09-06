# Selective routing (`routes`)

By default this project sends **all** proxied traffic through one VLESS
tunnel and leaves *which* traffic is proxied to Keenetic (assign devices
or a policy to `Proxy0`). The `routes` feature is the narrower, more
common want: **only these domains/subnets go through the tunnel, the rest
stays direct.**

## How it works

It drives Keenetic's own **DNS-based routes** (KeeneticOS 5.0+, finalised
in 5.0.4). Each named list becomes, on the router:

```
object-group fqdn keenetic-xray-<name>
    include youtube.com
    include 1.2.3.0/24
!
dns-proxy
    route object-group keenetic-xray-<name> Proxy0 auto [reject]
!
```

Keenetic watches DNS answers for the listed domains, collects their IPs,
and routes matching connections into `Proxy0` — which this project has
already pointed at the local Xray SOCKS inbound. `internal/keenetic`
(`ApplyRoutes` / `ShowRoutes` / `ClearRoutes`) reconciles the whole set
idempotently: it diffs the desired lists against what's on the router and
issues only the delta, then `system configuration save` once.

Lists live in `config.json` (`routing.lists[]`) and are re-applied when
the daemon starts, so a firmware event or config reset self-heals.

## Safety: your own lists are untouched

Every object-group and route this project creates is prefixed
`keenetic-xray-`. `ApplyRoutes`, `ClearRoutes`, the running-config
parser, and the package-purge cleanup **only ever read or write names
with that prefix**. Lists you built by hand in the Keenetic web UI
(`youtube`, `telegram`, `domain-list0`, …) are never read, changed, or
deleted. It's fine for a `keenetic-xray-*` list to overlap them — both
just route to `Proxy0`.

## Router requirements (Keenetic's, not ours)

DNS-based routes only work when:

1. **The router is the client's DNS server.** Keenetic populates each
   list's IP set by snooping DNS answers. A device using DoH/DoT or a
   hard-coded public resolver (`8.8.8.8`) bypasses that — its domains
   won't route.
2. **The client is on the default connection policy** (Приоритеты
   подключений).
3. **Warm-up.** The first connection to a domain may go direct until the
   router has seen a DNS answer for it. Subsequent connections route.
   Also: a connection *already open* to an IP when you add/change a list
   keeps its original route until it closes — netfilter caches the route
   decision per flow. If `conntrack-tools` is installed
   (`opkg install conntrack-tools`), the tool runs `conntrack -F` after
   any list change so those flows re-evaluate on their next packet and
   move into the tunnel; without it, they just age out.

`*` wildcards aren't allowed; a domain automatically covers its
subdomains. IDN must be entered in punycode (`xn--…`). IPv6 isn't
supported in this version.

## Commands

CLI:

```
keenetic-xray routes new youtube youtube.com googlevideo.com ytimg.com
keenetic-xray routes add youtube 1.2.3.0/24
keenetic-xray routes set youtube --iface=Wireguard4   # send this list out a different interface
keenetic-xray routes set youtube --exclusive          # drop, don't leak direct, if the tunnel is down
keenetic-xray routes disable youtube                  # keep the list, stop routing it
keenetic-xray routes show youtube                     # config vs what's live on the router
keenetic-xray routes rm youtube
```

Bot: `📍 Маршруты` on a router card (add / remove entries, on/off,
`🎯 Интерфейс`, delete, show), or
`/routes <router> {list|show|new|add|del|rm|on|off|iface <name> <ProxyN|WireguardN>}`.

## `--exclusive`

Adds `reject` to the route: when `Proxy0` is down, matched traffic is
dropped rather than sent out the WAN unprotected. Off by default —
availability over leak-prevention — because the failover daemon normally
keeps a tunnel live regardless.

## Video stalls through the tunnel? MSS clamping

If routed video (Instagram Reels, YouTube Shorts) plays for a few
seconds, freezes ~20 s, then resumes — sometimes to a black screen —
it's a **PMTU black hole**, not a routing problem. The LAN client
negotiates a TCP MSS of ~1460 against the router's 1500-byte MTU, but
those full-size segments don't fit the `Proxy0 → xray → xhttp/REALITY`
path, and large transfers stall on retransmit. It affects traffic
*forwarded* by the router only — a client app running its own xray
(Happ, an AWG tunnel) sizes its own segments and isn't touched, which is
why "direct on the phone" works while the router doesn't.

Fix: `keenetic-xray transport mss auto` (= MSS 1360). It adds one
`iptables` mangle rule tagged `keenetic-xray-mss` that clamps forwarded
TCP SYNs. Presets: `1400` milder, `1280` most headroom, `off` to remove.
Applies only while `Proxy0` is on; removed on `proxy0 off`; `iptables`
is installed via `opkg` if missing; the daemon re-asserts the rule every
2 minutes in case the firmware flushes it. In the bot: the `📶 MSS`
presets on `⚙️ Порты и транспорт`, or `/proxy0 <router> mss auto|off|N`.

## Routing through WireGuard instead of Proxy0

`routes ... --iface=` also accepts a `WireguardN` name, not just
`ProxyN`. Two ways to have one:

- **Your own Keenetic WireGuard tunnel.** If you already run a WG client
  interface to a VPS (configured in the Keenetic web UI), just point a
  list at it: `routes set <list> --iface=Wireguard2`. The tool writes
  `dns-proxy route object-group … Wireguard2 auto` and nothing else --
  the tunnel itself is yours to manage.

- **The in-router WG transport** (`transport wg on`). This stands up a
  `WireguardN` interface *to the local xray* -- `LAN → WireguardN → xray
  wireguard inbound → VLESS/xhttp out` -- as an alternative router→xray
  hop to Proxy0/SOCKS. The tool owns this interface end to end: it picks
  the lowest free `WireguardN`, generates the xray-side X25519 keypair +
  a pre-shared key, lets KeeneticOS generate its own keypair and reads
  the public key back, and wires the peer. The interface is marked
  `description keenetic-xray-wg`; **only** that interface is ever read or
  removed, so your hand-made WG tunnels are untouched. It gets MTU 1280
  and KeeneticOS's `ip tcp adjust-mss pmtu`, so the PMTU stall above
  doesn't apply here. Coexists with `Proxy0`. `transport wg off` (or a
  package purge) removes the interface; the daemon re-asserts it on
  start. Bot: `🔌 WG-транспорт` under `⚙️ Порты и транспорт`, or
  `/proxy0 <router> wg on|off|show`.

  It is a lateral choice, not an upgrade: WireGuard adds ChaCha20 over a
  localhost hop and ~60 bytes of encapsulation. Reach for it when you
  want the cleaner Keenetic routing integration (policies, `ip route`,
  `dns-proxy route` all target a real interface), not for raw speed.
