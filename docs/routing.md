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

`*` wildcards aren't allowed; a domain automatically covers its
subdomains. IDN must be entered in punycode (`xn--…`). IPv6 isn't
supported in this version.

## Commands

CLI:

```
keenetic-xray routes new youtube youtube.com googlevideo.com ytimg.com
keenetic-xray routes add youtube 1.2.3.0/24
keenetic-xray routes set youtube --exclusive          # drop, don't leak direct, if the tunnel is down
keenetic-xray routes disable youtube                  # keep the list, stop routing it
keenetic-xray routes show youtube                     # config vs what's live on the router
keenetic-xray routes rm youtube
```

Bot: `📍 Маршруты` on a router card (add / remove entries, on/off, delete,
show), or `/routes <router> {list|show|new|add|del|rm|on|off}`.

## `--exclusive`

Adds `reject` to the route: when `Proxy0` is down, matched traffic is
dropped rather than sent out the WAN unprotected. Off by default —
availability over leak-prevention — because the failover daemon normally
keeps a tunnel live regardless.
