# Secure DNS (`dns`)

Points Keenetic's built-in `dns-proxy` at a DNS-over-TLS / DNS-over-HTTPS
resolver. Useful when the ISP's DNS returns poisoned answers for blocked
domains — including for the selective-routing lists, since the router
builds each list's IP set by snooping DNS replies.

## How it works

The router side is `dns-proxy tls upstream <ip> sni <host>` and
`dns-proxy https upstream <url> dnsm`, both children of the `dns-proxy`
block in `show running-config`. Removal syntax differs — DoT by IP
(`no dns-proxy tls upstream <ip>`), DoH by URL — confirmed on
KeeneticOS 5.1.3; the feature gates at KeeneticOS 3.1+.

There is no marker on a DNS upstream, so scoping is by value:
`ApplyDNS` only ever removes an upstream whose IP (DoT) or URL (DoH) is
in this project's catalogue (`internal/dnsupstream`) or the config's own
`dns.dot` / `dns.doh`. An upstream added by hand in the web UI or CLI is
never touched. The daemon re-asserts the configured upstreams on its
reconcile loop, like Proxy0 / routes / MSS.

## Commands

```
keenetic-xray dns test                     # measure every provider's DoT+DoH latency from the router
keenetic-xray dns list                     # provider ids
keenetic-xray dns preset cloudflare        # apply (DoT + DoH); --dot / --doh to pick one
keenetic-xray dns preset quad9 --doh
keenetic-xray dns set doh https://dns.example/dns-query
keenetic-xray dns set dot 1.2.3.4 dns.example
keenetic-xray dns show                     # config + what's live on the router (ours marked)
keenetic-xray dns off                      # remove every managed upstream
```

Bot: `⚙️ Порты и транспорт` → `🧭 DNS` → provider button → `DoT / DoH /
Оба`; `📊 Проверить` runs the latency table; `✏️ Свои` for custom
upstreams; `⛔ Убрать наши`. Or `/dns <router> {show|test|preset <id>
[dot|doh|both]|off}`.

## `dns test`

The agent (Go, stdlib) probes each provider's first DoT and first DoH
endpoint in parallel: a TLS dial to `:853` + one `example.com A` query
over DNS-over-TCP framing, and an `application/dns-message` POST for DoH,
each with a 3 s timeout. The table sorts working resolvers by latency;
`— (timeout)` / `— (refused)` means the router can't reach it (often DPI
on `:853`). DoH over `:443` usually survives where DoT doesn't.

## Providers

~20 public resolvers (`internal/dnsupstream/providers.go`): Cloudflare
(+Security), Google, Quad9 (+Unsecured), AdGuard (+Family), Yandex
(+Safe, DoT), Mullvad (+Adblock), Gcore, DNS4EU, DNS.SB, Comss.one (DoH),
OpenDNS, CleanBrowsing, UncensoredDNS, ControlD Unfiltered, LibreDNS. A
filtering resolver (AdGuard, CleanBrowsing) can return NXDOMAIN for
ad/tracker domains — which can interfere with routing. Run `dns test` on
the router to see which are actually reachable from your ISP.

## Not done

DoH bootstrap-IP pinning, per-interface / per-policy DNS, disabling the
plain-`:53` upstreams (kept as a fallback), and routing a resolver's own
IP through the tunnel.
