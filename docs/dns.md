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
keenetic-xray dns test                     # measure the shown catalogue's DoT+DoH latency from the router
keenetic-xray dns test --all               # also probe the wider candidate pool (~45), for curating the list
keenetic-xray dns list                     # provider ids
keenetic-xray dns preset cloudflare        # apply (DoT + DoH); --dot / --doh to pick one
keenetic-xray dns preset quad9 --doh
keenetic-xray dns preset controld-p1,dns4eu --doh   # several at once, the same mode for each
keenetic-xray dns set doh https://dns.example/dns-query
keenetic-xray dns set dot 1.2.3.4 dns.example
keenetic-xray dns show                     # config + what's live on the router (ours marked)
keenetic-xray dns off                      # remove every managed upstream
```

Bot: `⚙️ Порты и транспорт` → `🧭 DNS` → provider button → `DoT / DoH /
Оба`; `📊 Проверить` runs the latency table and shows the top 4 with
`✅ Применить весь топ` (every provider that answered, at once) or one
button per provider — both apply only the protocols that answered in the
test, so a DoT port the network blocks doesn't become an upstream (the
ranking lives in the control server's memory: after a server restart the
button asks for a fresh test); `✏️ Свои` for custom upstreams;
`⛔ Убрать наши`. Or `/dns <router> {show|test|preset <id>
[dot|doh|both]|off}`.

## `dns test`

The agent (Go, stdlib) probes each provider's first DoT and first DoH
endpoint in parallel: a TLS dial to `:853` + one `example.com A` query
over DNS-over-TCP framing, and an `application/dns-message` POST for DoH,
each with a 3 s timeout. The table sorts working resolvers by latency;
`— (timeout)` / `— (refused)` means the router can't reach it (often DPI
on `:853`). DoH over `:443` usually survives where DoT doesn't.

## Providers

The shown catalogue (`providers` in `internal/dnsupstream/providers.go`)
is ~22 resolvers: Cloudflare (+Security), Google, Quad9 (+Unsecured),
AdGuard (+Family), DNS4EU (+Unfiltered), ControlD (Unfiltered,
Uncensored, Malware; DoH), Mullvad, Hurricane Electric, Freifunk
München, DNS for Family (DoH), DNS.SB, Comss.one (DoH), OpenDNS,
CleanBrowsing, UncensoredDNS, LibreDNS (DoH). Yandex's three were
dropped (a Russian operator); their endpoints stay in a `retired` list,
so an upstream an older version set is still recognised as ours and
removed on the next apply. A wider `candidates` pool (~23 more: BlahDNS,
DNSforge, SWITCH, AliDNS, DNSPod, NextDNS, more ControlD/DNS4EU
variants, …) is probed only by `dns test --all` and never shown as a
button — it's what the shown list is curated from after a run on real
hardware. A filtering resolver (AdGuard, CleanBrowsing) can return
NXDOMAIN for ad/tracker domains, which can interfere with routing. Run
`dns test` (or `--all`) on the router to see what's actually reachable
from your ISP.

## Not done

DoH bootstrap-IP pinning, per-interface / per-policy DNS, disabling the
plain-`:53` upstreams (kept as a fallback), and routing a resolver's own
IP through the tunnel.
