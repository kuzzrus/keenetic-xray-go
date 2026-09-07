// Package dnsupstream holds the curated list of public DNS resolvers the
// "🧭 DNS" feature offers (DNS-over-TLS and DNS-over-HTTPS), plus a
// stdlib-only latency probe so an operator can measure them from the
// router before picking one. It never talks to ndmc -- applying a choice
// is internal/keenetic.ApplyDNS.
package dnsupstream

import "strings"

// TLS is one DNS-over-TLS endpoint: the resolver IP and the TLS SNI /
// certificate name Keenetic needs (`dns-proxy tls upstream <IP> sni <SNI>`).
type TLS struct {
	IP  string
	SNI string
}

// HTTPS is one DNS-over-HTTPS endpoint URL (`dns-proxy https upstream
// <URL> dnsm`). The message format is always RFC 8484 wire ("dnsm").
type HTTPS struct {
	URL string
}

// Provider is one selectable resolver. DoT/DoH each list the endpoints
// applied together when that mode is chosen (usually primary + secondary).
type Provider struct {
	ID   string // stable slug used in config + callback_data
	Name string
	Note string // one-line hint shown in the UI
	DoT  []TLS
	DoH  []HTTPS
}

// providers is the fixed catalogue. A few values (Comss IPs, some DoH
// paths) are best-effort and are meant to be checked with `dns test` on
// real hardware before trusting them.
var providers = []Provider{
	{
		ID: "cloudflare", Name: "Cloudflare", Note: "быстрый, без фильтрации",
		DoT: []TLS{{"1.1.1.1", "one.one.one.one"}, {"1.0.0.1", "one.one.one.one"}},
		DoH: []HTTPS{{"https://cloudflare-dns.com/dns-query"}},
	},
	{
		ID: "cloudflare-security", Name: "Cloudflare Security", Note: "блокирует малварь",
		DoT: []TLS{{"1.1.1.2", "security.cloudflare-dns.com"}, {"1.0.0.2", "security.cloudflare-dns.com"}},
		DoH: []HTTPS{{"https://security.cloudflare-dns.com/dns-query"}},
	},
	{
		ID: "google", Name: "Google", Note: "",
		DoT: []TLS{{"8.8.8.8", "dns.google"}, {"8.8.4.4", "dns.google"}},
		DoH: []HTTPS{{"https://dns.google/dns-query"}},
	},
	{
		ID: "quad9", Name: "Quad9", Note: "блокирует малварь, ECS off",
		DoT: []TLS{{"9.9.9.9", "dns.quad9.net"}, {"149.112.112.112", "dns.quad9.net"}},
		DoH: []HTTPS{{"https://dns.quad9.net/dns-query"}},
	},
	{
		ID: "quad9-unsecured", Name: "Quad9 Unsecured", Note: "без фильтрации",
		DoT: []TLS{{"9.9.9.10", "dns10.quad9.net"}, {"149.112.112.10", "dns10.quad9.net"}},
		DoH: []HTTPS{{"https://dns10.quad9.net/dns-query"}},
	},
	{
		ID: "adguard", Name: "AdGuard", Note: "режет рекламу — возможен конфликт с маршрутами",
		DoT: []TLS{{"94.140.14.14", "dns.adguard-dns.com"}, {"94.140.15.15", "dns.adguard-dns.com"}},
		DoH: []HTTPS{{"https://dns.adguard-dns.com/dns-query"}},
	},
	{
		ID: "adguard-family", Name: "AdGuard Family", Note: "реклама + взрослый контент",
		DoT: []TLS{{"94.140.14.15", "family.adguard-dns.com"}, {"94.140.15.16", "family.adguard-dns.com"}},
		DoH: []HTTPS{{"https://family.adguard-dns.com/dns-query"}},
	},
	{
		ID: "yandex", Name: "Yandex", Note: "RU, DoT",
		DoT: []TLS{{"77.88.8.8", "common.dot.dns.yandex.net"}, {"77.88.8.1", "common.dot.dns.yandex.net"}},
	},
	{
		ID: "yandex-safe", Name: "Yandex Safe", Note: "RU, блокирует мошенников (DoT)",
		DoT: []TLS{{"77.88.8.88", "safe.dot.dns.yandex.net"}, {"77.88.8.2", "safe.dot.dns.yandex.net"}},
	},
	{
		ID: "mullvad", Name: "Mullvad", Note: "без логов, Швеция",
		DoT: []TLS{{"194.242.2.2", "dns.mullvad.net"}},
		DoH: []HTTPS{{"https://dns.mullvad.net/dns-query"}},
	},
	{
		ID: "mullvad-adblock", Name: "Mullvad Adblock", Note: "без логов + режет рекламу",
		DoT: []TLS{{"194.242.2.3", "adblock.dns.mullvad.net"}},
		DoH: []HTTPS{{"https://adblock.dns.mullvad.net/dns-query"}},
	},
	{
		ID: "dns4eu", Name: "DNS4EU", Note: "официальный резолвер ЕС, блокирует малварь/фишинг",
		DoT: []TLS{{"86.54.11.1", "protective.joindns4.eu"}, {"86.54.11.201", "protective.joindns4.eu"}},
		DoH: []HTTPS{{"https://protective.joindns4.eu/dns-query"}},
	},
	{
		ID: "dnssb", Name: "DNS.SB", Note: "без логов, anycast",
		DoT: []TLS{{"185.222.222.222", "dns.sb"}, {"45.11.45.11", "dns.sb"}},
		DoH: []HTTPS{{"https://doh.dns.sb/dns-query"}},
	},
	{
		ID: "comss", Name: "Comss.one", Note: "RU, анти-цензура (DoH)",
		DoH: []HTTPS{{"https://dns.comss.one/dns-query"}},
	},
	{
		ID: "opendns", Name: "OpenDNS", Note: "Cisco; DoT неофициальный",
		DoT: []TLS{{"208.67.222.222", "dns.opendns.com"}, {"208.67.220.220", "dns.opendns.com"}},
		DoH: []HTTPS{{"https://doh.opendns.com/dns-query"}},
	},
	{
		ID: "cleanbrowsing", Name: "CleanBrowsing Security", Note: "блокирует малварь/фишинг",
		DoT: []TLS{{"185.228.168.9", "security-filter-dns.cleanbrowsing.org"}, {"185.228.169.9", "security-filter-dns.cleanbrowsing.org"}},
		DoH: []HTTPS{{"https://doh.cleanbrowsing.org/doh/security-filter/"}},
	},
	{
		ID: "uncensoreddns", Name: "UncensoredDNS", Note: "Дания, без логов",
		DoT: []TLS{{"91.239.100.100", "anycast.censurfridns.dk"}, {"89.233.43.71", "unicast.censurfridns.dk"}},
		DoH: []HTTPS{{"https://anycast.uncensoreddns.org/dns-query"}},
	},
	{
		ID: "controld-unfiltered", Name: "ControlD Unfiltered", Note: "без фильтрации (DoH)",
		DoH: []HTTPS{{"https://freedns.controld.com/p0"}},
	},
	{
		ID: "libredns", Name: "LibreDNS", Note: "община, без логов, Hetzner DE (DoH)",
		DoH: []HTTPS{{"https://doh.libredns.gr/dns-query"}},
	},
}

// candidates is a wider pool probed only by `dns test --all`, not shown
// as buttons. It's the shortlist we curate `providers` down from after a
// run on real hardware.
var candidates = []Provider{
	{ID: "cloudflare-family", Name: "Cloudflare Family", Note: "малварь + взрослый контент",
		DoT: []TLS{{"1.1.1.3", "family.cloudflare-dns.com"}, {"1.0.0.3", "family.cloudflare-dns.com"}},
		DoH: []HTTPS{{"https://family.cloudflare-dns.com/dns-query"}}},
	{ID: "quad9-ecs", Name: "Quad9 ECS", Note: "с EDNS Client Subnet (лучше гео CDN)",
		DoT: []TLS{{"9.9.9.11", "dns11.quad9.net"}, {"149.112.112.11", "dns11.quad9.net"}},
		DoH: []HTTPS{{"https://dns11.quad9.net/dns-query"}}},
	{ID: "controld-p1", Name: "ControlD Malware", Note: "блок малвари (DoH)",
		DoH: []HTTPS{{"https://freedns.controld.com/p1"}}},
	{ID: "controld-p2", Name: "ControlD Malware+Ads", Note: "малварь + реклама (DoH)",
		DoH: []HTTPS{{"https://freedns.controld.com/p2"}}},
	{ID: "dns4eu-noads", Name: "DNS4EU + Ads", Note: "ЕС, малварь + реклама",
		DoT: []TLS{{"86.54.11.13", "noads.joindns4.eu"}}, DoH: []HTTPS{{"https://noads.joindns4.eu/dns-query"}}},
	{ID: "dns4eu-unfiltered", Name: "DNS4EU Unfiltered", Note: "ЕС, без фильтрации",
		DoT: []TLS{{"86.54.11.100", "unfiltered.joindns4.eu"}}, DoH: []HTTPS{{"https://unfiltered.joindns4.eu/dns-query"}}},
	{ID: "yandex-family", Name: "Yandex Family", Note: "RU, + взрослый контент (DoT)",
		DoT: []TLS{{"77.88.8.7", "family.dot.dns.yandex.net"}, {"77.88.8.3", "family.dot.dns.yandex.net"}}},
	{ID: "blahdns-de", Name: "BlahDNS DE", Note: "без логов, режет рекламу, Германия",
		DoT: []TLS{{"78.46.244.143", "dot-de.blahdns.com"}}, DoH: []HTTPS{{"https://doh-de.blahdns.com/dns-query"}}},
	{ID: "dnsforge", Name: "DNSforge", Note: "Германия, режет рекламу/трекеры",
		DoT: []TLS{{"176.9.93.198", "dnsforge.de"}, {"176.9.1.117", "dnsforge.de"}}, DoH: []HTTPS{{"https://dnsforge.de/dns-query"}}},
	{ID: "ffmuc", Name: "Freifunk München", Note: "без логов, Германия",
		DoT: []TLS{{"5.1.66.255", "dot.ffmuc.net"}, {"185.150.99.255", "dot.ffmuc.net"}}, DoH: []HTTPS{{"https://doh.ffmuc.net/dns-query"}}},
	{ID: "digitale-gesellschaft", Name: "Digitale Gesellschaft", Note: "НКО, без логов, Швейцария",
		DoT: []TLS{{"185.95.218.42", "dns.digitale-gesellschaft.ch"}, {"185.95.218.43", "dns.digitale-gesellschaft.ch"}},
		DoH: []HTTPS{{"https://dns.digitale-gesellschaft.ch/dns-query"}}},
	{ID: "switch", Name: "SWITCH", Note: "академ. сеть Швейцарии",
		DoT: []TLS{{"130.59.31.248", "dns.switch.ch"}, {"130.59.31.251", "dns.switch.ch"}}, DoH: []HTTPS{{"https://dns.switch.ch/dns-query"}}},
	{ID: "restena", Name: "Restena", Note: "исследовательская сеть Люксембурга",
		DoT: []TLS{{"158.64.1.29", "kaitain.restena.lu"}}, DoH: []HTTPS{{"https://kaitain.restena.lu/dns-query"}}},
	{ID: "he-net", Name: "Hurricane Electric", Note: "крупный транзит, без фильтрации",
		DoT: []TLS{{"74.82.42.42", "ordns.he.net"}}, DoH: []HTTPS{{"https://ordns.he.net/dns-query"}}},
	{ID: "canadianshield", Name: "CIRA Canadian Shield", Note: "Канада, приватный профиль",
		DoT: []TLS{{"149.112.121.10", "private.canadianshield.cira.ca"}, {"149.112.122.10", "private.canadianshield.cira.ca"}},
		DoH: []HTTPS{{"https://private.canadianshield.cira.ca/dns-query"}}},
	{ID: "alidns", Name: "AliDNS", Note: "Alibaba, Китай — anycast",
		DoT: []TLS{{"223.5.5.5", "dns.alidns.com"}, {"223.6.6.6", "dns.alidns.com"}}, DoH: []HTTPS{{"https://dns.alidns.com/dns-query"}}},
	{ID: "dnspod", Name: "DNSPod", Note: "Tencent, Китай",
		DoT: []TLS{{"1.12.12.12", "dot.pub"}, {"120.53.53.53", "dot.pub"}}, DoH: []HTTPS{{"https://doh.pub/dns-query"}}},
	{ID: "iij", Name: "IIJ", Note: "Япония",
		DoT: []TLS{{"103.2.57.5", "public.dns.iij.jp"}, {"103.2.57.6", "public.dns.iij.jp"}}, DoH: []HTTPS{{"https://public.dns.iij.jp/dns-query"}}},
	{ID: "tiarap", Name: "Tiarap", Note: "Сингапур, режет рекламу/трекеры",
		DoT: []TLS{{"174.138.21.128", "doh.tiar.app"}}, DoH: []HTTPS{{"https://doh.tiar.app/dns-query"}}},
	{ID: "controld-uncensored", Name: "ControlD Uncensored", Note: "разблокирует geo-контент (DoH)",
		DoH: []HTTPS{{"https://freedns.controld.com/uncensored"}}},
	{ID: "nextdns-anycast", Name: "NextDNS (общий)", Note: "без персон. профиля",
		DoT: []TLS{{"45.90.28.0", "dns.nextdns.io"}, {"45.90.30.0", "dns.nextdns.io"}}, DoH: []HTTPS{{"https://dns.nextdns.io/"}}},
	{ID: "controld-block-ads", Name: "ControlD Ads/Tracking", Note: "реклама + трекеры (DoH)",
		DoH: []HTTPS{{"https://freedns.controld.com/p3"}}},
}

// Providers returns the shown catalogue in display order.
func Providers() []Provider { return providers }

// TestPool is providers + candidates, for `dns test --all` — a one-off
// wide sweep we curate the shown catalogue from.
func TestPool() []Provider {
	out := make([]Provider, 0, len(providers)+len(candidates))
	out = append(out, providers...)
	out = append(out, candidates...)
	return out
}

// InCatalogue reports whether id is one of the shown providers (not just
// a test-pool candidate).
func InCatalogue(id string) bool {
	for _, p := range providers {
		if p.ID == id {
			return true
		}
	}
	return false
}

// Find looks a provider up by ID (case-insensitive), searching the shown
// catalogue then the wider test pool -- so `dns preset <candidate-id>`
// works from the CLI before a candidate is promoted to a button.
func Find(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	for _, p := range candidates {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// AllTLSIPs / AllDoHURLs are every endpoint this project knows (shown
// catalogue + test-pool candidates) -- the "managed" set
// internal/keenetic uses to decide which upstreams on the router are
// ours to remove. A hand-added upstream with a different IP/URL is never
// touched.
func AllTLSIPs() []string {
	var out []string
	for _, p := range TestPool() {
		for _, t := range p.DoT {
			out = append(out, t.IP)
		}
	}
	return out
}

func AllDoHURLs() []string {
	var out []string
	for _, p := range TestPool() {
		for _, h := range p.DoH {
			out = append(out, h.URL)
		}
	}
	return out
}
