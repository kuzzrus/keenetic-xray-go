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
		ID: "adguard-unfiltered", Name: "AdGuard Unfiltered", Note: "без фильтрации",
		DoT: []TLS{{"94.140.14.140", "unfiltered.adguard-dns.com"}, {"94.140.14.141", "unfiltered.adguard-dns.com"}},
		DoH: []HTTPS{{"https://unfiltered.adguard-dns.com/dns-query"}},
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
		ID: "dns0", Name: "dns0.eu", Note: "EU, НКО",
		DoT: []TLS{{"193.110.81.0", "dns0.eu"}, {"185.253.5.0", "dns0.eu"}},
		DoH: []HTTPS{{"https://dns0.eu/"}},
	},
	{
		ID: "dns0-zero", Name: "dns0.eu ZERO", Note: "EU, агрессивная защита",
		DoT: []TLS{{"193.110.81.9", "zero.dns0.eu"}, {"185.253.5.9", "zero.dns0.eu"}},
		DoH: []HTTPS{{"https://zero.dns0.eu/"}},
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
		ID: "controld-unfiltered", Name: "ControlD Unfiltered", Note: "без фильтрации",
		DoT: []TLS{{"76.76.2.0", "p0.freedns.controld.com"}, {"76.76.10.0", "p0.freedns.controld.com"}},
		DoH: []HTTPS{{"https://freedns.controld.com/p0"}},
	},
}

// Providers returns the catalogue in display order.
func Providers() []Provider { return providers }

// Find looks a provider up by ID (case-insensitive).
func Find(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// AllTLSIPs / AllDoHURLs are every endpoint the catalogue knows -- the
// "managed" set internal/keenetic uses to decide which upstreams on the
// router are ours to remove. A hand-added upstream with a different
// IP/URL is never touched.
func AllTLSIPs() []string {
	var out []string
	for _, p := range providers {
		for _, t := range p.DoT {
			out = append(out, t.IP)
		}
	}
	return out
}

func AllDoHURLs() []string {
	var out []string
	for _, p := range providers {
		for _, h := range p.DoH {
			out = append(out, h.URL)
		}
	}
	return out
}
