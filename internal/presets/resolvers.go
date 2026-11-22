package presets

import (
	"net"
	"strings"
)

// Public DNS resolvers inside a list of subnets.
//
// A provider's published ranges (Google's, Cloudflare's, ...) include the
// addresses of its public DNS service: the google presets carry 8.8.8.0/24 and
// 8.8.4.0/24. With such a list bound to the tunnel, a LAN device that has a
// resolver hard-coded (a Chromecast, a TV, an app doing DoT/DoH on its own) sends
// its DNS into the tunnel too. That is not wrong -- it keeps the provider from
// spoofing the answers and opens DoT/DoH to a resolver that is blocked direct --
// but it is a side effect nobody asked for when they pressed "add the IP ranges",
// and without UDP/53 in the tunnel such a device is left without name resolution.
// The lists are left as they are; this is how the CLI and the bot say so.

type publicResolver struct {
	name   string
	ranges []*net.IPNet
}

func mustResolver(name string, cidrs ...string) publicResolver {
	r := publicResolver{name: name}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("presets: bad resolver range " + c) // a typo in this file, caught by the first test run
		}
		r.ranges = append(r.ranges, n)
	}
	return r
}

// publicResolvers are the services worth naming: the anycast ranges of the
// resolvers people hard-code.
var publicResolvers = []publicResolver{
	mustResolver("Google Public DNS (8.8.8.8, 8.8.4.4)", "8.8.8.0/24", "8.8.4.0/24"),
	mustResolver("Cloudflare (1.1.1.1)", "1.1.1.0/24", "1.0.0.0/24"),
	mustResolver("Quad9 (9.9.9.9)", "9.9.9.0/24", "149.112.112.0/24"),
	mustResolver("OpenDNS (208.67.222.222)", "208.67.222.0/24", "208.67.220.0/24"),
}

// overlaps reports whether the two networks share an address: one contains the
// other's base address (CIDR blocks are either nested or disjoint).
func overlaps(a, b *net.IPNet) bool { return a.Contains(b.IP) || b.Contains(a.IP) }

// ResolversIn names the well-known public DNS services that a list of subnet
// entries (CIDR blocks or single addresses, as in a "-ip" preset) covers --
// an entry equal to, inside or wider than the service's range counts, since all
// three put the resolver's address into the tunnel. Entries that are not
// addresses are ignored. The names come in a fixed order, each once.
func ResolversIn(entries []string) []string {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if !strings.Contains(e, "/") {
			e += "/32"
		}
		if _, n, err := net.ParseCIDR(e); err == nil && n.IP.To4() != nil {
			nets = append(nets, n)
		}
	}
	var out []string
	for _, r := range publicResolvers {
	next:
		for _, rn := range r.ranges {
			for _, n := range nets {
				if overlaps(rn, n) {
					out = append(out, r.name)
					break next
				}
			}
		}
	}
	return out
}

// Resolvers names the public DNS services a subnet preset covers; nil for a
// domain preset or an unknown one.
func (p Preset) Resolvers() []string {
	if p.Kind != "cidr" {
		return nil
	}
	entries, ok := Entries(p.Name)
	if !ok {
		return nil
	}
	return ResolversIn(entries)
}

// ResolverNote is the sentence both the CLI and the bot say about a list that
// covers public DNS services (the result of ResolversIn / Resolvers).
func ResolverNote(names []string) string {
	return "в IP-диапазонах есть публичный DNS — " + strings.Join(names, "; ") +
		". Устройства с зашитым адресом резолвера (Chromecast, ТВ, приложения с собственным DoT/DoH) " +
		"отправят свой DNS в туннель: это обходит подмену DNS провайдером, но если туннель не несёт UDP/53, " +
		"такое устройство останется без разрешения имён. Список не менялся; если не нужно — уберите эти подсети из него"
}
