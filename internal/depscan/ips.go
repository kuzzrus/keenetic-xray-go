package depscan

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// IP addresses of the hosts a scan finds.
//
// A domain entry in a route list is enough for everything that asks DNS
// for the name: the router sees the answer and routes the address. Some
// traffic never does. A call app connects to a media server's address it
// was handed over its own signalling, or one it remembered, or resolved
// with its own DoH -- the router's DNS never sees the name, and only an
// address entry catches the connection. So for the hosts that need the
// tunnel (and the scanned domains themselves) the scan also reports what
// the name resolves to, to be added as /32 entries to an IP companion list
// (config.AddCompanionIPs).
//
// What it will not offer, because adding it would do more harm than good:
// an address that is private or reserved (and 0.0.0.0, a DNS filter's
// answer for "blocked"), one in a Russian range (a poisoned answer is
// typically one, and Russian services must not leave through a foreign
// exit), and one of Cloudflare's -- an anycast address serves thousands of
// unrelated sites, so a /32 for it would route every one of them. Names
// are resolved by the router's own resolver: if that is the provider's
// poisoned DNS the addresses are the provider's lies, which the Russian
// range check usually catches.

// Resolver looks up the IPv4 addresses a name has.
type Resolver interface {
	LookupIPv4(ctx context.Context, host string) ([]string, error)
}

type netResolver struct{}

func (netResolver) LookupIPv4(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out, nil
}

const (
	// maxIPsPerHost caps what one name contributes: a name with dozens of
	// A records is a large pool, and a few of them stand for none.
	maxIPsPerHost = 8
	// ipLookupTimeout bounds one name's lookup; ipResolveBudget all of them,
	// taken out of what is left of the scan's own budget.
	ipLookupTimeout = 3 * time.Second
	ipResolveBudget = 6 * time.Second
)

// unroutableV4 are ranges no route entry should name: the "this network"
// block (0.0.0.0 is what a DNS filter answers for a blocked name),
// private, shared (CGNAT), loopback, link-local, the documentation and
// benchmarking blocks, and multicast/reserved space.
var unroutableV4 = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
)

// cloudflareV4 is Cloudflare's published IPv4 list (cloudflare.com/ips-v4).
var cloudflareV4 = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// routableIP reports whether a is an address worth offering for a route
// entry; exclude, if set, is asked about its text form (the Russian
// ranges).
func routableIP(a netip.Addr, exclude func(string) bool) bool {
	if !a.Is4() || inPrefixes(a, unroutableV4) || inPrefixes(a, cloudflareV4) {
		return false
	}
	return exclude == nil || !exclude(a.String())
}

// resolveIPs returns the offerable IPv4 addresses of name -- distinct,
// in address order, at most maxIPsPerHost -- and how many it had to leave
// out. A lookup that fails is no addresses, not an error: names that only
// answer through the tunnel's far end are simply not resolved here.
func resolveIPs(ctx context.Context, r Resolver, exclude func(string) bool, name string) (ips []string, dropped int) {
	lctx, cancel := context.WithTimeout(ctx, ipLookupTimeout)
	defer cancel()
	raw, err := r.LookupIPv4(lctx, name)
	if err != nil {
		return nil, 0
	}
	seen := map[netip.Addr]struct{}{}
	var keep []netip.Addr
	for _, s := range raw {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		if !routableIP(a, exclude) {
			dropped++
			continue
		}
		keep = append(keep, a)
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].Less(keep[j]) })
	if len(keep) > maxIPsPerHost {
		dropped += len(keep) - maxIPsPerHost
		keep = keep[:maxIPsPerHost]
	}
	for _, a := range keep {
		ips = append(ips, a.String())
	}
	return ips, dropped
}

// ipTask is one name to resolve and where to put the answer.
type ipTask struct {
	name    string
	ips     *[]string
	dropped *int
}

// resolveAll runs the tasks workers at a time within the shared budget; a
// name the budget did not reach simply has no addresses.
func resolveAll(ctx context.Context, r Resolver, exclude func(string) bool, workers int, tasks []ipTask) {
	if workers <= 0 {
		workers = DefaultWorkers
	}
	ctx, cancel := context.WithTimeout(ctx, ipResolveBudget)
	defer cancel()
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(t ipTask) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if ctx.Err() != nil {
				return
			}
			*t.ips, *t.dropped = resolveIPs(ctx, r, exclude, t.name)
		}(t)
	}
	wg.Wait()
}

// IPs returns the addresses to add alongside the given hosts: those of
// every scanned domain, plus those of the hosts named in hosts. Distinct,
// in address order.
func (r *Result) IPs(hosts map[string]bool) []string {
	seen := map[netip.Addr]struct{}{}
	var all []netip.Addr
	add := func(list []string) {
		for _, s := range list {
			if a, err := netip.ParseAddr(s); err == nil {
				if _, dup := seen[a]; !dup {
					seen[a] = struct{}{}
					all = append(all, a)
				}
			}
		}
	}
	for _, p := range r.Pages {
		add(p.SeedIPs)
	}
	for _, h := range r.Hosts {
		if hosts[h.Name] {
			add(h.IPs)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Less(all[j]) })
	out := make([]string, len(all))
	for i, a := range all {
		out[i] = a.String()
	}
	return out
}
