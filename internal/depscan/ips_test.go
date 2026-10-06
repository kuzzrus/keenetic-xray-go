package depscan

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRoutableIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"95.47.173.35":    true,
		"8.8.4.4":         true,
		"149.154.167.51":  true,
		"0.0.0.0":         false, // what a DNS filter answers for a blocked name
		"0.1.2.3":         false,
		"10.1.2.3":        false,
		"100.64.0.1":      false, // shared / CGNAT
		"127.0.0.1":       false,
		"169.254.1.1":     false,
		"172.16.0.1":      false,
		"172.31.255.1":    false,
		"172.32.0.1":      true,
		"192.168.1.1":     false,
		"192.0.2.1":       false, // documentation
		"198.51.100.1":    false,
		"203.0.113.9":     false,
		"198.18.0.1":      false, // benchmarking
		"224.0.0.1":       false, // multicast
		"255.255.255.255": false,
		"104.16.1.1":      false, // Cloudflare
		"172.67.1.1":      false,
		"188.114.97.9":    false,
		"103.21.244.0":    false,
		"103.21.248.1":    true, // next to a Cloudflare block, not in it
		"2001:db8::1":     false,
	} {
		a := netip.MustParseAddr(ip)
		if got := routableIP(a, nil); got != want {
			t.Errorf("routableIP(%s) = %v, want %v", ip, got, want)
		}
	}
	ru := func(ip string) bool { return strings.HasPrefix(ip, "5.255.") }
	if routableIP(netip.MustParseAddr("5.255.255.77"), ru) || !routableIP(netip.MustParseAddr("8.8.4.4"), ru) {
		t.Error("the exclusion callback is not applied")
	}
}

func TestResolveIPs_FiltersSortsAndCaps(t *testing.T) {
	r := &fakeResolver{addrs: map[string][]string{"calls.example-a.net": {
		"95.47.173.36", "95.47.173.35", "95.47.173.35", // a duplicate
		"10.0.0.7", "0.0.0.0", // private, sinkhole
		"104.16.5.5",     // Cloudflare
		"5.255.255.77",   // Russian (by the callback)
		"not an address", // junk is ignored, not counted
	}}}
	ru := func(ip string) bool { return strings.HasPrefix(ip, "5.255.") }
	ips, dropped := resolveIPs(context.Background(), r, ru, "calls.example-a.net")
	if !slices.Equal(ips, []string{"95.47.173.35", "95.47.173.36"}) || dropped != 4 {
		t.Errorf("ips=%v dropped=%d, want the two good ones sorted and 4 dropped", ips, dropped)
	}

	// More than the cap: the first maxIPsPerHost in address order, the rest counted.
	var many []string
	for i := 20; i > 0; i-- {
		many = append(many, fmt.Sprintf("93.184.216.%d", i))
	}
	r = &fakeResolver{addrs: map[string][]string{"big.example-a.net": many}}
	ips, dropped = resolveIPs(context.Background(), r, nil, "big.example-a.net")
	if len(ips) != maxIPsPerHost || ips[0] != "93.184.216.1" || dropped != 20-maxIPsPerHost {
		t.Errorf("ips=%v dropped=%d", ips, dropped)
	}

	// A name that does not resolve is no addresses, not a failure.
	if ips, dropped := resolveIPs(context.Background(), &fakeResolver{}, nil, "nx.example-a.net"); ips != nil || dropped != 0 {
		t.Errorf("unresolved: %v %d", ips, dropped)
	}
}

func TestScan_AddressesForTheSeedAndTheHostsThatNeedTheTunnel(t *testing.T) {
	html := `<img src="https://need.example-a.net/a.png"><img src="https://open.example-b.net/a.png">` +
		`<img src="https://gone.example-c.net/a.png"><img src="https://listed.example-d.net/a.png">`
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": {
		status: 200, body: html,
		header: http.Header{"Content-Security-Policy": {"img-src https://maybe.example-f.net"}},
	}}}
	pr := &fakeProber{
		direct: map[string]Reach{"open.example-b.net": ok(200), "example.com": fail("сброс")},
		tunnel: map[string]Reach{"need.example-a.net": ok(200), "maybe.example-f.net": ok(200)},
	}
	rs := &fakeResolver{addrs: map[string][]string{
		"example.com":          {"93.184.216.34"},
		"need.example-a.net":   {"95.47.173.35", "10.0.0.1"},
		"maybe.example-f.net":  {"198.51.100.4", "151.101.1.1"},
		"open.example-b.net":   {"1.1.1.1"},
		"gone.example-c.net":   {"2.2.2.2"},
		"listed.example-d.net": {"3.3.3.3"},
	}}
	opts := scanOpts(tun, pr)
	opts.Resolver = rs
	opts.Covered = func(h string) string {
		if h == "listed.example-d.net" {
			return "mine"
		}
		return ""
	}
	res, err := Scan(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Pages[0]; !slices.Equal(p.SeedIPs, []string{"93.184.216.34"}) || p.SeedIPsDropped != 0 {
		t.Errorf("seed IPs = %v (%d dropped)", p.SeedIPs, p.SeedIPsDropped)
	}
	need := hostByName(res, "need.example-a.net")
	if need.Class != ClassNeed || !slices.Equal(need.IPs, []string{"95.47.173.35"}) || need.IPsDropped != 1 {
		t.Errorf("need = %+v", need)
	}
	if mb := hostByName(res, "maybe.example-f.net"); mb.Class != ClassMaybe || !slices.Equal(mb.IPs, []string{"151.101.1.1"}) || mb.IPsDropped != 1 {
		t.Errorf("maybe = %+v", mb)
	}
	// Only the hosts an operator might add are looked up: never one that
	// opens directly, is dead, or is already in a list.
	for _, h := range []string{"open.example-b.net", "gone.example-c.net", "listed.example-d.net"} {
		if rs.lookedUp(h) {
			t.Errorf("%s was resolved though it needs no entry", h)
		}
	}
	if got := res.IPs(map[string]bool{"need.example-a.net": true}); !slices.Equal(got, []string{"93.184.216.34", "95.47.173.35"}) {
		t.Errorf("IPs(need) = %v: the domain's own plus the ticked host's", got)
	}
	if got := res.IPs(nil); !slices.Equal(got, []string{"93.184.216.34"}) {
		t.Errorf("IPs(nil) = %v: with nothing ticked, just the domain's", got)
	}
}

func TestScan_PageUnreadableButTheNameResolves(t *testing.T) {
	// An app's host: no web page at all, but the address is what is wanted.
	tun := &fakeTunnel{sites: map[string]site{}}
	opts := scanOpts(tun, &fakeProber{direct: map[string]Reach{"voip.example.com": fail("сброс")}})
	opts.Resolver = &fakeResolver{addrs: map[string][]string{"voip.example.com": {"149.154.167.51", "149.154.167.91"}}}
	res, err := Scan(context.Background(), "voip.example.com", opts)
	if err != nil {
		t.Fatalf("a name that resolves must not be an error: %v", err)
	}
	p := res.Pages[0]
	if p.Status != 0 || !strings.Contains(p.Note, "IP-адреса домена найдены") || !slices.Equal(p.SeedIPs, []string{"149.154.167.51", "149.154.167.91"}) {
		t.Errorf("page = %+v", p)
	}
	if len(res.Hosts) != 0 || p.Direct.OK {
		t.Errorf("hosts=%v direct=%+v", res.Hosts, p.Direct)
	}

	// Neither a page nor an address: that is an error, as before.
	opts.Resolver = &fakeResolver{}
	if _, err := Scan(context.Background(), "typo.example.com", opts); err == nil || !strings.Contains(err.Error(), "не открылась") {
		t.Errorf("err = %v", err)
	}
}

func TestScan_ASlowResolverDoesNotHoldTheScanUp(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(`<img src="https://need.example-a.net/a.png">`)}}
	pr := &fakeProber{tunnel: map[string]Reach{"need.example-a.net": ok(200)}}
	opts := scanOpts(tun, pr)
	opts.Resolver = &fakeResolver{block: true}
	opts.Budget = 400 * time.Millisecond
	start := time.Now()
	res, err := Scan(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v with a 400ms budget", d)
	}
	if h := hostByName(res, "need.example-a.net"); h == nil || len(h.IPs) != 0 {
		t.Errorf("host = %+v: an unanswered lookup leaves the host without addresses", h)
	}
}

func TestTSV_CarriesAddresses(t *testing.T) {
	in := &Result{
		Pages: []Page{{Seed: "example.com", Status: 200, SeedIPs: []string{"1.2.3.4", "1.2.3.5"}, SeedIPsDropped: 2}},
		Hosts: []Host{{Name: "need.example-a.net", Class: ClassNeed, IPs: []string{"5.6.7.8"}, IPsDropped: 1, Direct: fail("сброс"), Tunnel: ok(200)}},
	}
	out, err := ParseTSV(in.TSV())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(out.Pages[0].SeedIPs, in.Pages[0].SeedIPs) || out.Pages[0].SeedIPsDropped != 2 ||
		!slices.Equal(out.Hosts[0].IPs, []string{"5.6.7.8"}) || out.Hosts[0].IPsDropped != 1 {
		t.Errorf("out = %+v", out)
	}
	// An answer from an agent that predates addresses still parses.
	old := "#page\texample.com\texample.com\t200\tok:200\t\n" +
		"need.example-a.net\tneed\tA\t-\thtml\t-\terr:таймаут\tok:200\n"
	r, err := ParseTSV(old)
	if err != nil || len(r.Hosts) != 1 || len(r.Hosts[0].IPs) != 0 || len(r.Pages[0].SeedIPs) != 0 {
		t.Errorf("old format: %v %+v", err, r)
	}
}

func TestText_ShowsAddresses(t *testing.T) {
	r := &Result{
		Pages: []Page{{Seed: "example.com", Status: 200, SeedIPs: []string{"1.2.3.4"}, SeedIPsDropped: 3}},
		Hosts: []Host{{Name: "need.example-a.net", Class: ClassNeed, Via: []string{ViaHTML}, IPs: []string{"5.6.7.8", "5.6.7.9"}}},
	}
	txt := r.Text()
	for _, want := range []string{"IP-адреса домена: 1.2.3.4 (ещё 3 отброшено", "need.example-a.net", "IP: 5.6.7.8, 5.6.7.9"} {
		if !strings.Contains(txt, want) {
			t.Errorf("Text() lacks %q:\n%s", want, txt)
		}
	}
}
