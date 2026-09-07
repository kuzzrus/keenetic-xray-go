package keenetic

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// This file reconciles Keenetic's built-in dns-proxy secure upstreams --
// DNS-over-TLS (`dns-proxy tls upstream <ip> sni <host>`) and
// DNS-over-HTTPS (`dns-proxy https upstream <url> dnsm`). Both live as
// indented children of the column-0 `dns-proxy` block in
// `show running-config`. Removal syntax differs: DoT by IP
// (`no dns-proxy tls upstream <ip>`), DoH by URL
// (`no dns-proxy https upstream <url>`) -- confirmed on KeeneticOS 5.1.3.
//
// Scoping: this project has no marker on a DNS upstream, so ApplyDNS only
// ever removes an upstream whose IP (DoT) or URL (DoH) is in the caller's
// "managed" set (the dnsupstream catalogue + config's own custom
// entries). A hand-added upstream with any other IP/URL is never touched.

// minDNSOSMajor / minDNSOSMinor is the KeeneticOS floor for secure DNS
// upstreams via the CLI. DoT is much older; DoH landed around 3.1.
const (
	minDNSOSMajor = 3
	minDNSOSMinor = 1
)

// DNSUpstreamTLS / DNSUpstreamHTTPS are the concrete endpoints ApplyDNS
// works with (kept free of any internal/config import).
type DNSUpstreamTLS struct {
	IP  string
	SNI string
}

type DNSUpstreamHTTPS struct {
	URL string
}

// DNSDesired is one reconcile request: the upstreams that should be
// present, plus the managed sets that bound what ApplyDNS may remove.
type DNSDesired struct {
	TLS              []DNSUpstreamTLS
	HTTPS            []DNSUpstreamHTTPS
	ManagedTLSIPs    []string
	ManagedHTTPSURLs []string
}

// DNSReport summarizes what ApplyDNS changed.
type DNSReport struct {
	TLSAdded     []string
	TLSRemoved   []string
	HTTPSAdded   []string
	HTTPSRemoved []string
	Saved        bool
}

// Changed reports whether ApplyDNS issued any add/remove.
func (r DNSReport) Changed() bool {
	return len(r.TLSAdded)+len(r.TLSRemoved)+len(r.HTTPSAdded)+len(r.HTTPSRemoved) > 0
}

// LiveDNS is the router's current secure upstreams.
type LiveDNS struct {
	TLS   []DNSUpstreamTLS
	HTTPS []DNSUpstreamHTTPS
}

// ApplyDNS makes the router's dns-proxy carry exactly `want.TLS` /
// `want.HTTPS` among the managed upstreams, leaving every other upstream
// (and the whole dns-proxy block otherwise) untouched. `system
// configuration save` runs once if anything changed.
func ApplyDNS(ctx context.Context, want DNSDesired) (DNSReport, error) {
	var rep DNSReport
	if !Available() {
		return rep, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if ok, err := OSAtLeast(ctx, minDNSOSMajor, minDNSOSMinor); err != nil {
		return rep, fmt.Errorf("защищённый DNS требует KeeneticOS %d.%d+, версию определить не вышло: %w", minDNSOSMajor, minDNSOSMinor, err)
	} else if !ok {
		maj, min, _, _ := OSVersion(ctx)
		return rep, fmt.Errorf("KeeneticOS %d.%d — защищённый DNS (DoT/DoH) настраивается с %d.%d", maj, min, minDNSOSMajor, minDNSOSMinor)
	}

	live, err := readDNSUpstreams(ctx)
	if err != nil {
		return rep, err
	}

	haveTLS := map[string]DNSUpstreamTLS{}
	for _, t := range live.TLS {
		haveTLS[t.IP] = t
	}
	haveHTTPS := map[string]struct{}{}
	for _, h := range live.HTTPS {
		haveHTTPS[h.URL] = struct{}{}
	}
	wantTLS := map[string]DNSUpstreamTLS{}
	for _, t := range want.TLS {
		wantTLS[t.IP] = t
	}
	wantHTTPS := map[string]struct{}{}
	for _, h := range want.HTTPS {
		wantHTTPS[h.URL] = struct{}{}
	}
	managedIP := toSet(want.ManagedTLSIPs)
	managedURL := toSet(want.ManagedHTTPSURLs)

	var cmds []string

	for _, t := range want.TLS {
		cur, ok := haveTLS[t.IP]
		if ok && cur.SNI == t.SNI {
			continue // already present, same SNI
		}
		if ok { // present with a different SNI -> drop then re-add
			cmds = append(cmds, "no dns-proxy tls upstream "+t.IP)
		}
		cmds = append(cmds, fmt.Sprintf("dns-proxy tls upstream %s sni %s", t.IP, t.SNI))
		rep.TLSAdded = append(rep.TLSAdded, t.IP)
	}
	for ip := range haveTLS {
		if _, keep := wantTLS[ip]; keep {
			continue
		}
		if _, managed := managedIP[ip]; !managed {
			continue // someone else's upstream
		}
		cmds = append(cmds, "no dns-proxy tls upstream "+ip)
		rep.TLSRemoved = append(rep.TLSRemoved, ip)
	}

	for _, h := range want.HTTPS {
		if _, ok := haveHTTPS[h.URL]; !ok {
			cmds = append(cmds, fmt.Sprintf("dns-proxy https upstream %s dnsm", h.URL))
			rep.HTTPSAdded = append(rep.HTTPSAdded, h.URL)
		}
	}
	for url := range haveHTTPS {
		if _, keep := wantHTTPS[url]; keep {
			continue
		}
		if _, managed := managedURL[url]; !managed {
			continue
		}
		cmds = append(cmds, "no dns-proxy https upstream "+url)
		rep.HTTPSRemoved = append(rep.HTTPSRemoved, url)
	}

	if len(cmds) == 0 {
		return rep, nil
	}
	cmds = append(cmds, "system configuration save")

	sort.Strings(rep.TLSAdded)
	sort.Strings(rep.TLSRemoved)
	sort.Strings(rep.HTTPSAdded)
	sort.Strings(rep.HTTPSRemoved)

	var failed []string
	for _, c := range cmds {
		if _, err := ndmcRun(ctx, c); err != nil {
			failed = append(failed, fmt.Sprintf("%q: %v", c, err))
		}
	}
	rep.Saved = true
	if len(failed) > 0 {
		return rep, fmt.Errorf("часть команд не выполнилась:\n%s", strings.Join(failed, "\n"))
	}
	return rep, nil
}

// SetLocalNameServer adds or removes an `ip name-server <ip>:<port>`
// entry (KeeneticOS accepts the colon form for a non-standard port; the
// bare positional form treats the second field as a domain). Used to
// point the router's dns-proxy at a locally-installed resolver
// (internal/addons: unbound) WITHOUT `opkg dns-override` -- dns-proxy
// stays in the path, so its DNS-name → route snooping keeps working.
// `system configuration save` runs after. Keenetic rejects a loopback
// address here, so the caller passes the LAN IP.
func SetLocalNameServer(ctx context.Context, ip string, port int, on bool) error {
	if !Available() {
		return fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	spec := fmt.Sprintf("ip name-server %s:%d", ip, port)
	if !on {
		spec = "no " + spec
	}
	for _, c := range []string{spec, "system configuration save"} {
		if _, err := ndmcRun(ctx, c); err != nil {
			return fmt.Errorf("%q: %w", c, err)
		}
	}
	return nil
}

// LocalNameServerActive reports whether `ip name-server <ip>:<port>` is
// in the running config.
func LocalNameServerActive(ctx context.Context, ip string, port int) (bool, error) {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return false, fmt.Errorf("show running-config: %w", err)
	}
	want := fmt.Sprintf("ip name-server %s:%d", ip, port)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		// "ip name-server <ip>:<port> [domain] [on <iface>]"
		if len(f) >= 3 && f[0] == "ip" && f[1] == "name-server" && f[2] == fmt.Sprintf("%s:%d", ip, port) {
			return true, nil
		}
		if strings.TrimSpace(line) == want {
			return true, nil
		}
	}
	return false, nil
}

// ShowDNS returns the router's current secure upstreams, sorted.
func ShowDNS(ctx context.Context) (LiveDNS, error) {
	if !Available() {
		return LiveDNS{}, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	live, err := readDNSUpstreams(ctx)
	if err != nil {
		return LiveDNS{}, err
	}
	sort.Slice(live.TLS, func(i, j int) bool { return live.TLS[i].IP < live.TLS[j].IP })
	sort.Slice(live.HTTPS, func(i, j int) bool { return live.HTTPS[i].URL < live.HTTPS[j].URL })
	return live, nil
}

// ClearDNS removes every managed secure upstream and saves. A no-op if
// none are ours.
func ClearDNS(ctx context.Context, managedTLSIPs, managedHTTPSURLs []string) (DNSReport, error) {
	return ApplyDNS(ctx, DNSDesired{
		ManagedTLSIPs:    managedTLSIPs,
		ManagedHTTPSURLs: managedHTTPSURLs,
	})
}

// readDNSUpstreams parses `show running-config` for the tls/https upstream
// children of the column-0 `dns-proxy` block.
func readDNSUpstreams(ctx context.Context) (LiveDNS, error) {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return LiveDNS{}, fmt.Errorf("show running-config: %w", err)
	}
	var live LiveDNS
	inBlock := false
	for _, line := range strings.Split(out, "\n") {
		body := strings.TrimLeft(line, " \t")
		if body == "" {
			continue
		}
		if body == line { // column-0: block boundary
			inBlock = strings.Fields(body)[0] == "dns-proxy" && len(strings.Fields(body)) == 1
			continue
		}
		if !inBlock {
			continue
		}
		f := strings.Fields(body)
		switch {
		case len(f) >= 5 && f[0] == "tls" && f[1] == "upstream" && f[3] == "sni":
			live.TLS = append(live.TLS, DNSUpstreamTLS{IP: f[2], SNI: f[4]})
		case len(f) >= 3 && f[0] == "https" && f[1] == "upstream":
			live.HTTPS = append(live.HTTPS, DNSUpstreamHTTPS{URL: f[2]})
		}
	}
	return live, nil
}

func toSet(xs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[x] = struct{}{}
	}
	return m
}
