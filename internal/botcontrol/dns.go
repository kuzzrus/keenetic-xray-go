package botcontrol

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// The dns_* actions manage Keenetic's built-in dns-proxy secure upstreams
// (DoT / DoH) -- same logic as `keenetic-xray dns …`, re-exposed over the
// bot protocol. Mutations go through h.Config + keenetic.ApplyDNS; only
// upstreams whose IP/URL is in the dnsupstream catalogue (or config's own
// custom list) are ever removed.

func (h *RouterHandler) dnsShow(ctx context.Context) (string, error) {
	var b strings.Builder
	d := h.Config.DNS
	if !d.Configured() {
		b.WriteString("защищённый DNS: не настроен\n")
	} else {
		src := d.Provider
		if src == "" {
			src = "custom"
		}
		fmt.Fprintf(&b, "защищённый DNS: %s\n", src)
		for _, t := range d.DoT {
			fmt.Fprintf(&b, "  DoT  %s  (sni %s)\n", t.IP, t.SNI)
		}
		for _, hh := range d.DoH {
			fmt.Fprintf(&b, "  DoH  %s\n", hh.URL)
		}
	}
	if !keenetic.Available() {
		return strings.TrimRight(b.String(), "\n"), nil
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	live, err := keenetic.ShowDNS(cctx)
	if err != nil {
		fmt.Fprintf(&b, "на роутере: %v\n", err)
		return strings.TrimRight(b.String(), "\n"), nil
	}
	ours := dnsManaged(h.Config)
	b.WriteString("\nна роутере сейчас:\n")
	if len(live.TLS) == 0 && len(live.HTTPS) == 0 {
		b.WriteString("  (защищённых апстримов нет)\n")
	}
	for _, t := range live.TLS {
		fmt.Fprintf(&b, "  DoT  %s  sni %s%s\n", t.IP, t.SNI, dnsMark(ours.ip[t.IP]))
	}
	for _, hh := range live.HTTPS {
		fmt.Fprintf(&b, "  DoH  %s%s\n", hh.URL, dnsMark(ours.url[hh.URL]))
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func dnsMark(ours bool) string {
	if ours {
		return "  ← наш"
	}
	return ""
}

func (h *RouterHandler) dnsTest(ctx context.Context, args []string) (string, error) {
	all := len(args) > 0 && strings.EqualFold(args[0], "all")
	pool := dnsupstream.Providers()
	if all {
		pool = dnsupstream.TestPool()
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	res := dnsupstream.ProbeAll(cctx, pool)
	var b strings.Builder
	fmt.Fprintf(&b, "%-22s %-14s %s\n", "провайдер", "DoT", "DoH")
	for _, r := range res {
		tag := ""
		if all && !dnsupstream.InCatalogue(r.Provider.ID) {
			tag = " ·канд"
		}
		fmt.Fprintf(&b, "%-22s %-14s %s%s\n", r.Provider.ID, r.DoT.String(), r.DoH.String(), tag)
	}
	b.WriteString("\nвыбрать: кнопкой в 🧭 DNS (или /dns <r> preset <id>)")
	return b.String(), nil
}

func (h *RouterHandler) dnsPreset(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: dns_preset <id> [dot|doh|both]")
	}
	p, ok := dnsupstream.Find(args[0])
	if !ok {
		return "", fmt.Errorf("нет провайдера %q", args[0])
	}
	mode := "both"
	if len(args) > 1 {
		mode = strings.ToLower(args[1])
	}
	next := config.DNSConfig{Provider: p.ID}
	if mode == "dot" || mode == "both" {
		for _, t := range p.DoT {
			next.DoT = append(next.DoT, config.DNSHostTLS{IP: t.IP, SNI: t.SNI})
		}
	}
	if mode == "doh" || mode == "both" {
		for _, hh := range p.DoH {
			next.DoH = append(next.DoH, config.DNSHostHTTPS{URL: hh.URL})
		}
	}
	if !next.Configured() {
		return "", fmt.Errorf("у %q нет эндпоинтов для режима %s", p.ID, mode)
	}
	h.Config.DNS = next
	return h.dnsApply(ctx, fmt.Sprintf("DNS → %s (%s)", p.Name, mode))
}

func (h *RouterHandler) dnsSet(ctx context.Context, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("usage: dns_set <dot|doh> <список>")
	}
	fields := strings.FieldsFunc(args[1], func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ','
	})
	switch args[0] {
	case "dot":
		if len(fields)%2 != 0 || len(fields) == 0 {
			return "", fmt.Errorf("нужны пары «ip sni»")
		}
		h.Config.DNS.Provider = "custom"
		for i := 0; i < len(fields); i += 2 {
			h.Config.DNS.DoT = append(h.Config.DNS.DoT, config.DNSHostTLS{IP: fields[i], SNI: fields[i+1]})
		}
	case "doh":
		if len(fields) == 0 {
			return "", fmt.Errorf("нужен хотя бы один URL")
		}
		h.Config.DNS.Provider = "custom"
		for _, u := range fields {
			h.Config.DNS.DoH = append(h.Config.DNS.DoH, config.DNSHostHTTPS{URL: u})
		}
	default:
		return "", fmt.Errorf("dns_set <dot|doh> …")
	}
	return h.dnsApply(ctx, "DNS → свои апстримы")
}

func (h *RouterHandler) dnsOff(ctx context.Context) (string, error) {
	managed := dnsManaged(h.Config)
	h.Config.DNS = config.DNSConfig{}
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if !keenetic.Available() {
		return "DNS выключен в конфиге (применится при следующем запуске демона)", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rep, err := keenetic.ClearDNS(cctx, dnsKeys(managed.ip), dnsKeys(managed.url))
	if err != nil {
		return "в конфиге выключено, но на роутере убрать не вышло: " + err.Error(), nil
	}
	return fmt.Sprintf("DNS выключен. убрано с роутера: DoT %d, DoH %d", len(rep.TLSRemoved), len(rep.HTTPSRemoved)), nil
}

func (h *RouterHandler) dnsApply(ctx context.Context, okMsg string) (string, error) {
	if err := h.Config.Save(h.ConfigPath); err != nil {
		return "", err
	}
	if !keenetic.Available() {
		return okMsg + "\n(сохранено; на роутере применится при следующем запуске демона)", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyDNS(cctx, botDNSDesired(h.Config.DNS))
	if err != nil {
		return okMsg + fmt.Sprintf("\n⚠️ на роутере: %v", err), nil
	}
	return okMsg + fmt.Sprintf("\nроутер: DoT +%d/−%d, DoH +%d/−%d",
		len(rep.TLSAdded), len(rep.TLSRemoved), len(rep.HTTPSAdded), len(rep.HTTPSRemoved)), nil
}

func botDNSDesired(d config.DNSConfig) keenetic.DNSDesired {
	des := keenetic.DNSDesired{
		ManagedTLSIPs:    dnsupstream.AllTLSIPs(),
		ManagedHTTPSURLs: dnsupstream.AllDoHURLs(),
	}
	for _, t := range d.DoT {
		des.TLS = append(des.TLS, keenetic.DNSUpstreamTLS{IP: t.IP, SNI: t.SNI})
		des.ManagedTLSIPs = append(des.ManagedTLSIPs, t.IP)
	}
	for _, hh := range d.DoH {
		des.HTTPS = append(des.HTTPS, keenetic.DNSUpstreamHTTPS{URL: hh.URL})
		des.ManagedHTTPSURLs = append(des.ManagedHTTPSURLs, hh.URL)
	}
	return des
}

type dnsOwnedSet struct {
	ip  map[string]bool
	url map[string]bool
}

func dnsManaged(cfg *config.Config) dnsOwnedSet {
	o := dnsOwnedSet{ip: map[string]bool{}, url: map[string]bool{}}
	for _, ip := range dnsupstream.AllTLSIPs() {
		o.ip[ip] = true
	}
	for _, u := range dnsupstream.AllDoHURLs() {
		o.url[u] = true
	}
	for _, t := range cfg.DNS.DoT {
		o.ip[t.IP] = true
	}
	for _, hh := range cfg.DNS.DoH {
		o.url[hh.URL] = true
	}
	return o
}

func dnsKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
