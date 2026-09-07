package main

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// cmdDNS manages Keenetic's built-in dns-proxy secure upstreams (DoT /
// DoH). Picking a provider or entering custom endpoints writes
// config.DNS and reconciles the router; the daemon re-asserts it on the
// reconcile loop. `dns test` benchmarks the whole catalogue from the
// router so an operator can pick by measured latency.
func cmdDNS(args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		return dnsShow(cfg)
	case "test":
		return dnsTest()
	case "list":
		return dnsList()
	case "preset":
		return dnsPreset(cfg, args[1:])
	case "set":
		return dnsSet(cfg, args[1:])
	case "off", "clear":
		return dnsOff(cfg)
	default:
		return dnsUsage()
	}
}

func dnsUsage() error {
	return fmt.Errorf("usage: keenetic-xray dns {show | test | list | " +
		"preset <id> [--dot|--doh|--both] | set dot <ip> <sni> [<ip> <sni> …] | set doh <url> [<url> …] | off}")
}

func dnsList() error {
	for _, p := range dnsupstream.Providers() {
		note := ""
		if p.Note != "" {
			note = "  — " + p.Note
		}
		fmt.Printf("%-22s %s%s\n", p.ID, p.Name, note)
	}
	return nil
}

func dnsShow(cfg *config.Config) error {
	d := cfg.DNS
	if !d.Configured() {
		fmt.Println("защищённый DNS: не настроен (роутерный dns-proxy не трогаем)")
	} else {
		src := d.Provider
		if src == "" {
			src = "custom"
		}
		fmt.Printf("защищённый DNS: %s\n", src)
		for _, t := range d.DoT {
			fmt.Printf("  DoT  %s  (sni %s)\n", t.IP, t.SNI)
		}
		for _, h := range d.DoH {
			fmt.Printf("  DoH  %s\n", h.URL)
		}
	}
	if !keenetic.Available() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	live, err := keenetic.ShowDNS(ctx)
	if err != nil {
		fmt.Println("на роутере: " + err.Error())
		return nil
	}
	ours := managedSet(cfg)
	fmt.Println("на роутере сейчас:")
	if len(live.TLS) == 0 && len(live.HTTPS) == 0 {
		fmt.Println("  (защищённых апстримов нет)")
	}
	for _, t := range live.TLS {
		fmt.Printf("  DoT  %-16s sni %s%s\n", t.IP, t.SNI, mark(ours.tlsIP[t.IP]))
	}
	for _, h := range live.HTTPS {
		fmt.Printf("  DoH  %s%s\n", h.URL, mark(ours.dohURL[h.URL]))
	}
	return nil
}

func mark(ours bool) string {
	if ours {
		return "  ← наш"
	}
	return ""
}

func dnsTest() error {
	fmt.Println("проверяю провайдеров с роутера (DoT :853 / DoH :443, таймаут 3с)…")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res := dnsupstream.ProbeAll(ctx, dnsupstream.Providers())
	fmt.Printf("\n%-22s %-16s %s\n", "провайдер", "DoT", "DoH")
	for _, r := range res {
		fmt.Printf("%-22s %-16s %s\n", r.Provider.ID, r.DoT.String(), r.DoH.String())
	}
	fmt.Println("\nвыбрать:  keenetic-xray dns preset <id>")
	return nil
}

func dnsPreset(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keenetic-xray dns preset <id> [--dot|--doh|--both]")
	}
	p, ok := dnsupstream.Find(args[0])
	if !ok {
		return fmt.Errorf("нет провайдера %q (см. keenetic-xray dns list)", args[0])
	}
	mode := "both"
	for _, a := range args[1:] {
		switch a {
		case "--dot":
			mode = "dot"
		case "--doh":
			mode = "doh"
		case "--both":
			mode = "both"
		default:
			return fmt.Errorf("неизвестный флаг %q", a)
		}
	}

	cfg.DNS = config.DNSConfig{Provider: p.ID}
	if mode == "dot" || mode == "both" {
		for _, t := range p.DoT {
			cfg.DNS.DoT = append(cfg.DNS.DoT, config.DNSHostTLS{IP: t.IP, SNI: t.SNI})
		}
	}
	if mode == "doh" || mode == "both" {
		for _, h := range p.DoH {
			cfg.DNS.DoH = append(cfg.DNS.DoH, config.DNSHostHTTPS{URL: h.URL})
		}
	}
	if !cfg.DNS.Configured() {
		return fmt.Errorf("у провайдера %q нет эндпоинтов для режима %s", p.ID, mode)
	}
	return dnsApply(cfg, fmt.Sprintf("DNS: %s (%s)", p.Name, mode))
}

func dnsSet(cfg *config.Config, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: keenetic-xray dns set {dot <ip> <sni> [<ip> <sni> …] | doh <url> [<url> …]}")
	}
	kind, rest := args[0], args[1:]
	switch kind {
	case "dot":
		if len(rest)%2 != 0 {
			return fmt.Errorf("dot принимает пары <ip> <sni>")
		}
		cfg.DNS.Provider = "custom"
		for i := 0; i < len(rest); i += 2 {
			cfg.DNS.DoT = append(cfg.DNS.DoT, config.DNSHostTLS{IP: rest[i], SNI: rest[i+1]})
		}
	case "doh":
		cfg.DNS.Provider = "custom"
		for _, u := range rest {
			cfg.DNS.DoH = append(cfg.DNS.DoH, config.DNSHostHTTPS{URL: u})
		}
	default:
		return fmt.Errorf("dns set {dot|doh} …")
	}
	return dnsApply(cfg, "DNS: свои апстримы")
}

func dnsOff(cfg *config.Config) error {
	managed := managedSet(cfg)
	cfg.DNS = config.DNSConfig{}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	if !keenetic.Available() {
		fmt.Println("DNS выключен в конфиге (на роутере применится при следующем запуске демона)")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := keenetic.ClearDNS(ctx, keys(managed.tlsIP), keys(managed.dohURL))
	if err != nil {
		return fmt.Errorf("в конфиге выключено, но на роутере убрать не вышло: %w", err)
	}
	fmt.Printf("DNS выключен. убрано с роутера: DoT %d, DoH %d\n", len(rep.TLSRemoved), len(rep.HTTPSRemoved))
	return nil
}

// dnsApply saves cfg (Validate runs in Save) and reconciles the router.
func dnsApply(cfg *config.Config, okMsg string) error {
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	if !keenetic.Available() {
		fmt.Println(okMsg + " (сохранено; на роутере применится при следующем запуске демона)")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyDNS(ctx, dnsDesired(cfg.DNS))
	if err != nil {
		return fmt.Errorf("%s, но применить на роутере не вышло: %w", okMsg, err)
	}
	fmt.Printf("%s. роутер: DoT +%d/−%d, DoH +%d/−%d\n", okMsg,
		len(rep.TLSAdded), len(rep.TLSRemoved), len(rep.HTTPSAdded), len(rep.HTTPSRemoved))
	return nil
}

// dnsDesired turns config.DNS into a keenetic reconcile request. The
// managed set is the whole catalogue plus whatever custom endpoints the
// config itself names -- so ApplyDNS can retire an endpoint we set last
// time, but never one a person added by hand elsewhere.
func dnsDesired(d config.DNSConfig) keenetic.DNSDesired {
	des := keenetic.DNSDesired{
		ManagedTLSIPs:    dnsupstream.AllTLSIPs(),
		ManagedHTTPSURLs: dnsupstream.AllDoHURLs(),
	}
	for _, t := range d.DoT {
		des.TLS = append(des.TLS, keenetic.DNSUpstreamTLS{IP: t.IP, SNI: t.SNI})
		des.ManagedTLSIPs = append(des.ManagedTLSIPs, t.IP)
	}
	for _, h := range d.DoH {
		des.HTTPS = append(des.HTTPS, keenetic.DNSUpstreamHTTPS{URL: h.URL})
		des.ManagedHTTPSURLs = append(des.ManagedHTTPSURLs, h.URL)
	}
	return des
}

type dnsOwned struct {
	tlsIP  map[string]bool
	dohURL map[string]bool
}

func managedSet(cfg *config.Config) dnsOwned {
	o := dnsOwned{tlsIP: map[string]bool{}, dohURL: map[string]bool{}}
	for _, ip := range dnsupstream.AllTLSIPs() {
		o.tlsIP[ip] = true
	}
	for _, u := range dnsupstream.AllDoHURLs() {
		o.dohURL[u] = true
	}
	for _, t := range cfg.DNS.DoT {
		o.tlsIP[t.IP] = true
	}
	for _, h := range cfg.DNS.DoH {
		o.dohURL[h.URL] = true
	}
	return o
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// applyDNSAtStartup reconciles the configured secure DNS upstreams when
// the daemon starts -- best-effort, non-fatal, same as the Proxy0 / MSS /
// routes startup hooks. Skipped when config.DNS is empty.
func applyDNSAtStartup(cfg *config.Config, logf func(string, ...any)) {
	if !cfg.DNS.Configured() || !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rep, err := keenetic.ApplyDNS(ctx, dnsDesired(cfg.DNS))
	if err != nil {
		logf("dns: apply failed: %v", err)
		return
	}
	if rep.Saved {
		logf("dns: reconciled (DoT +%d/-%d, DoH +%d/-%d)",
			len(rep.TLSAdded), len(rep.TLSRemoved), len(rep.HTTPSAdded), len(rep.HTTPSRemoved))
	}
}

// reconcileDNS re-asserts config.DNS if ndm dropped an upstream. Cheap
// (one `show running-config` + a diff), folded into reconcileOnce.
func reconcileDNS(ctx context.Context, cfg *config.Config, logf func(string, ...any)) {
	if !cfg.DNS.Configured() {
		return
	}
	rep, err := keenetic.ApplyDNS(ctx, dnsDesired(cfg.DNS))
	if err != nil {
		logf("dns: reconcile failed: %v", err)
		return
	}
	if rep.Changed() {
		logf("dns: re-asserted (DoT +%d/-%d, DoH +%d/-%d)",
			len(rep.TLSAdded), len(rep.TLSRemoved), len(rep.HTTPSAdded), len(rep.HTTPSRemoved))
	}
}
