package botcontrol

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestBotDnsDesired_IncludesExtraManaged mirrors
// cmd/keenetic-xray's TestDnsDesired_IncludesExtraManaged -- see its own
// doc comment. Both packages carry an independent, near-identical copy
// of this logic (can't share unexported code across package boundaries),
// so both need the same coverage.
func TestBotDnsDesired_IncludesExtraManaged(t *testing.T) {
	d := config.DNSConfig{DoT: []config.DNSHostTLS{{IP: "1.2.3.4", SNI: "example.com"}}}
	extra := dnsOwnedSet{
		ip:  map[string]bool{"9.9.9.9": true},
		url: map[string]bool{"https://old.example/dns-query": true},
	}
	got := botDNSDesired(d, extra)

	if !slices.Contains(got.ManagedTLSIPs, "9.9.9.9") {
		t.Errorf("ManagedTLSIPs = %v, want it to include the old custom IP from extraManaged", got.ManagedTLSIPs)
	}
	if !slices.Contains(got.ManagedHTTPSURLs, "https://old.example/dns-query") {
		t.Errorf("ManagedHTTPSURLs = %v, want it to include the old custom URL from extraManaged", got.ManagedHTTPSURLs)
	}
	if !slices.Contains(got.ManagedTLSIPs, "1.2.3.4") {
		t.Errorf("ManagedTLSIPs = %v, want the new desired IP too", got.ManagedTLSIPs)
	}
	for _, tls := range got.TLS {
		if tls.IP == "9.9.9.9" {
			t.Errorf("TLS = %v, the old custom IP must not be in the desired-add set", got.TLS)
		}
	}
}

func TestBotDnsDesired_ZeroExtraManagedIsSafe(t *testing.T) {
	d := config.DNSConfig{DoT: []config.DNSHostTLS{{IP: "1.2.3.4", SNI: "example.com"}}}
	got := botDNSDesired(d, dnsOwnedSet{})
	if !slices.Contains(got.ManagedTLSIPs, "1.2.3.4") {
		t.Errorf("ManagedTLSIPs = %v, want the desired IP even with a zero-value extraManaged", got.ManagedTLSIPs)
	}
}

func TestDnsManaged_IncludesCatalogueAndCustom(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.DoT = []config.DNSHostTLS{{IP: "9.9.9.9", SNI: "custom.example"}}
	got := dnsManaged(cfg)
	if !got.ip["9.9.9.9"] {
		t.Error("dnsManaged should include the config's own custom DoT IP")
	}
	if len(got.ip) < 2 {
		t.Errorf("dnsManaged.ip = %v, want the catalogue's IPs plus the custom one", got.ip)
	}
}

// TestRouterHandler_DNSOff_NoRouterSavesEmptyConfig mirrors
// cmd/keenetic-xray's TestDnsOff_NoRouterSavesEmptyConfig -- see its own
// doc comment for why this is the branch actually reachable here.
func TestRouterHandler_DNSOff_NoRouterSavesEmptyConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	cfg := config.Default()
	cfg.DNS.DoT = []config.DNSHostTLS{{IP: "9.9.9.9", SNI: "dns.example.com"}}
	h := &RouterHandler{Config: cfg, ConfigPath: cfgPath}

	out, err := h.dnsOff(context.Background())
	if err != nil {
		t.Fatalf("dnsOff = %v, want nil (no router -> just save)", err)
	}
	if out == "" {
		t.Error("expected a confirmation message")
	}
	if h.Config.DNS.Configured() {
		t.Error("h.Config.DNS should be cleared")
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DNS.Configured() {
		t.Error("saved config should have DNS cleared too")
	}
}

// TestRouterHandler_DNSPresetMulti: the whole ranking goes in at once,
// each provider with its own protocols, shared endpoints once.
func TestRouterHandler_DNSPresetMulti(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	h := &RouterHandler{Config: config.Default(), ConfigPath: path}
	out, err := h.Handle(context.Background(), Command{Action: ActionDNSPresetMulti, Args: []string{
		"controld-p1:doh", "dns4eu:both", "controld-p1:doh",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ControlD Malware, DNS4EU") {
		t.Errorf("reply = %q", out)
	}
	saved, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := saved.DNS
	if d.Provider != "controld-p1+dns4eu" || len(d.DoT) != 2 || len(d.DoH) != 2 {
		t.Errorf("saved DNS = %+v, want both providers: 2 DoT (DNS4EU), 2 DoH (one each)", d)
	}

	for _, bad := range [][]string{nil, {"nope:both"}, {"cloudflare:udp"}} {
		if _, err := h.Handle(context.Background(), Command{Action: ActionDNSPresetMulti, Args: bad}); err == nil {
			t.Errorf("args %v accepted", bad)
		}
	}
}
