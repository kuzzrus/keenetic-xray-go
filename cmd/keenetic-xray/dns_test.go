package main

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestDnsDesired_IncludesExtraManaged is DNS-01's regression test for
// dnsPreset's own bug: a custom (non-catalogue) endpoint being replaced
// by a preset falls out of cfg.DNS the moment the caller overwrites it,
// so dnsDesired's extraManaged parameter is the only way ApplyDNS ever
// learns it needs removing. Confirms the old custom entries land in the
// *managed* (eligible for removal) set, but not in the *desired* (add)
// set.
func TestDnsDesired_IncludesExtraManaged(t *testing.T) {
	d := config.DNSConfig{DoT: []config.DNSHostTLS{{IP: "1.2.3.4", SNI: "example.com"}}}
	extra := dnsOwned{
		tlsIP:  map[string]bool{"9.9.9.9": true},
		dohURL: map[string]bool{"https://old.example/dns-query": true},
	}
	got := dnsDesired(d, extra)

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

func TestDnsDesired_ZeroExtraManagedIsSafe(t *testing.T) {
	d := config.DNSConfig{DoT: []config.DNSHostTLS{{IP: "1.2.3.4", SNI: "example.com"}}}
	got := dnsDesired(d, dnsOwned{}) // nil maps, same as every caller with nothing to protect
	if !slices.Contains(got.ManagedTLSIPs, "1.2.3.4") {
		t.Errorf("ManagedTLSIPs = %v, want the desired IP even with a zero-value extraManaged", got.ManagedTLSIPs)
	}
}

func TestManagedSet_IncludesCatalogueAndCustom(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.DoT = []config.DNSHostTLS{{IP: "9.9.9.9", SNI: "custom.example"}}
	got := managedSet(cfg)
	if !got.tlsIP["9.9.9.9"] {
		t.Error("managedSet should include the config's own custom DoT IP")
	}
	if len(got.tlsIP) < 2 {
		t.Errorf("managedSet.tlsIP = %v, want the catalogue's IPs plus the custom one", got.tlsIP)
	}
}

// TestDnsOff_NoRouterSavesEmptyConfig confirms the no-router branch
// (keenetic.Available() == false, the only branch this dev/CI
// environment can reach) still saves the cleared config directly, same
// as before DNS-01's reordering -- that fix only changed the
// router-available branch (clear before save), which needs real hardware
// to verify end-to-end.
func TestDnsOff_NoRouterSavesEmptyConfig(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)

	cfg := config.Default()
	cfg.DNS.DoT = []config.DNSHostTLS{{IP: "9.9.9.9", SNI: "dns.example.com"}}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	if err := dnsOff(cfg); err != nil {
		t.Fatalf("dnsOff = %v, want nil (no router -> just save)", err)
	}
	if cfg.DNS.Configured() {
		t.Error("cfg.DNS should be cleared")
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DNS.Configured() {
		t.Error("saved config should have DNS cleared too")
	}
}
