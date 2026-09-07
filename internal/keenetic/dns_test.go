package keenetic

import (
	"context"
	"strings"
	"testing"
)

const dnsRunningConfig = `!
service dns-proxy
!
dns-proxy
    rebind-protect auto
    route object-group domain-list0 Proxy0 auto
    route object-group keenetic-xray-yt Wireguard4 auto
    tls upstream 9.9.9.9 sni dns.quad9.net
    https upstream https://adg.iiadmin.info/dns-query/router dnsm
    https upstream https://dns.google/dns-query dnsm
!
mdns
    reflector enforce
!
`

func dnsFake(t *testing.T) *[]string {
	return fakeNdmc(t, map[string]string{
		"show version":        "            title: 5.1.3\n",
		"show running-config": dnsRunningConfig,
	})
}

func TestReadDNSUpstreams(t *testing.T) {
	dnsFake(t)
	live, err := ShowDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(live.TLS) != 1 || live.TLS[0].IP != "9.9.9.9" || live.TLS[0].SNI != "dns.quad9.net" {
		t.Errorf("TLS = %+v", live.TLS)
	}
	if len(live.HTTPS) != 2 {
		t.Fatalf("HTTPS = %+v", live.HTTPS)
	}
	// sorted: adg... before dns.google
	if live.HTTPS[0].URL != "https://adg.iiadmin.info/dns-query/router" || live.HTTPS[1].URL != "https://dns.google/dns-query" {
		t.Errorf("HTTPS = %+v", live.HTTPS)
	}
}

func TestApplyDNS_AddsAndRemovesOnlyManaged(t *testing.T) {
	sent := dnsFake(t)

	// Want: keep Google DoH, add Cloudflare DoT, drop the Quad9 DoT
	// (it's managed). The user's adg.iiadmin.info DoH is NOT in the
	// managed set -> must survive.
	rep, err := ApplyDNS(context.Background(), DNSDesired{
		TLS:              []DNSUpstreamTLS{{IP: "1.1.1.1", SNI: "one.one.one.one"}},
		HTTPS:            []DNSUpstreamHTTPS{{URL: "https://dns.google/dns-query"}},
		ManagedTLSIPs:    []string{"9.9.9.9", "1.1.1.1"},
		ManagedHTTPSURLs: []string{"https://dns.google/dns-query", "https://dns.quad9.net/dns-query"},
	})
	if err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(*sent, "\n")
	want := []string{
		"dns-proxy tls upstream 1.1.1.1 sni one.one.one.one",
		"no dns-proxy tls upstream 9.9.9.9",
		"system configuration save",
	}
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("expected command %q in:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "iiadmin") {
		t.Errorf("touched the user's own DoH upstream:\n%s", joined)
	}
	if strings.Contains(joined, "dns-proxy https upstream https://dns.google/dns-query dnsm") {
		t.Errorf("re-added a DoH upstream that was already present:\n%s", joined)
	}
	if len(rep.TLSAdded) != 1 || len(rep.TLSRemoved) != 1 || rep.HTTPSAdded != nil {
		t.Errorf("report = %+v", rep)
	}
}

func TestApplyDNS_NoChangeNoSave(t *testing.T) {
	sent := dnsFake(t)
	rep, err := ApplyDNS(context.Background(), DNSDesired{
		TLS:              []DNSUpstreamTLS{{IP: "9.9.9.9", SNI: "dns.quad9.net"}},
		HTTPS:            []DNSUpstreamHTTPS{{URL: "https://dns.google/dns-query"}},
		ManagedTLSIPs:    []string{"9.9.9.9"},
		ManagedHTTPSURLs: []string{"https://dns.google/dns-query"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range *sent {
		if c == "system configuration save" {
			t.Error("saved despite no changes")
		}
	}
	if rep.Saved {
		t.Error("rep.Saved true on a no-op")
	}
}

func TestApplyDNS_SNIChangeReplaces(t *testing.T) {
	sent := dnsFake(t)
	_, err := ApplyDNS(context.Background(), DNSDesired{
		TLS:           []DNSUpstreamTLS{{IP: "9.9.9.9", SNI: "dns10.quad9.net"}}, // same IP, new SNI
		ManagedTLSIPs: []string{"9.9.9.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*sent, "\n")
	if !strings.Contains(joined, "no dns-proxy tls upstream 9.9.9.9") ||
		!strings.Contains(joined, "dns-proxy tls upstream 9.9.9.9 sni dns10.quad9.net") {
		t.Errorf("SNI change should drop+re-add:\n%s", joined)
	}
}

func TestClearDNS(t *testing.T) {
	sent := dnsFake(t)
	_, err := ClearDNS(context.Background(),
		[]string{"9.9.9.9"},
		[]string{"https://dns.google/dns-query"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*sent, "\n")
	if !strings.Contains(joined, "no dns-proxy tls upstream 9.9.9.9") ||
		!strings.Contains(joined, "no dns-proxy https upstream https://dns.google/dns-query") {
		t.Errorf("ClearDNS should remove both managed upstreams:\n%s", joined)
	}
	if strings.Contains(joined, "iiadmin") {
		t.Errorf("ClearDNS touched an unmanaged upstream:\n%s", joined)
	}
}
