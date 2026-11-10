package config

import "testing"

func egressConfig() *Config {
	c := Default()
	c.WGTransport = WGTransportConfig{Enabled: true, Iface: "Wireguard0"}
	return c
}

// A list is matched when what it sends to its interface ends in our own xray:
// the managed Proxy interface, and the WG / TUN transports while they are on.
func TestL7SNIEgress(t *testing.T) {
	c := egressConfig()
	c.TunTransport = TunTransportConfig{Enabled: true, Iface: "OpkgTun3"}
	for iface, want := range map[string]bool{
		"Proxy0": true, "Wireguard0": true, "OpkgTun3": true,
		"UsbLte0": false, "Wireguard1": false, "OpkgTun0": false, "Proxy1": false, "": false,
	} {
		if got := c.L7SNIEgress(iface); got != want {
			t.Errorf("L7SNIEgress(%q) = %v, want %v", iface, got, want)
		}
	}

	// the transports count only while they are on, and only under their own name
	c.WGTransport.Enabled = false
	c.TunTransport.Enabled = false
	if c.L7SNIEgress("Wireguard0") || c.L7SNIEgress("OpkgTun3") {
		t.Error("an interface of a transport that is switched off is still taken for our egress")
	}
	// a transport that is on but has no interface picked yet must not turn "" into one
	c.WGTransport = WGTransportConfig{Enabled: true}
	if c.L7SNIEgress("") {
		t.Error("an empty interface name is taken for our egress")
	}
}

// The Proxy interface the daemon manages may have another name; a list that
// names no interface follows it, a list that names "Proxy0" then does not.
func TestL7SNIListEligible_FollowsTheManagedProxyInterface(t *testing.T) {
	c := Default()
	c.Proxy0.Interface = "Proxy1"
	cases := []struct {
		name string
		rl   RouteList
		want bool
	}{
		{"names none: the managed Proxy1", RouteList{}, true},
		{"explicit Proxy1", RouteList{Interface: "Proxy1"}, true},
		{"explicit Proxy0: not the managed one", RouteList{Interface: "Proxy0"}, false},
		{"disabled", RouteList{Disabled: true}, false},
	}
	for _, tc := range cases {
		if got := c.L7SNIListEligible(tc.rl); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := Default().L7SNIListEligible(RouteList{}); !got {
		t.Error("with the default Proxy0 a list that names no interface is not eligible")
	}
}

// His real shape: lists routed through the WG transport. They are our egress,
// so they count -- not "an interface the capture does not look at".
func TestL7SNIListSummary_ListsOnTheWGTransportCount(t *testing.T) {
	c := egressConfig()
	c.Routing.Lists = []RouteList{
		{Name: "telegram", Entries: []string{"t.me", "telegram.org"}, Interface: "Wireguard0"},
		{Name: "telegram-ip", Entries: []string{"149.154.160.0/20"}, Interface: "Wireguard0"},
	}
	domains, others := c.L7SNIListSummary()
	if domains != 2 || len(others) != 0 {
		t.Errorf("summary = %d, %v, want 2 domains and nothing skipped", domains, others)
	}

	c.WGTransport.Enabled = false // the same lists with the transport off: somebody else's interface
	domains, others = c.L7SNIListSummary()
	if domains != 0 || len(others) != 1 || others[0] != "Wireguard0" {
		t.Errorf("summary with the transport off = %d, %v, want 0 domains and [Wireguard0]", domains, others)
	}
}

func TestL7SNIListSummary_CountsEligibleDomainsAndNamesTheRest(t *testing.T) {
	c := egressConfig()
	c.Routing.Lists = []RouteList{
		{Name: "default-iface", Entries: []string{"youtube.com", "10.0.0.0/8", "googlevideo.com"}},
		{Name: "explicit", Entries: []string{"instagram.com"}, Interface: "Proxy0"},
		{Name: "off", Entries: []string{"x.com"}, Disabled: true},
		{Name: "wg", Entries: []string{"t.me"}, Interface: "Wireguard0"},
		{Name: "lte", Entries: []string{"bank.example"}, Interface: "UsbLte0"},
		{Name: "vpn", Entries: []string{"internal.example"}, Interface: "Wireguard1"},
		{Name: "vpn2", Entries: []string{"t.co"}, Interface: "Wireguard1"},
		{Name: "ips-only", Entries: []string{"1.2.3.4"}, Interface: "Wireguard9"},
	}
	domains, others := c.L7SNIListSummary()
	if domains != 4 {
		t.Errorf("domains = %d, want 4 (two of the default list, the explicit Proxy0 one and the WG one; the CIDR and the disabled list do not count)", domains)
	}
	if len(others) != 2 || others[0] != "UsbLte0" || others[1] != "Wireguard1" {
		t.Errorf("skipped interfaces = %v, want [UsbLte0 Wireguard1] (sorted, once each, no IP-only lists)", others)
	}
}

func TestL7SNIEgressIfaces(t *testing.T) {
	c := Default()
	if got := c.L7SNIEgressIfaces(); len(got) != 1 || got[0] != "Proxy0" {
		t.Errorf("defaults: %v, want [Proxy0]", got)
	}
	c = egressConfig()
	c.TunTransport = TunTransportConfig{Enabled: true, Iface: "OpkgTun3"}
	got := c.L7SNIEgressIfaces()
	if len(got) != 3 || got[0] != "Proxy0" || got[1] != "Wireguard0" || got[2] != "OpkgTun3" {
		t.Errorf("all on: %v, want [Proxy0 Wireguard0 OpkgTun3]", got)
	}
	for _, iface := range got {
		if !c.L7SNIEgress(iface) {
			t.Errorf("%q is listed but not accepted by L7SNIEgress", iface)
		}
	}
}
