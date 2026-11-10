package config

import "sort"

// L7SNIEgress reports whether what a route list sends to iface ends up in this
// project's own xray: the Proxy interface the daemon manages, the WG
// transport's interface while that is on, the TUN transport's while that is on.
// A match of the L7 capture feeds the adaptive-routing address set, which is
// redirected into the same xray -- so a name on a list routed through one of
// these is a name that belongs in the set. A list routed anywhere else (a
// second VPN, the LTE modem, a Proxy interface that is not ours) has an egress
// the redirect cannot honour, and is not matched; its names are the ones the
// capture must leave alone (cmd/keenetic-xray's veto).
func (c *Config) L7SNIEgress(iface string) bool {
	switch {
	case iface == "":
		return false
	case iface == c.Proxy0.IfaceName():
		return true
	case c.WGTransport.Enabled && iface == c.WGTransport.Iface:
		return true
	case c.TunTransport.Enabled && iface == c.TunTransport.Iface:
		return true
	}
	return false
}

// L7SNIListIface is where a list of this config is routed: its own interface,
// or the Proxy interface when it names none (RouteList.Interface's doc).
func (c *Config) L7SNIListIface(rl RouteList) string {
	if rl.Interface != "" {
		return rl.Interface
	}
	return c.Proxy0.IfaceName()
}

// L7SNIListEligible reports whether the L7 capture may match names against one
// of this config's route lists: an enabled one routed into our own xray
// (L7SNIEgress). One rule for the capture, the CLI and the bot -- the three
// must agree on which lists count.
func (c *Config) L7SNIListEligible(rl RouteList) bool {
	return !rl.Disabled && c.L7SNIEgress(c.L7SNIListIface(rl))
}

// L7SNIListSummary says what the L7 capture has to match against among this
// config's own lists: how many domain entries the eligible lists hold, and the
// interfaces of the enabled lists that hold domains but are not eligible
// (sorted, once each). The router's own lists are not in here -- they live on
// the router, not in config.json (cmd/keenetic-xray reads them).
func (c *Config) L7SNIListSummary() (domains int, skippedIfaces []string) {
	seen := map[string]bool{}
	for _, rl := range c.Routing.Lists {
		if rl.Disabled {
			continue
		}
		n := 0
		for _, e := range rl.Entries {
			if kind, _, err := ClassifyRouteEntry(e); err == nil && kind == RouteDomain {
				n++
			}
		}
		switch {
		case n == 0:
		case c.L7SNIListEligible(rl):
			domains += n
		default:
			if iface := c.L7SNIListIface(rl); !seen[iface] {
				seen[iface] = true
				skippedIfaces = append(skippedIfaces, iface)
			}
		}
	}
	sort.Strings(skippedIfaces)
	return domains, skippedIfaces
}

// L7SNIEgressIfaces lists the interfaces L7SNIEgress accepts right now, in a
// stable order (the Proxy interface, then the WG and TUN transports' while on):
// what a message says when it tells an operator which lists the capture reads.
func (c *Config) L7SNIEgressIfaces() []string {
	out := []string{c.Proxy0.IfaceName()}
	if c.WGTransport.Enabled && c.WGTransport.Iface != "" {
		out = append(out, c.WGTransport.Iface)
	}
	if c.TunTransport.Enabled && c.TunTransport.Iface != "" {
		out = append(out, c.TunTransport.Iface)
	}
	return out
}
