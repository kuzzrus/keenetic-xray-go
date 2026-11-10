package config

import "sort"

// L7SNIListEligible reports whether the L7 capture may match names against a
// route list: an enabled one routed through Proxy0 (the default interface of a
// list that names none). A match only ever feeds the adaptive-routing address
// set, which rides the live egress -- there is no dataplane through which it
// could honour a list the operator pointed at another interface -- so a list
// that goes elsewhere is not looked at (see cmd/keenetic-xray's
// l7sniDomainsFrom for the long version). One rule for the capture, the CLI
// and the bot: the three must agree on which lists count.
func L7SNIListEligible(rl RouteList) bool {
	return !rl.Disabled && rl.RouteIface() == "Proxy0"
}

// L7SNIListSummary says what the L7 capture has to match against: how many
// domain entries the eligible lists hold, and the interfaces of the enabled
// lists that hold domains but are not eligible (sorted, once each). With no
// domains the capture can count names and redirect nothing, and the second
// value is what tells an operator why: their lists are all routed through
// Wireguard0, say, and L7SNIListEligible looks only at Proxy0.
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
		case L7SNIListEligible(rl):
			domains += n
		default:
			if iface := rl.RouteIface(); !seen[iface] {
				seen[iface] = true
				skippedIfaces = append(skippedIfaces, iface)
			}
		}
	}
	sort.Strings(skippedIfaces)
	return domains, skippedIfaces
}
