package keenetic

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// AllRoutes is ShowRoutes and ShowManualRoutes together: every
// domain-based route list on the router, this project's and the
// operator's own, sorted by group name.
func AllRoutes(ctx context.Context) ([]LiveRoute, error) {
	if !Available() {
		return nil, fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	groups, routes, err := readRoutesMatching(ctx, func(string) bool { return true })
	if err != nil {
		return nil, err
	}
	return liveRoutesFrom(groups, routes), nil
}

// ObjectGroupCount is what `show object-group fqdn` reports for one
// group: how many addresses and names it currently holds, the names
// KeeneticOS added itself while following CNAME chains included.
type ObjectGroupCount struct {
	IPv4, IPv6, FQDN int
}

// ObjectGroupCounts reads those counts for every fqdn object-group --
// how much a routed list actually pulls into its interface, which the
// list's own entries don't tell (docs/routing.md: a CDN zone in a list
// takes every site served through that CDN).
func ObjectGroupCounts(ctx context.Context) (map[string]ObjectGroupCount, error) {
	out, err := ndmcRun(ctx, "show object-group fqdn")
	if err != nil {
		return nil, fmt.Errorf("show object-group fqdn: %w", err)
	}
	return parseObjectGroupCounts(out), nil
}

// parseObjectGroupCounts reads the per-group header fields of `show
// object-group fqdn` -- see parseObjectGroupAddrs for the format.
func parseObjectGroupCounts(out string) map[string]ObjectGroupCount {
	counts := map[string]ObjectGroupCount{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "group-name" {
			cur = val
			counts[cur] = ObjectGroupCount{}
			continue
		}
		n, err := strconv.Atoi(val)
		if cur == "" || err != nil {
			continue
		}
		c := counts[cur]
		switch key {
		case "ipv4-addresses-count":
			c.IPv4 = n
		case "ipv6-addresses-count":
			c.IPv6 = n
		case "fqdn-count":
			c.FQDN = n
		default:
			continue
		}
		counts[cur] = c
	}
	return counts
}
