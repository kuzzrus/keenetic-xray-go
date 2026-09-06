package keenetic

import (
	"context"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// Conntrack caches each flow's routing decision on its first packet. When
// a `routes` list starts sending an IP through Proxy0/WireguardN,
// connections already open to that IP keep going out the WAN until they
// close -- the "first connect may leak direct" caveat. Flushing conntrack
// after a routes change makes every flow re-evaluate its route on the
// next packet (invisible for TCP; a blip for an active UDP stream), so
// matched connections move into the tunnel right away.
//
// `conntrack` isn't on Keenetic by default and this project does not
// pull it in: FlushConntrack is a no-op when the binary is absent, and
// the caveat simply stands. `opkg install conntrack` enables it (Entware
// names the package `conntrack`, not `conntrack-tools`).

var (
	conntrackRun = func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "conntrack", args...).Run()
	}
	conntrackPresent = func() bool { return exec.Command("conntrack", "--version").Run() == nil }
)

// ConntrackPresent reports whether the `conntrack` CLI is runnable.
func ConntrackPresent() bool { return conntrackPresent() }

// FlushConntrack drops the whole conntrack table (`conntrack -F`).
// Best-effort: a no-op, no error, when conntrack isn't installed.
func FlushConntrack(ctx context.Context) error {
	if !conntrackPresent() {
		return nil
	}
	return conntrackRun(ctx, "-F")
}

// maxTargetedFlush caps how many per-IP deletes are worth doing before
// falling back to a single `conntrack -F`.
const maxTargetedFlush = 400

// FlushConntrackForGroups re-routes open connections after a routes
// change. It reads the resolved IPs currently in the given `object-group
// fqdn` names and deletes just those conntrack entries (`conntrack -D -d
// <ip>`), so unrelated flows keep their NAT state. If it can't enumerate
// a useful set -- nothing resolved yet, CIDR-only lists, too many IPs --
// it falls back to flushing the whole table. Returns which path it took
// ("точечно (N IP)" / "весь conntrack" / "" when conntrack isn't
// installed). Best-effort: individual -D failures are ignored.
func FlushConntrackForGroups(ctx context.Context, groups []string) (string, error) {
	if !conntrackPresent() {
		return "", nil
	}
	seen := map[string]struct{}{}
	for _, g := range groups {
		for _, ip := range objectGroupIPs(ctx, g) {
			seen[ip] = struct{}{}
		}
	}
	if len(seen) == 0 || len(seen) > maxTargetedFlush {
		if err := conntrackRun(ctx, "-F"); err != nil {
			return "", err
		}
		return "весь conntrack", nil
	}
	for ip := range seen {
		_ = conntrackRun(ctx, "-D", "-d", ip) // exit 1 = no such entry, fine
	}
	return "точечно (" + strconv.Itoa(len(seen)) + " IP)", nil
}

// objectGroupIPs parses `show object-group fqdn <name>` for the IPv4
// addresses Keenetic currently has resolved for that group. Format-
// tolerant: any bare dotted-quad on a line that isn't an `excluded-*` or
// a `*-count` field. Empty on any error.
func objectGroupIPs(ctx context.Context, group string) []string {
	out, err := ndmcRun(ctx, "show object-group fqdn "+group)
	if err != nil {
		return nil
	}
	var ips []string
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "excluded-") || strings.Contains(l, "-count") {
			continue
		}
		for _, f := range strings.FieldsFunc(l, func(r rune) bool { return r == ' ' || r == ':' || r == ',' }) {
			f = strings.TrimSuffix(f, "/32")
			if ip := net.ParseIP(f); ip != nil && ip.To4() != nil {
				ips = append(ips, f)
			}
		}
	}
	return ips
}
