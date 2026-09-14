package keenetic

import (
	"context"
	"fmt"
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
// `conntrack` isn't on Keenetic by default. FlushConntrack/
// FlushConntrackForGroups (the `routes` use above) treat that as
// acceptable best-effort degradation -- a no-op, no error, the caveat
// simply stands -- since routes' own DNS-based matching still gets a
// freshly-opened connection right either way. DeleteConntrackFlow's own
// caller (adaptive routing's classify loop, internal/classifier) is
// different: an already-established flow that just got promoted to
// "route through the tunnel" has no other way to move over besides this
// -- without it, that specific flow just sits there until the client's
// own retry/timeout eventually opens a fresh one. So adaptive routing
// calls EnsureConntrackTool explicitly (see cmd/keenetic-xray's
// adaptiveRouteOn/applyAdaptiveRouteAtStartup), the same shape as
// internal/adaptiveroute.EnsureIPSetTool for its own ipset dependency,
// rather than silently accepting the gap the way routes does.

var (
	conntrackRun = func(ctx context.Context, args ...string) error {
		return exec.CommandContext(ctx, "conntrack", args...).Run()
	}
	conntrackPresent     = func() bool { return exec.Command("conntrack", "--version").Run() == nil }
	opkgInstallConntrack = func(ctx context.Context) error {
		// `opkg update` first, best-effort -- same reasoning as
		// internal/addons' own opkgInstall helper and this project's
		// other opkg-install call sites: a stale/empty local package
		// index makes `opkg install <name>` fail as "not found" even
		// when the package genuinely exists in the feed.
		_ = exec.CommandContext(ctx, "opkg", "update").Run()
		return exec.CommandContext(ctx, "opkg", "install", "conntrack").Run()
	}
)

// ConntrackPresent reports whether the `conntrack` CLI is runnable.
func ConntrackPresent() bool { return conntrackPresent() }

// EnsureConntrackTool makes sure the `conntrack` CLI is runnable,
// installing the Entware package if not. See the comment above for why
// adaptive routing needs this guaranteed rather than accepting
// FlushConntrack's silent-degradation default.
func EnsureConntrackTool(ctx context.Context) error {
	if conntrackPresent() {
		return nil
	}
	if err := opkgInstallConntrack(ctx); err != nil {
		return fmt.Errorf("installing conntrack via opkg: %w", err)
	}
	if !conntrackPresent() {
		return fmt.Errorf("conntrack still not runnable after opkg install")
	}
	return nil
}

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

// DeleteConntrackFlow deletes one specific conntrack entry by its
// original-direction 5-tuple (`conntrack -D -p <proto> -s <src> -d <dst>
// --sport <sport> --dport <dport>`) -- used by the adaptive-routing
// classifier (internal/classifier) to force a fresh connection attempt
// through a just-changed routing decision without disturbing any other
// flow to/from the same address, unlike FlushConntrackForGroups' whole-IP
// `-D -d <ip>`. Best-effort, same as FlushConntrackForGroups' per-IP
// deletes: a no-op when conntrack isn't installed, and "no such entry"
// (the flow already closed on its own between the classifier's scan and
// this call) is not an error either.
func DeleteConntrackFlow(ctx context.Context, proto, src, dst string, sport, dport uint) {
	if !conntrackPresent() {
		return
	}
	_ = conntrackRun(ctx, "-D", "-p", proto, "-s", src, "-d", dst,
		"--sport", strconv.FormatUint(uint64(sport), 10), "--dport", strconv.FormatUint(uint64(dport), 10))
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
