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
// change. It reads the addresses currently resolved in the given
// `object-group fqdn` names and deletes just those conntrack entries
// (`conntrack -D -d <ip>`, IPv6 with `-f ipv6`), so unrelated flows keep
// their NAT state. If it can't enumerate a useful set -- the read
// failed, nothing resolved yet, a subnet among the entries, too many
// addresses -- it falls back to flushing the whole table. Returns which
// path it took ("точечно (N IP)" / "весь conntrack" / "" when conntrack
// isn't installed). Best-effort: individual -D failures are ignored.
func FlushConntrackForGroups(ctx context.Context, groups []string) (string, error) {
	if !conntrackPresent() {
		return "", nil
	}
	want := make(map[string]bool, len(groups))
	for _, g := range groups {
		want[g] = true
	}
	addrs, subnet, err := objectGroupAddrs(ctx, want)
	if err != nil || subnet || len(addrs) == 0 || len(addrs) > maxTargetedFlush {
		if err := conntrackRun(ctx, "-F"); err != nil {
			return "", err
		}
		return "весь conntrack", nil
	}
	for _, ip := range addrs {
		if strings.Contains(ip, ":") {
			_ = conntrackRun(ctx, "-D", "-f", "ipv6", "-d", ip)
		} else {
			_ = conntrackRun(ctx, "-D", "-d", ip) // exit 1 = no such entry, fine
		}
	}
	return "точечно (" + strconv.Itoa(len(addrs)) + " IP)", nil
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

// objectGroupAddrs reads the addresses Keenetic currently has resolved
// for the `object-group fqdn` groups in want, deduplicated. subnet
// reports a network among them (a CIDR entry): conntrack -D can't target
// one, so the caller has to flush everything.
//
// It reads every group at once: `show object-group fqdn <name>` does not
// exist -- "Command::Base error[7405600]: no such command: <name>" on a
// real router (2026-09-28). The per-group form this used to call was
// written against a guessed format and never worked, so every routes
// change fell back to a full flush.
func objectGroupAddrs(ctx context.Context, want map[string]bool) (addrs []string, subnet bool, err error) {
	out, err := ndmcRun(ctx, "show object-group fqdn")
	if err != nil {
		return nil, false, err
	}
	addrs, subnet = parseObjectGroupAddrs(out, want)
	return addrs, subnet, nil
}

// parseObjectGroupAddrs picks the wanted groups' addresses out of `show
// object-group fqdn`. Real output (KeeneticOS 5.x, trimmed):
//
//	group:
//	   group-name: akamai
//	      enabled: yes
//	   ipv4-addresses-count: 340
//	entry:
//	         fqdn: a132.dscb.akamai.net
//	         type: runtime
//	       parent: akamai.net
//	         ipv4:
//	      address: 23.73.4.217
//	          ttl: 20
//
// Each group opens with `group-name:`; its resolved addresses are the
// `address:` fields. Any value in a wanted group that parses as a
// network (not a single host) counts as a subnet entry, whichever field
// the firmware prints it in.
func parseObjectGroupAddrs(out string, want map[string]bool) (addrs []string, subnet bool) {
	seen := map[string]bool{}
	in := false
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "group-name" {
			in = want[val]
			continue
		}
		if !in || val == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(val); err == nil {
			if ones, bits := n.Mask.Size(); ones < bits {
				subnet = true
				continue
			}
			val = n.IP.String()
		}
		if key != "address" {
			continue
		}
		if ip := net.ParseIP(val); ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			addrs = append(addrs, ip.String())
		}
	}
	return addrs, subnet
}
