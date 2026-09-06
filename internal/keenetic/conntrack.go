package keenetic

import (
	"context"
	"os/exec"
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
// the caveat simply stands. `opkg install conntrack-tools` enables it.

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
