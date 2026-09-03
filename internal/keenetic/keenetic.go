// Package keenetic drives the router's own CLI (ndmc) to point Keenetic's
// Proxy interface at the local Xray inbound, so selected LAN traffic can
// be policy-routed through the proxy without the operator hand-editing
// the router config.
//
// The LAN-IP detection deliberately only looks at the LAN bridge
// (Bridge0/Home/br0) and never falls back to a loopback address: on a 4G
// uplink the WAN carries a private CGNAT address that looks local but
// routes to the carrier, and an earlier shell version that fell back to
// 127.0.0.1 on a failed probe quietly broke a working upstream every
// time it re-ran.
package keenetic

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// lanInterfaces are the names Keenetic uses for the LAN bridge.
var lanInterfaces = []string{"Bridge0", "Home", "br0"}

// ndmcRun executes one `ndmc -c "<cmd>"` and returns its stdout. Replaced
// in tests.
var ndmcRun = func(ctx context.Context, cmd string) (string, error) {
	out, err := exec.CommandContext(ctx, "ndmc", "-c", cmd).Output()
	return string(out), err
}

// lookNdmc reports whether ndmc is on PATH. Replaced in tests.
var lookNdmc = func() error {
	_, err := exec.LookPath("ndmc")
	return err
}

// Available reports whether this looks like a Keenetic router (ndmc is
// present). Callers should treat a false result as "skip, not an error".
func Available() bool { return lookNdmc() == nil }

// LANIP returns the router's LAN IPv4. override (e.g. from a config field
// or KEENETIC_XRAY_LAN_IP) wins outright, including a deliberate
// non-standard value. Otherwise it asks ndmc for each LAN interface in
// turn. It never returns a loopback or non-private address.
func LANIP(ctx context.Context, override string) (string, error) {
	if o := strings.TrimSpace(override); o != "" {
		if !validPrivateIPv4(o) {
			return "", fmt.Errorf("override LAN IP %q is not a valid private IPv4", o)
		}
		return o, nil
	}
	if !Available() {
		return "", fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	for _, iface := range lanInterfaces {
		if ip := lanIPFromRunningConfig(ctx, iface); validPrivateIPv4(ip) {
			return ip, nil
		}
		if ip := lanIPFromShowInterface(ctx, iface); validPrivateIPv4(ip) {
			return ip, nil
		}
	}
	return "", fmt.Errorf("could not detect a LAN IPv4 on %s", strings.Join(lanInterfaces, "/"))
}

func lanIPFromRunningConfig(ctx context.Context, iface string) string {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return ""
	}
	inBlock := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "interface" {
			inBlock = len(f) > 1 && f[1] == iface
			continue
		}
		if inBlock && len(f) >= 3 && f[0] == "ip" && f[1] == "address" {
			return stripMask(f[2])
		}
	}
	return ""
}

func lanIPFromShowInterface(ctx context.Context, iface string) string {
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "address:" {
			return stripMask(f[1])
		}
	}
	return ""
}

// Proxy0Options configures ConfigureProxy0.
type Proxy0Options struct {
	Interface    string // "" -> "Proxy0"
	UpstreamHost string // the router LAN IP the Xray inbound listens on
	UpstreamPort int
	Protocol     string // "" -> "socks5"; also accepts "http"
	Description  string // "" -> "keenetic-xray"
}

func (o Proxy0Options) iface() string {
	if o.Interface != "" {
		return o.Interface
	}
	return "Proxy0"
}

func (o Proxy0Options) proto() string {
	if o.Protocol != "" {
		return o.Protocol
	}
	return "socks5"
}

// ConfigureProxy0 creates/updates the Proxy interface to forward to
// UpstreamHost:UpstreamPort, brings it up, persists the config, then
// reads the running-config back to confirm the upstream took.
func ConfigureProxy0(ctx context.Context, o Proxy0Options) error {
	if !Available() {
		return fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if !validPrivateIPv4(o.UpstreamHost) {
		return fmt.Errorf("upstream host %q is not a valid private IPv4", o.UpstreamHost)
	}
	if o.UpstreamPort <= 0 || o.UpstreamPort > 65535 {
		return fmt.Errorf("upstream port %d out of range", o.UpstreamPort)
	}

	iface := o.iface()
	desc := o.Description
	if desc == "" {
		desc = "keenetic-xray"
	}

	cmds := []string{
		"interface " + iface,
		fmt.Sprintf("interface %s description %s", iface, desc),
		fmt.Sprintf("interface %s proxy protocol %s", iface, o.proto()),
	}
	if o.proto() == "socks5" {
		cmds = append(cmds, "interface "+iface+" proxy socks5-udp")
	}
	cmds = append(cmds,
		fmt.Sprintf("interface %s proxy upstream %s %d", iface, o.UpstreamHost, o.UpstreamPort),
		"interface "+iface+" no ip global",
		"interface "+iface+" up",
		"system configuration save",
	)
	for _, c := range cmds {
		if _, err := ndmcRun(ctx, c); err != nil {
			return fmt.Errorf("ndmc %q: %w", c, err)
		}
	}

	host, port, ok, err := Proxy0Upstream(ctx, iface)
	if err != nil {
		return fmt.Errorf("verifying %s upstream: %w", iface, err)
	}
	if !ok || host != o.UpstreamHost || port != o.UpstreamPort {
		return fmt.Errorf("%s upstream reads back as %s:%d, expected %s:%d", iface, host, port, o.UpstreamHost, o.UpstreamPort)
	}
	return nil
}

// Proxy0Upstream returns the upstream currently set on iface ("" ->
// "Proxy0"), with ok=false if the interface exists but has none.
func Proxy0Upstream(ctx context.Context, iface string) (host string, port int, ok bool, err error) {
	if iface == "" {
		iface = "Proxy0"
	}
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return "", 0, false, err
	}
	inBlock := false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "interface" {
			inBlock = len(f) > 1 && f[1] == iface
			continue
		}
		if inBlock && len(f) >= 4 && f[0] == "proxy" && f[1] == "upstream" {
			p, perr := strconv.Atoi(f[3])
			if perr != nil {
				return "", 0, false, fmt.Errorf("unparseable upstream port %q", f[3])
			}
			return f[2], p, true, nil
		}
	}
	return "", 0, false, nil
}

// DisableProxy0 brings iface down and persists the config.
func DisableProxy0(ctx context.Context, iface string) error {
	if !Available() {
		return fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if iface == "" {
		iface = "Proxy0"
	}
	for _, c := range []string{"interface " + iface + " down", "system configuration save"} {
		if _, err := ndmcRun(ctx, c); err != nil {
			return fmt.Errorf("ndmc %q: %w", c, err)
		}
	}
	return nil
}

func stripMask(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// validPrivateIPv4 accepts a dotted-quad in the RFC 1918 ranges and
// nothing else -- no CIDR suffix, no netmask, no loopback, no public
// address.
func validPrivateIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	var o [4]int
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
		o[i] = n
	}
	switch {
	case o[0] == 10:
		return true
	case o[0] == 192 && o[1] == 168:
		return true
	case o[0] == 172 && o[1] >= 16 && o[1] <= 31:
		return true
	}
	return false
}
