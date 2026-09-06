package keenetic

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// WGIfaceMarker is the interface description this project stamps on the
// one Keenetic WireGuard interface it manages -- same idea as the Proxy0
// `description keenetic-xray` and the `keenetic-xray-` object-group
// prefix. ApplyWGTransport / ClearWGTransport and the running-config
// parser only ever touch an interface carrying this marker, so the
// operator's own WireGuard tunnels are never read, changed, or removed.
const WGIfaceMarker = "keenetic-xray-wg"

// WGTransportSpec fully describes the Keenetic side of the in-router WG
// transport: LAN traffic routed into Iface is encrypted to the xray
// `wireguard` inbound at Endpoint.
type WGTransportSpec struct {
	Iface      string // "Wireguard4"
	Address    string // the /32 this interface takes on the tunnel
	MTU        int    // interface MTU (>= 1280)
	PeerPubKey string // xray's WG public key, base64
	PeerPSK    string // shared pre-shared key, base64; "" to omit
	Endpoint   string // host:port where xray's wireguard inbound listens
	Keepalive  int    // persistent keepalive seconds (<=0 -> 25)
}

func (s WGTransportSpec) keepalive() int {
	if s.Keepalive <= 0 {
		return 25
	}
	return s.Keepalive
}

// FreeWireguardIface returns the Keenetic WireGuard interface this
// project should use: the one already carrying WGIfaceMarker if it
// exists (so a re-run is stable), otherwise the lowest WireguardN not
// present in the running-config.
func FreeWireguardIface(ctx context.Context) (string, error) {
	if !Available() {
		return "", fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	used, ours, err := scanWireguardIfaces(ctx)
	if err != nil {
		return "", err
	}
	if ours != "" {
		return ours, nil
	}
	for n := 0; n < 256; n++ {
		name := "Wireguard" + strconv.Itoa(n)
		if !used[name] {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free WireGuard interface slot (0..255 all in use?)")
}

// scanWireguardIfaces reads the running-config and returns the set of
// existing `interface WireguardN` names plus the name of the one bearing
// WGIfaceMarker ("" if none).
func scanWireguardIfaces(ctx context.Context) (used map[string]bool, ours string, err error) {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return nil, "", fmt.Errorf("show running-config: %w", err)
	}
	used = map[string]bool{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		body := strings.TrimLeft(line, " \t")
		if body == "" {
			continue
		}
		f := strings.Fields(body)
		if body == line { // column-0: block boundary
			cur = ""
			if len(f) == 2 && f[0] == "interface" && strings.HasPrefix(f[1], "Wireguard") {
				used[f[1]] = true
				cur = f[1]
			}
			continue
		}
		if cur != "" && len(f) >= 2 && f[0] == "description" && unquote(strings.TrimSpace(strings.TrimPrefix(body, "description "))) == WGIfaceMarker {
			ours = cur
		}
	}
	return used, ours, nil
}

// WGInterfacePublicKey reads the public key KeeneticOS generated for
// iface out of `show interface <iface>` -- the `public-key:` under the
// top-level `wireguard:` block, before any `peer:`.
func WGInterfacePublicKey(ctx context.Context, iface string) (string, error) {
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return "", fmt.Errorf("show interface %s: %w", iface, err)
	}
	seenWG, seenPeer := false, false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "wireguard:":
			seenWG = true
		case "peer:":
			seenPeer = true
		case "public-key:":
			if seenWG && !seenPeer && len(f) >= 2 {
				return f[1], nil
			}
		}
	}
	return "", fmt.Errorf("no interface public-key in `show interface %s` (interface not created yet?)", iface)
}

// ourPeerKeys returns the peer public keys currently configured under
// iface in the running-config -- used to drop a stale one after the xray
// key is rotated.
func ourPeerKeys(ctx context.Context, iface string) ([]string, error) {
	out, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return nil, fmt.Errorf("show running-config: %w", err)
	}
	var keys []string
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		body := strings.TrimLeft(line, " \t")
		if body == "" {
			continue
		}
		f := strings.Fields(body)
		if body == line {
			cur = ""
			if len(f) == 2 && f[0] == "interface" {
				cur = f[1]
			}
			continue
		}
		if cur == iface && len(f) >= 3 && f[0] == "wireguard" && f[1] == "peer" {
			keys = append(keys, f[2])
		}
	}
	return keys, nil
}

// ApplyWGTransport reconciles the single Keenetic WireGuard interface
// named in spec.Iface to spec, creating it if absent (which makes
// KeeneticOS generate its own keypair), and returns that interface's
// public key -- what the caller feeds to the xray `wireguard` inbound as
// the peer. Only ever touches spec.Iface. `system configuration save`
// runs once at the end.
func ApplyWGTransport(ctx context.Context, spec WGTransportSpec) (ifacePubKey string, err error) {
	if !Available() {
		return "", fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if !wgIfaceNameOK(spec.Iface) {
		return "", fmt.Errorf("bad WireGuard interface name %q", spec.Iface)
	}
	if spec.PeerPubKey == "" || spec.Endpoint == "" || spec.Address == "" {
		return "", fmt.Errorf("WGTransportSpec needs Iface, Address, PeerPubKey and Endpoint")
	}

	// Create the interface + stamp our marker, then persist so KeeneticOS
	// commits the generated keypair before we read it back. `up` is left
	// for the reconcile pass below -- some firmware rejects `up` on a WG
	// interface that has no peer yet.
	for _, c := range []string{
		"interface " + spec.Iface,
		fmt.Sprintf("interface %s description %s", spec.Iface, WGIfaceMarker),
		"system configuration save",
	} {
		if _, e := ndmcRun(ctx, c); e != nil {
			return "", fmt.Errorf("ndmc %q: %w", c, e)
		}
	}

	pub := ""
	for attempt := 0; attempt < 5; attempt++ {
		var e error
		if pub, e = WGInterfacePublicKey(ctx, spec.Iface); e == nil && pub != "" {
			break
		} else if e != nil {
			err = e
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
	}
	if pub == "" {
		if err != nil {
			return "", fmt.Errorf("could not read %s public key after creating it: %w", spec.Iface, err)
		}
		return "", fmt.Errorf("could not read %s public key after creating it", spec.Iface)
	}

	stale, _ := ourPeerKeys(ctx, spec.Iface)

	pfx := "interface " + spec.Iface
	peer := pfx + " wireguard peer " + spec.PeerPubKey
	var cmds []string
	for _, k := range stale {
		if k != spec.PeerPubKey {
			cmds = append(cmds, fmt.Sprintf("%s no wireguard peer %s", pfx, k))
		}
	}
	cmds = append(cmds,
		pfx+" security-level public",
		fmt.Sprintf("%s ip address %s %s", pfx, spec.Address, "255.255.255.255"),
		fmt.Sprintf("%s ip mtu %d", pfx, wgMTU(spec.MTU)),
		pfx+" ip tcp adjust-mss pmtu",
		peer,
		peer+" endpoint "+spec.Endpoint,
		fmt.Sprintf("%s keepalive-interval %d", peer, spec.keepalive()),
	)
	if spec.PeerPSK != "" {
		cmds = append(cmds, peer+" preshared-key "+spec.PeerPSK)
	}
	cmds = append(cmds,
		peer+" allow-ips 0.0.0.0 0.0.0.0",
		peer+" connect",
		pfx+" up",
		"system configuration save",
	)

	var failed []string
	for _, c := range cmds {
		if _, e := ndmcRun(ctx, c); e != nil {
			shown := c
			if spec.PeerPSK != "" {
				shown = strings.ReplaceAll(shown, spec.PeerPSK, "<psk>")
			}
			failed = append(failed, fmt.Sprintf("%q: %v", shown, e))
		}
	}
	if len(failed) > 0 {
		return pub, fmt.Errorf("часть команд не выполнилась:\n%s", strings.Join(failed, "\n"))
	}
	return pub, nil
}

// WGInterfaceUp reports whether iface exists and is administratively up
// (`state:` is anything other than "down"). The daemon's reconcile loop
// uses this as a cheap "is it still there" check before deciding whether
// to rebuild the interface -- a dead peer (no handshake) is a network
// problem, not config drift, so "up" is enough.
func WGInterfaceUp(ctx context.Context, iface string) bool {
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "state:" {
			return f[1] != "down"
		}
	}
	return false
}

// ShowWGTransport returns a short human summary of our WG interface's
// live state, or a note if it isn't set up.
func ShowWGTransport(ctx context.Context, iface string) (string, error) {
	if !Available() {
		return "", fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	if iface == "" {
		_, iface, _ = scanWireguardIfaces(ctx)
	}
	if iface == "" {
		return "WG-транспорт: интерфейс не создан", nil
	}
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return "", fmt.Errorf("show interface %s: %w", iface, err)
	}
	get := func(key string) string {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == key+":" {
				return strings.Join(f[1:], " ")
			}
		}
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "интерфейс: %s\n", iface)
	if v := get("state"); v != "" {
		fmt.Fprintf(&b, "состояние: %s\n", v)
	}
	if v := get("address"); v != "" {
		fmt.Fprintf(&b, "адрес: %s\n", v)
	}
	if v := get("mtu"); v != "" {
		fmt.Fprintf(&b, "mtu: %s\n", v)
	}
	if strings.Contains(out, "last-handshake:") {
		hs := get("last-handshake")
		online := get("online")
		fmt.Fprintf(&b, "last-handshake: %s, online: %s", hs, online)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// ClearWGTransport removes this project's WireGuard interface (found by
// marker, or the given name) and saves. A no-op if there is none.
func ClearWGTransport(ctx context.Context) error {
	if !Available() {
		return fmt.Errorf("ndmc not found (not a Keenetic router?)")
	}
	_, iface, err := scanWireguardIfaces(ctx)
	if err != nil {
		return err
	}
	if iface == "" {
		return nil
	}
	for _, c := range []string{"no interface " + iface, "system configuration save"} {
		if _, e := ndmcRun(ctx, c); e != nil {
			return fmt.Errorf("ndmc %q: %w", c, e)
		}
	}
	return nil
}

func wgMTU(m int) int {
	if m < 1280 {
		return 1280
	}
	return m
}

// unquote strips one layer of surrounding double quotes.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// wgIfaceNameOK mirrors config.ValidWGIface without the import (this
// package is imported by config's consumers, not by config).
func wgIfaceNameOK(s string) bool {
	if !strings.HasPrefix(s, "Wireguard") {
		return false
	}
	n := strings.TrimPrefix(s, "Wireguard")
	if n == "" {
		return false
	}
	for _, r := range n {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
