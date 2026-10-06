package keenetic

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TunIfaceMarker is the interface description this project stamps on the
// one Keenetic OpkgTun interface it manages -- same idea as WGIfaceMarker.
// ApplyTunTransport, ClearTunTransport and the running-config parser only
// ever touch an interface carrying it (or a bare one a crash left
// half-made), so an operator's own OpkgTun interface is never read,
// changed, or removed. That is a real case: the AmneziaWG-go and tun2socks
// guides for KeeneticOS both build on OpkgTun0.
const TunIfaceMarker = "keenetic-xray-tun"

// TunTransportSpec fully describes the Keenetic side of the OpkgTun
// transport: LAN traffic routed into Iface reaches xray's `tun` inbound,
// which attaches to the kernel device ndm makes for it.
type TunTransportSpec struct {
	Iface   string // "OpkgTun0"
	Address string // the /32 this interface takes
	MTU     int    // interface MTU (>= 1280)
}

var errNoNdmc = errors.New("ndmc not found (not a Keenetic router?)")

// sysClassNet is where the kernel lists its network devices. A var so
// tests can point it at a temp dir.
var sysClassNet = "/sys/class/net"

// How long ApplyTunTransport waits for the kernel device to appear after
// the interface is created, and how often it looks. Vars so tests don't
// sleep. On the router it is there straight away (verified on KeeneticOS
// 5.1); the wait is for a slower firmware, and the error it ends in is how
// a firmware without OpkgTun support shows itself.
var (
	tunDeviceWait = 8 * time.Second
	tunDevicePoll = 200 * time.Millisecond
)

// TunDeviceName is the kernel device ndm creates for an OpkgTun interface
// -- the name xray's tun inbound attaches to. ndm lowercases it
// ("OpkgTun0" -> "opkgtun0", verified on KeeneticOS 5.1), unlike a
// WireGuard interface ("Wireguard4" -> "nwg0"). "" for anything that is
// not an OpkgTun<n> name.
func TunDeviceName(iface string) string {
	if !tunIfaceNameOK(iface) {
		return ""
	}
	return strings.ToLower(iface)
}

// TunDevicePresent reports whether the kernel has a network device called
// dev. ndm creates one for the OpkgTun interface the moment the interface
// exists and keeps it (without carrier) until the interface is removed --
// whether or not anything has attached to it.
func TunDevicePresent(dev string) bool {
	if dev == "" || strings.ContainsAny(dev, "/\\") {
		return false
	}
	_, err := os.Stat(filepath.Join(sysClassNet, dev))
	return err == nil
}

// FreeOpkgTunIface returns the Keenetic OpkgTun interface this project
// should use: the one already carrying TunIfaceMarker if it exists (so a
// re-run is stable), otherwise the lowest OpkgTunN that is neither in the
// running-config nor already a kernel device.
func FreeOpkgTunIface(ctx context.Context) (string, error) {
	if !Available() {
		return "", errNoNdmc
	}
	used, ours, err := scanIfaces(ctx, "OpkgTun", TunIfaceMarker)
	if err != nil {
		return "", err
	}
	if ours != "" {
		return ours, nil
	}
	for n := 0; n < 256; n++ {
		name := "OpkgTun" + strconv.Itoa(n)
		if !used[name] && !TunDevicePresent(strings.ToLower(name)) {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free OpkgTun interface slot (0..255 all in use?)")
}

// ActiveTunIface returns the OpkgTun interface this project has already
// created (carrying TunIfaceMarker), or "" if none exists yet. Unlike
// FreeOpkgTunIface it never allocates one.
func ActiveTunIface(ctx context.Context) (string, error) {
	if !Available() {
		return "", errNoNdmc
	}
	_, ours, err := scanIfaces(ctx, "OpkgTun", TunIfaceMarker)
	return ours, err
}

// ifaceBlock returns the settings under `interface <name>` in a
// running-config, each with its whitespace collapsed, and whether the
// block exists at all.
func ifaceBlock(rc, name string) (body []string, found bool) {
	in := false
	for _, line := range strings.Split(rc, "\n") {
		t := strings.TrimLeft(line, " \t")
		if t == "" {
			continue
		}
		if t == line { // column 0: a block boundary
			f := strings.Fields(t)
			in = len(f) == 2 && f[0] == "interface" && f[1] == name
			if in {
				found = true
			}
			continue
		}
		if in {
			body = append(body, strings.Join(strings.Fields(t), " "))
		}
	}
	return body, found
}

// blockDescription is the interface's `description`, unquoted; "" if it has none.
func blockDescription(body []string) string {
	for _, l := range body {
		if rest, ok := strings.CutPrefix(l, "description "); ok {
			return unquote(strings.TrimSpace(rest))
		}
	}
	return ""
}

// ApplyTunTransport creates the OpkgTun interface named in spec.Iface, or
// brings an existing one of ours back to spec, and waits for ndm to make
// its kernel device -- the thing xray's tun inbound attaches to. Only ever
// touches spec.Iface, and refuses one whose description says it belongs to
// someone else. `system configuration save` runs once at the end.
//
// Deliberately no `ip global`: the interface carries only what is routed
// into it (static routes, DNS routes) and must never become a candidate for
// the default route.
func ApplyTunTransport(ctx context.Context, spec TunTransportSpec) error {
	if !Available() {
		return errNoNdmc
	}
	if !tunIfaceNameOK(spec.Iface) {
		return fmt.Errorf("bad OpkgTun interface name %q", spec.Iface)
	}
	if spec.Address == "" {
		return fmt.Errorf("TunTransportSpec needs Iface and Address")
	}
	rc, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return fmt.Errorf("show running-config: %w", err)
	}
	if body, found := ifaceBlock(rc, spec.Iface); found {
		if d := blockDescription(body); d != "" && d != TunIfaceMarker {
			return fmt.Errorf("%s is somebody else's interface (description %q) -- not touching it", spec.Iface, d)
		}
	}

	pfx := "interface " + spec.Iface
	// The object first: it is what makes ndm create the kernel device.
	if _, err := ndmcRun(ctx, pfx); err != nil {
		return fmt.Errorf("ndmc %q: %w (does this firmware support OpkgTun? it needs KeeneticOS 5.0+)", pfx, err)
	}
	var failed []string
	for _, c := range []string{
		pfx + " description " + TunIfaceMarker,
		pfx + " security-level public",
		fmt.Sprintf("%s ip address %s 255.255.255.255", pfx, spec.Address),
		fmt.Sprintf("%s ip mtu %d", pfx, tunMTU(spec.MTU)),
		pfx + " ip tcp adjust-mss pmtu",
		pfx + " up",
	} {
		if _, e := ndmcRun(ctx, c); e != nil {
			failed = append(failed, fmt.Sprintf("%q: %v", c, e))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("часть команд не выполнилась:\n%s", strings.Join(failed, "\n"))
	}
	if err := SaveConfig(ctx); err != nil {
		return err
	}
	return waitTunDevice(ctx, TunDeviceName(spec.Iface))
}

// waitTunDevice waits for the kernel device dev to exist.
func waitTunDevice(ctx context.Context, dev string) error {
	deadline := time.Now().Add(tunDeviceWait)
	for !TunDevicePresent(dev) {
		if time.Now().After(deadline) {
			return fmt.Errorf("ndm created the interface but the kernel device %s did not appear within %s -- this firmware does not name OpkgTun devices the way this project expects", dev, tunDeviceWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tunDevicePoll):
		}
	}
	return nil
}

// TunLink is what ndm reports about an OpkgTun interface. The two layers
// are independent: State is the administrative one (`interface ... up` /
// `down`), Link/Connected is carrier -- present only while a process holds
// the kernel device, which is what ndm's `auto` routes follow.
type TunLink struct {
	State     string // "up" or "down"; "" if not reported
	Link      string // "up" or "down"; "" if not reported
	Connected bool
	Address   string
	MTU       string
}

// CarrierUp reports whether something is attached to the device.
func (l TunLink) CarrierUp() bool { return l.Link == "up" && l.Connected }

// TunLinkState reads `show interface <iface>`.
func TunLinkState(ctx context.Context, iface string) (TunLink, error) {
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return TunLink{}, fmt.Errorf("show interface %s: %w", iface, err)
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
	return TunLink{
		State:     get("state"),
		Link:      get("link"),
		Connected: get("connected") == "yes",
		Address:   get("address"),
		MTU:       get("mtu"),
	}, nil
}

// WaitTunCarrierGone waits until nothing holds iface's device any more --
// xray was restarted without the tun inbound, or is not running at all --
// up to limit, and reports whether the carrier is gone. Removing the
// interface from under a process that still holds the device is what the
// caller is waiting to avoid; after the limit it is the operator's call
// that decides, so callers go on regardless.
func WaitTunCarrierGone(ctx context.Context, iface string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		l, err := TunLinkState(ctx, iface)
		if err != nil || !l.CarrierUp() {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(tunCarrierPoll):
		}
	}
}

// tunCarrierPoll is how often WaitTunCarrierGone looks. A var so tests don't sleep.
var tunCarrierPoll = time.Second

// TunCounts are the kernel's own counters for the OpkgTun device, seen from
// the kernel's side of it: Tx is what the kernel handed to xray (LAN ->
// tunnel), Rx is what xray handed back (tunnel -> LAN). They are the only
// ground truth of whether traffic really goes through the interface -- the
// exit IP is the same for every transport -- and they keep their values
// while xray restarts (the device belongs to ndm).
type TunCounts struct {
	TxPackets, RxPackets uint64
	TxBytes, RxBytes     uint64
}

// ReadTunCounts reads the counters of the kernel device dev; ok is false
// when it does not exist or its counters can't be read.
func ReadTunCounts(dev string) (c TunCounts, ok bool) {
	if !TunDevicePresent(dev) {
		return TunCounts{}, false
	}
	read := func(name string) (uint64, bool) {
		b, err := os.ReadFile(filepath.Join(sysClassNet, dev, "statistics", name))
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n, err == nil
	}
	var okAll [4]bool
	c.TxPackets, okAll[0] = read("tx_packets")
	c.RxPackets, okAll[1] = read("rx_packets")
	c.TxBytes, okAll[2] = read("tx_bytes")
	c.RxBytes, okAll[3] = read("rx_bytes")
	return c, okAll[0] && okAll[1] && okAll[2] && okAll[3]
}

// Summary is the counters as one line for a human.
func (c TunCounts) Summary() string {
	return fmt.Sprintf("в туннель %s (%d пакетов), из туннеля %s (%d)",
		humanBytes(c.TxBytes), c.TxPackets, humanBytes(c.RxBytes), c.RxPackets)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d Б", n)
	}
	units := []string{"КБ", "МБ", "ГБ", "ТБ"}
	f, i := float64(n)/unit, 0
	for f >= unit && i < len(units)-1 {
		f /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// TunTransportIntact is the cheap check the reconcile loop runs: our
// interface is still in the running-config under our description, is not
// administratively down, and its kernel device exists. Anything else needs
// ApplyTunTransport. why says what was wrong. Address and MTU drift is
// deliberately not checked here -- ndm does not change them by itself, and
// a mismatch in how this firmware prints them must never turn into a flash
// write on every tick.
func TunTransportIntact(ctx context.Context, iface string) (ok bool, why string, err error) {
	if !Available() {
		return false, "", errNoNdmc
	}
	rc, err := ndmcRun(ctx, "show running-config")
	if err != nil {
		return false, "", fmt.Errorf("show running-config: %w", err)
	}
	body, found := ifaceBlock(rc, iface)
	switch {
	case !found:
		return false, "the interface is not in the running config", nil
	case blockDescription(body) != TunIfaceMarker:
		return false, "the interface lost our description", nil
	}
	link, err := TunLinkState(ctx, iface)
	if err != nil {
		return false, "", err
	}
	switch {
	case link.State == "down":
		return false, "the interface is administratively down", nil
	case !TunDevicePresent(TunDeviceName(iface)):
		return false, "the kernel device " + TunDeviceName(iface) + " is missing", nil
	}
	return true, "", nil
}

// ShowTunTransport returns a short human summary of our OpkgTun
// interface's live state, or a note if it isn't set up.
func ShowTunTransport(ctx context.Context, iface string) (string, error) {
	if !Available() {
		return "", errNoNdmc
	}
	if iface == "" {
		_, iface, _ = scanIfaces(ctx, "OpkgTun", TunIfaceMarker)
	}
	if iface == "" {
		return "TUN-транспорт: интерфейс не создан", nil
	}
	l, err := TunLinkState(ctx, iface)
	if err != nil {
		return "", err
	}
	yesno := func(b bool) string {
		if b {
			return "есть"
		}
		return "нет"
	}
	dev := TunDeviceName(iface)
	var b strings.Builder
	fmt.Fprintf(&b, "интерфейс: %s (устройство ядра %s: %s)\n", iface, dev, yesno(TunDevicePresent(dev)))
	if l.State != "" {
		fmt.Fprintf(&b, "состояние: %s\n", l.State)
	}
	fmt.Fprintf(&b, "несущая (xray держит устройство): %s", yesno(l.CarrierUp()))
	if l.Address != "" {
		fmt.Fprintf(&b, "\nадрес: %s", l.Address)
	}
	if l.MTU != "" {
		fmt.Fprintf(&b, "\nmtu: %s", l.MTU)
	}
	if c, ok := ReadTunCounts(dev); ok {
		fmt.Fprintf(&b, "\nтрафик устройства: %s", c.Summary())
	}
	return b.String(), nil
}

// ClearTunTransport removes this project's OpkgTun interface (found by
// marker) and saves. A no-op if there is none. Remove it only after xray
// has let go of the device (see cmd/keenetic-xray's tunTransportOff).
func ClearTunTransport(ctx context.Context) error {
	if !Available() {
		return errNoNdmc
	}
	_, iface, err := scanIfaces(ctx, "OpkgTun", TunIfaceMarker)
	if err != nil {
		return err
	}
	if iface == "" {
		return nil
	}
	if _, e := ndmcRun(ctx, "no interface "+iface); e != nil {
		return fmt.Errorf("ndmc %q: %w", "no interface "+iface, e)
	}
	return SaveConfig(ctx)
}

func tunMTU(m int) int {
	if m < 1280 {
		return 1280
	}
	return m
}

// tunIfaceNameOK mirrors config.ValidTunIface without the import (this
// package is imported by config's consumers, not by config).
func tunIfaceNameOK(s string) bool {
	n, ok := strings.CutPrefix(s, "OpkgTun")
	if !ok || n == "" {
		return false
	}
	for _, r := range n {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
