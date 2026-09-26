package keenetic

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// HealthCheckProfile is the ping-check profile this project binds to the
// Proxy interface. Without it Keenetic keeps Proxy0 fully up while xray
// is dead -- its upstream is the router's own LAN IP, always reachable --
// so every `dns-proxy route ... Proxy0 auto` black-holes client traffic
// whenever xray is not running: a crash, an update, or the USB stick with
// Entware failing to mount at boot. A failed check drops Proxy0's IP
// layer (`show interface` → layer ipv4: pending), and `auto` routes fall
// back to the ISP on their own. Hardware-verified 2026-09-26; see the
// proxy0-no-failover memory.
const HealthCheckProfile = "kxray"

// The check's parameters, all verified on a real router:
//   - mode tls, not connect: Keenetic's proxy client accepts a TCP
//     handshake locally before it ever dials SOCKS, so a connect-mode
//     check still passes with xray dead. A TLS handshake needs a real
//     reply from the far end.
//   - never icmp: ICMP cannot traverse a SOCKS proxy, so an ICMP check
//     would fail forever and drop Proxy0 for good.
//   - 5s × 3 fails: Keenetic's own recommendation for Ethernet, and long
//     enough that a routine xray restart (self-update) never trips it.
const (
	healthCheckHost     = "1.1.1.1"
	healthCheckPort     = 443
	healthCheckMode     = "tls"
	healthCheckInterval = 5
	healthCheckMaxFails = 3
)

// PingCheckBinding is one interface a ping-check profile is bound to.
type PingCheckBinding struct {
	Interface    string
	Status       string // "pass" / "fail"
	SuccessCount int
	FailCount    int
}

// PingCheckProfile is one profile block of `show ping-check`.
type PingCheckProfile struct {
	Name           string
	Host           string
	Port           int
	Mode           string
	UpdateInterval int
	MaxFails       int
	Bindings       []PingCheckBinding
}

// BoundTo returns the binding for iface, or nil.
func (p PingCheckProfile) BoundTo(iface string) *PingCheckBinding {
	for i := range p.Bindings {
		if p.Bindings[i].Interface == iface {
			return &p.Bindings[i]
		}
	}
	return nil
}

func (p PingCheckProfile) wanted() bool {
	return p.Mode == healthCheckMode && p.Host == healthCheckHost && p.Port == healthCheckPort &&
		p.UpdateInterval == healthCheckInterval && p.MaxFails == healthCheckMaxFails
}

// parsePingCheck parses `show ping-check`. Each profile opens with a
// `pingcheck:` line; its own settings come first, then one `interface:`
// entry per binding, each possibly followed by `ipcache:` entries whose
// `host:` lines are resolved targets, not the profile's host -- hence
// the section tracking.
func parsePingCheck(out string) []PingCheckProfile {
	var profiles []PingCheckProfile
	section := ""
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "pingcheck" {
			profiles = append(profiles, PingCheckProfile{})
			section = "profile"
			continue
		}
		if len(profiles) == 0 {
			continue
		}
		cur := &profiles[len(profiles)-1]
		switch {
		case key == "interface" && val == "":
			cur.Bindings = append(cur.Bindings, PingCheckBinding{})
			section = "interface"
		case key == "ipcache":
			section = "ipcache"
		case section == "profile":
			switch key {
			case "profile":
				cur.Name = val
			case "host":
				cur.Host = val
			case "port":
				cur.Port, _ = strconv.Atoi(val)
			case "mode":
				cur.Mode = val
			case "update-interval":
				cur.UpdateInterval, _ = strconv.Atoi(val)
			case "max-fails":
				cur.MaxFails, _ = strconv.Atoi(val)
			}
		case section == "interface" && len(cur.Bindings) > 0:
			b := &cur.Bindings[len(cur.Bindings)-1]
			switch key {
			case "name":
				b.Interface = val
			case "status":
				b.Status = val
			case "successcount":
				b.SuccessCount, _ = strconv.Atoi(val)
			case "failcount":
				b.FailCount, _ = strconv.Atoi(val)
			}
		}
	}
	return profiles
}

// Proxy0HealthCheck reports HealthCheckProfile as the router sees it; ok
// is false when the profile does not exist.
func Proxy0HealthCheck(ctx context.Context) (p PingCheckProfile, ok bool, err error) {
	out, err := ndmcRun(ctx, "show ping-check")
	if err != nil {
		return PingCheckProfile{}, false, err
	}
	for _, pr := range parsePingCheck(out) {
		if pr.Name == HealthCheckProfile {
			return pr, true, nil
		}
	}
	return PingCheckProfile{}, false, nil
}

// EnsureProxy0HealthCheck makes sure HealthCheckProfile exists with the
// verified settings and is bound to iface, and only iface. A no-op -- no
// writes, no save -- when it already is, so it is cheap enough for every
// reconcile tick. Reports whether it changed anything.
//
// Order matters: `mode tls` goes first and the bind goes last. A firmware
// that rejects tls (KeeneticOS before 4.0) must never end up with the
// profile bound in its default mode, so any failure before tls is
// confirmed deletes the half-built profile, and a read-back that does
// not show the wanted settings undoes the whole thing.
func EnsureProxy0HealthCheck(ctx context.Context, iface string) (changed bool, err error) {
	if iface == "" {
		iface = "Proxy0"
	}
	cur, exists, err := Proxy0HealthCheck(ctx)
	if err != nil {
		return false, err
	}
	if exists && cur.wanted() && cur.BoundTo(iface) != nil && len(cur.Bindings) == 1 {
		return false, nil
	}

	p := "ping-check profile " + HealthCheckProfile
	steps := []string{
		p,
		p + " mode " + healthCheckMode,
		p + " host " + healthCheckHost,
		fmt.Sprintf("%s port %d", p, healthCheckPort),
		fmt.Sprintf("%s update-interval %d", p, healthCheckInterval),
		fmt.Sprintf("%s max-fails %d", p, healthCheckMaxFails),
	}
	for i, c := range steps {
		if _, err := ndmcRun(ctx, c); err != nil {
			if i <= 1 { // tls not confirmed: never leave the profile around
				_ = removeHealthCheck(ctx, cur)
			}
			return true, fmt.Errorf("ndmc %q: %w", c, err)
		}
	}
	for _, b := range cur.Bindings {
		if b.Interface != iface {
			if _, err := ndmcRun(ctx, "interface "+b.Interface+" no ping-check profile "+HealthCheckProfile); err != nil {
				return true, fmt.Errorf("unbinding %s from %s: %w", HealthCheckProfile, b.Interface, err)
			}
		}
	}
	for _, c := range []string{"interface " + iface + " ping-check profile " + HealthCheckProfile, "system configuration save"} {
		if _, err := ndmcRun(ctx, c); err != nil {
			return true, fmt.Errorf("ndmc %q: %w", c, err)
		}
	}

	got, ok, err := Proxy0HealthCheck(ctx)
	if err != nil {
		return true, fmt.Errorf("verifying %s: %w", HealthCheckProfile, err)
	}
	if !ok || !got.wanted() || got.BoundTo(iface) == nil {
		_ = removeHealthCheck(ctx, got)
		return true, fmt.Errorf("%s reads back as mode=%q host=%q port=%d on %v -- removed it rather than leave a wrong check bound",
			HealthCheckProfile, got.Mode, got.Host, got.Port, got.Bindings)
	}
	return true, nil
}

// RemoveHealthCheck unbinds HealthCheckProfile from every interface it is
// bound to and deletes it. A no-op when it does not exist.
func RemoveHealthCheck(ctx context.Context) error {
	cur, ok, err := Proxy0HealthCheck(ctx)
	if err != nil || !ok {
		return err
	}
	return removeHealthCheck(ctx, cur)
}

func removeHealthCheck(ctx context.Context, cur PingCheckProfile) error {
	var cmds []string
	for _, b := range cur.Bindings {
		cmds = append(cmds, "interface "+b.Interface+" no ping-check profile "+HealthCheckProfile)
	}
	cmds = append(cmds, "no ping-check profile "+HealthCheckProfile, "system configuration save")
	for _, c := range cmds {
		if _, err := ndmcRun(ctx, c); err != nil {
			return fmt.Errorf("ndmc %q: %w", c, err)
		}
	}
	return nil
}

// ProxyIPLayer reports the ipv4 layer state from `show interface <iface>`
// -- "running", or "pending" while a failed health check has pulled it
// down. This is the field routing follows; `connected` stays yes either
// way.
func ProxyIPLayer(ctx context.Context, iface string) (string, error) {
	if iface == "" {
		iface = "Proxy0"
	}
	out, err := ndmcRun(ctx, "show interface "+iface)
	if err != nil {
		return "", err
	}
	inLayer := false
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "layer" {
			inLayer = true
			continue
		}
		if inLayer && key == "ipv4" {
			return strings.TrimSpace(val), nil
		}
	}
	return "", nil
}
