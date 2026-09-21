package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// XrayConfigOptions parameterizes GenerateXrayConfig. The same generator
// produces both the production config and the isolated recovery-pretest
// config (internal/failover, M4) — only the ports and which Profile is
// used as the outbound differ, so the two configs cannot structurally
// drift apart from each other.
type XrayConfigOptions struct {
	SOCKSPort  int     // local SOCKS5 inbound port; 0 disables it
	HTTPPort   int     // local HTTP inbound port; 0 disables it
	ListenHost string  // inbound bind address; "" -> "127.0.0.1". Set to "0.0.0.0" so Keenetic's Proxy0 can reach the inbound over the LAN.
	Outbound   Profile // the profile to route all traffic through
	XHTTPMode  string  // "" -> keep the profile's own mode; otherwise force this xhttp mode (Config.XHTTPMode)

	// SidecarSOCKS is the local port a `naive` sidecar process is
	// listening on (internal/failover starts and owns that process; this
	// package never launches anything). Required when Outbound.Protocol
	// == "naive" -- ignored otherwise.
	SidecarSOCKS int

	// WG, when set, adds a `wireguard` inbound so Keenetic can carry
	// selected LAN traffic into xray over an in-router WireGuard hop
	// instead of (or alongside) Proxy0/SOCKS. Never set for the isolated
	// recovery-pretest instance.
	WG *WGInboundOptions

	// Transparent, when set, adds a `dokodemo-door` inbound for
	// REDIRECT-based transparent proxying -- adaptive per-IP routing
	// (Susanin Phase 2, see docs/HANDOFF-susanin.md) points an iptables
	// REDIRECT rule at this port for destinations its own classifier has
	// confirmed are blocked, so that traffic rides whatever vless/naive
	// profile is currently the live outbound below, same as every other
	// inbound here -- no separate egress, no second daemon. Never set
	// for the isolated recovery-pretest instance.
	Transparent *TransparentOptions
}

// TransparentOptions describes the xray `dokodemo-door` inbound used for
// REDIRECT-based transparent proxying. Always binds 0.0.0.0 -- confirmed
// live (2026-09-14) that this must NOT be 127.0.0.1: iptables' REDIRECT
// target rewrites the destination to the *primary address of the
// incoming interface* for a non-locally-generated packet, only mapping
// to 127.0.0.1 for packets the router itself originates (see
// iptables-extensions(8)'s own REDIRECT description). Our REDIRECT rule
// matches on `-i <lan-iface>` (internal/adaptiveroute), so every packet
// it catches arrives on the LAN bridge and gets rewritten to *that
// interface's own address* (e.g. the router's 192.168.1.1), never
// loopback. Binding only 127.0.0.1 silently black-holed every redirected
// connection -- the classifier still worked (ipset populated correctly),
// but nothing ever reached xray. Same accepted exposure as Proxy0/WG's
// own "must be reachable from the LAN" 0.0.0.0 bind: relies on
// Keenetic's own firewall keeping the WAN out, not on this port being
// otherwise unreachable.
type TransparentOptions struct {
	Port int // TCP+UDP listen port
}

// WGInboundOptions describes the xray `wireguard` inbound for the
// in-router WG transport. xray is the WG "server"; the single peer is
// the Keenetic WireGuard interface.
type WGInboundOptions struct {
	ListenHost     string   // bind address (0.0.0.0 so Keenetic reaches it over the LAN)
	Port           int      // UDP listen port
	SecretKey      string   // xray's WG private key, base64
	MTU            int      // 0 -> omit (xray default)
	PeerPublicKey  string   // the Keenetic interface's public key, base64
	PeerPSK        string   // shared pre-shared key, base64; "" -> omit
	PeerAllowedIPs []string // nil -> ["0.0.0.0/0"]
}

func (o XrayConfigOptions) listenHost() string {
	if o.ListenHost != "" {
		return o.ListenHost
	}
	return "127.0.0.1"
}

// GenerateXrayConfig renders an Xray-core JSON config. There is
// deliberately no `routing` block with geosite/geoip rules — this project
// ships no geodata, so the single "proxy" outbound (the first entry,
// Xray's default when nothing else matches) carries all traffic that
// reaches xray. Deciding *which* traffic reaches it is Keenetic's job:
// point the whole LAN at Proxy0, or route selected domains/subnets there
// with `keenetic-xray routes` (internal/keenetic drives Keenetic's own
// DNS-based routing) — either way xray itself stays a dumb single tunnel.
func GenerateXrayConfig(opts XrayConfigOptions) ([]byte, error) {
	if opts.SOCKSPort == 0 && opts.HTTPPort == 0 {
		return nil, fmt.Errorf("at least one of SOCKSPort or HTTPPort must be set")
	}
	if err := opts.Outbound.Validate(); err != nil {
		return nil, fmt.Errorf("invalid outbound profile: %w", err)
	}

	var inbounds []xrayInbound
	if opts.SOCKSPort != 0 {
		inbounds = append(inbounds, xrayInbound{
			Listen:   opts.listenHost(),
			Port:     opts.SOCKSPort,
			Protocol: "socks",
			Settings: map[string]any{"udp": true},
			Tag:      "socks-in",
		})
	}
	if opts.HTTPPort != 0 {
		inbounds = append(inbounds, xrayInbound{
			Listen:   opts.listenHost(),
			Port:     opts.HTTPPort,
			Protocol: "http",
			Settings: map[string]any{},
			Tag:      "http-in",
		})
	}
	if opts.WG != nil {
		wgIn, err := wgInbound(*opts.WG)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, wgIn)
	}
	if opts.Transparent != nil {
		tIn, err := transparentInbound(*opts.Transparent)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, tIn)
	}

	outbound, err := buildOutbound(opts.Outbound, opts.XHTTPMode, opts.SidecarSOCKS)
	if err != nil {
		return nil, err
	}

	cfg := xrayConfig{
		Log:      xrayLog{LogLevel: "warning"},
		Inbounds: inbounds,
		Outbounds: []xrayOutbound{
			outbound,
			{Tag: "direct", Protocol: "freedom"},
			{Tag: "block", Protocol: "blackhole"},
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding xray config: %w", err)
	}
	return data, nil
}

// wgInbound renders the `wireguard` inbound. kernelMode is false --
// Entware has no kernel WireGuard module, xray does it in userspace.
func wgInbound(o WGInboundOptions) (xrayInbound, error) {
	switch {
	case o.ListenHost == "":
		return xrayInbound{}, fmt.Errorf("wireguard inbound: ListenHost required")
	case o.Port <= 0 || o.Port > 65535:
		return xrayInbound{}, fmt.Errorf("wireguard inbound: bad port %d", o.Port)
	case !ValidWGKey(o.SecretKey):
		return xrayInbound{}, fmt.Errorf("wireguard inbound: SecretKey is not a valid key")
	case !ValidWGKey(o.PeerPublicKey):
		return xrayInbound{}, fmt.Errorf("wireguard inbound: PeerPublicKey is not a valid key")
	case o.PeerPSK != "" && !ValidWGKey(o.PeerPSK):
		return xrayInbound{}, fmt.Errorf("wireguard inbound: PeerPSK is not a valid key")
	}

	allowed := o.PeerAllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	peer := map[string]any{
		"publicKey":  o.PeerPublicKey,
		"allowedIPs": allowed,
	}
	if o.PeerPSK != "" {
		peer["preSharedKey"] = o.PeerPSK
	}
	settings := map[string]any{
		"secretKey":  o.SecretKey,
		"kernelMode": false,
		"peers":      []map[string]any{peer},
	}
	if o.MTU > 0 {
		settings["mtu"] = o.MTU
	}
	return xrayInbound{
		Listen:   o.ListenHost,
		Port:     o.Port,
		Protocol: "wireguard",
		Settings: settings,
		Tag:      "wg-in",
	}, nil
}

// transparentInbound renders the `dokodemo-door` inbound. followRedirect
// makes xray recover the real destination via SO_ORIGINAL_DST (TCP) / the
// packet's own original destination (UDP) instead of treating 127.0.0.1
// itself as the target -- confirmed against infra/conf/dokodemo.go at
// this project's pinned xray-core tag. No routing block is needed for
// this inbound any more than for socks-in/http-in/wg-in above: it falls
// through to the same single default "proxy" outbound.
func transparentInbound(o TransparentOptions) (xrayInbound, error) {
	if o.Port <= 0 || o.Port > 65535 {
		return xrayInbound{}, fmt.Errorf("dokodemo-door inbound: bad port %d", o.Port)
	}
	return xrayInbound{
		Listen:   "0.0.0.0",
		Port:     o.Port,
		Protocol: "dokodemo-door",
		Settings: map[string]any{
			"network":        "tcp,udp",
			"followRedirect": true,
		},
		Tag: "transparent-in",
	}, nil
}

func buildOutbound(p Profile, xhttpMode string, sidecarSOCKS int) (xrayOutbound, error) {
	// Protocol == "naive" doesn't speak vless at all -- its egress is a
	// separate `naive` process (internal/naivecore + the process manager
	// in internal/failover) that does the actual censorship-resistant
	// HTTP/2 CONNECT hop. xray's own outbound is just a plain socks
	// client pointed at that local sidecar; everything below this branch
	// (vnext/UUID/streamSettings) is vless-only and does not apply.
	if p.Protocol == "naive" {
		if sidecarSOCKS == 0 {
			return xrayOutbound{}, fmt.Errorf("profile %q: naive egress requires a running sidecar (SidecarSOCKS not set)", p.Remark)
		}
		return xrayOutbound{
			Tag:      "proxy",
			Protocol: "socks",
			Settings: map[string]any{
				"servers": []map[string]any{
					{"address": "127.0.0.1", "port": sidecarSOCKS},
				},
			},
		}, nil
	}

	// Protocol == "amneziawg" -- also doesn't speak vless: a direct
	// `wireguard` outbound on the vendored, AmneziaWG-patched xray-core
	// (see packaging/xray-core/amneziawg-<tag>.patch,
	// docs/HANDOFF-amneziawg.md). No sidecar, no second process -- unlike
	// naive above, the patched binary this project already ships
	// understands AWG's obfuscation fields directly.
	if p.Protocol == "amneziawg" {
		return buildAmneziaWGOutbound(p)
	}

	user := map[string]any{
		"id":         p.UUID,
		"encryption": firstNonEmpty(p.Encryption, "none"),
	}
	if p.Flow != "" {
		user["flow"] = p.Flow
	}

	settings := map[string]any{
		"vnext": []map[string]any{
			{
				"address": p.Address,
				"port":    p.Port,
				"users":   []map[string]any{user},
			},
		},
	}

	stream, err := buildStreamSettings(p, xhttpMode)
	if err != nil {
		return xrayOutbound{}, err
	}

	return xrayOutbound{
		Tag:            "proxy",
		Protocol:       "vless",
		Settings:       settings,
		StreamSettings: stream,
	}, nil
}

// buildAmneziaWGOutbound builds a direct `wireguard` outbound for an
// AmneziaWG profile. Field spellings here must match
// infra/conf/wireguard.go's own json tags in the vendored patch exactly
// (confirmed camelCase, e.g. "headerProtectionKey", "remoteDNS") -- this
// project defined that spelling itself when writing the patch (see
// docs/HANDOFF-amneziawg.md), so buildOutbound and the patch have to
// agree, not follow some external spec. Every AWG obfuscation field is
// relayed exactly as ParseAmneziaWGURI stored it -- see
// AmneziaWGParams' own doc comment for why nothing here parses or
// reinterprets any of them.
func buildAmneziaWGOutbound(p Profile) (xrayOutbound, error) {
	a := p.AWG
	if a == nil {
		return xrayOutbound{}, fmt.Errorf("profile %q: amneziawg egress requires AWG parameters", p.Remark)
	}

	peer := map[string]any{
		"publicKey": a.PeerPublicKey,
		"endpoint":  net.JoinHostPort(p.Address, strconv.Itoa(p.Port)),
	}
	if a.PresharedKey != "" {
		peer["preSharedKey"] = a.PresharedKey
	}
	if len(a.AllowedIPs) > 0 {
		peer["allowedIPs"] = a.AllowedIPs
	}
	if a.PersistentKeepalive > 0 {
		peer["keepAlive"] = a.PersistentKeepalive
	}

	settings := map[string]any{
		"IsClient":  true,
		"secretKey": a.PrivateKey,
		"peers":     []map[string]any{peer},
	}
	if a.Address != "" {
		settings["address"] = []string{a.Address}
	}
	if len(a.DNS) > 0 {
		settings["remoteDNS"] = a.DNS
	}
	if a.MTU > 0 {
		settings["mtu"] = a.MTU
	}
	for jsonKey, v := range map[string]string{
		"jc": a.Jc, "jmin": a.Jmin, "jmax": a.Jmax,
		"s1": a.S1, "s2": a.S2, "s3": a.S3, "s4": a.S4,
		"h1": a.H1, "h2": a.H2, "h3": a.H3, "h4": a.H4,
		"i1": a.I1, "i2": a.I2, "i3": a.I3, "i4": a.I4, "i5": a.I5,
		"headerProtectionKey":    a.HeaderProtectionKey,
		"contentPaddingAddition": a.ContentPaddingAddition,
		"rekeyAfterTime":         a.RekeyAfterTime,
		"rekeyTimeout":           a.RekeyTimeout,
		"rejectAfterTime":        a.RejectAfterTime,
		"keepaliveTimeout":       a.KeepaliveTimeout,
		"maxHandshakeAttempts":   a.MaxHandshakeAttempts,
		"randomTrailers":         a.RandomTrailers,
		"disableCookies":         a.DisableCookies,
	} {
		if v != "" {
			settings[jsonKey] = v
		}
	}

	return xrayOutbound{
		Tag:      "proxy",
		Protocol: "wireguard",
		Settings: settings,
	}, nil
}

func buildStreamSettings(p Profile, xhttpMode string) (map[string]any, error) {
	stream := map[string]any{
		"network": p.Network,
	}

	switch p.Security {
	case "none":
		stream["security"] = "none"
	case "tls":
		tlsSettings := map[string]any{}
		if p.SNI != "" {
			tlsSettings["serverName"] = p.SNI
		}
		if p.Fingerprint != "" {
			tlsSettings["fingerprint"] = p.Fingerprint
		}
		if len(p.ALPN) > 0 {
			tlsSettings["alpn"] = p.ALPN
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tlsSettings
	case "reality":
		realitySettings := map[string]any{
			"publicKey": p.PublicKey,
			"shortId":   p.ShortID,
		}
		if p.SNI != "" {
			realitySettings["serverName"] = p.SNI
		}
		if p.Fingerprint != "" {
			realitySettings["fingerprint"] = p.Fingerprint
		}
		if p.SpiderX != "" {
			realitySettings["spiderX"] = p.SpiderX
		}
		stream["security"] = "reality"
		stream["realitySettings"] = realitySettings
	default:
		return nil, fmt.Errorf("unsupported security %q", p.Security)
	}

	switch p.Network {
	case "tcp":
		if p.HeaderType != "" && p.HeaderType != "none" {
			stream["tcpSettings"] = map[string]any{
				"header": map[string]any{"type": p.HeaderType},
			}
		}
	case "ws":
		wsSettings := map[string]any{}
		if p.Path != "" {
			wsSettings["path"] = p.Path
		}
		if p.Host != "" {
			wsSettings["headers"] = map[string]any{"Host": p.Host}
		}
		stream["wsSettings"] = wsSettings
	case "grpc":
		svc := firstNonEmpty(p.ServiceName, p.Path)
		if svc == "" {
			return nil, fmt.Errorf("grpc network requires a serviceName or path")
		}
		stream["grpcSettings"] = map[string]any{"serviceName": svc}
	case "xhttp":
		// Seed from the share link's `extra` blob (xmux + sc* + padding
		// tuning) so those keys reach xray verbatim; then the dedicated
		// path/host/mode fields win over anything `extra` also carried.
		xhttpSettings := map[string]any{}
		if len(p.XHTTPExtra) > 0 {
			var extra map[string]any
			if err := json.Unmarshal(p.XHTTPExtra, &extra); err != nil {
				return nil, fmt.Errorf("xhttp_extra: %w", err)
			}
			for k, v := range extra {
				xhttpSettings[k] = v
			}
		}
		if p.Path != "" {
			xhttpSettings["path"] = p.Path
		}
		if p.Host != "" {
			xhttpSettings["host"] = p.Host
		}
		mode := p.Mode
		if xhttpMode != "" {
			mode = xhttpMode // Config.XHTTPMode global override
		}
		if mode != "" {
			xhttpSettings["mode"] = mode
		}
		stream["xhttpSettings"] = xhttpSettings
	default:
		return nil, fmt.Errorf("unsupported network %q", p.Network)
	}

	return stream, nil
}

type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayLog struct {
	LogLevel string `json:"loglevel"`
}

type xrayInbound struct {
	Listen   string         `json:"listen"`
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings"`
	Tag      string         `json:"tag"`
}

type xrayOutbound struct {
	Tag            string         `json:"tag"`
	Protocol       string         `json:"protocol"`
	Settings       map[string]any `json:"settings,omitempty"`
	StreamSettings map[string]any `json:"streamSettings,omitempty"`
}
