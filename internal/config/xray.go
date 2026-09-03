package config

import (
	"encoding/json"
	"fmt"
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
// Xray's default when nothing else matches) carries all traffic.
// Whole-LAN redirection to the local inbound is Keenetic's own
// Policy-Based Routing, outside this project's scope.
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

	outbound, err := buildOutbound(opts.Outbound)
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

func buildOutbound(p Profile) (xrayOutbound, error) {
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

	stream, err := buildStreamSettings(p)
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

func buildStreamSettings(p Profile) (map[string]any, error) {
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
		stream["grpcSettings"] = map[string]any{
			"serviceName": firstNonEmpty(p.ServiceName, p.Path),
		}
	case "h2", "http":
		stream["network"] = "http" // Xray's canonical name; some share links say "h2"
		httpSettings := map[string]any{}
		if p.Path != "" {
			httpSettings["path"] = p.Path
		}
		if p.Host != "" {
			httpSettings["host"] = []string{p.Host}
		}
		stream["httpSettings"] = httpSettings
	case "xhttp":
		xhttpSettings := map[string]any{}
		if p.Path != "" {
			xhttpSettings["path"] = p.Path
		}
		if p.Host != "" {
			xhttpSettings["host"] = p.Host
		}
		if p.Mode != "" {
			xhttpSettings["mode"] = p.Mode
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
