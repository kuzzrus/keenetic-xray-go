package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseNaiveURI parses a "naive+<scheme>://user:pass@host:port#remark"
// share link into a Profile with Protocol "naive". This is the share-link
// convention the wider ecosystem (sing-box, NekoBox, ...) uses for naive
// endpoints: the outer scheme names the egress (naive), the inner one
// (after "+") is the proxy URI scheme naive itself understands --
// "https" is the only one this build supports (naive's default, HTTP/2
// CONNECT + Chrome TLS + padding); "quic" (HTTP/3) and plaintext "http"
// are rejected with a clear reason rather than silently mishandled.
//
// naive has no UUID or transport/REALITY settings -- SNI is set to the
// host, matching what a bare naive client config with no explicit
// host-resolver-rules override does. Only the fields internal/naivecore's
// egress needs are populated; see the Protocol doc on Profile.
func ParseNaiveURI(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Profile{}, fmt.Errorf("parsing naive URI: %w", err)
	}
	outer, inner, ok := strings.Cut(u.Scheme, "+")
	if !ok || outer != "naive" {
		return Profile{}, fmt.Errorf("not a naive+<scheme>:// URI (scheme %q)", u.Scheme)
	}
	switch inner {
	case "https":
		// supported
	case "quic":
		return Profile{}, fmt.Errorf("naive+quic:// (HTTP/3) is not supported yet -- use naive+https://")
	case "http":
		return Profile{}, fmt.Errorf("naive+http:// is plaintext to the proxy -- not supported, use naive+https://")
	default:
		return Profile{}, fmt.Errorf("unsupported naive proxy scheme %q", inner)
	}

	if u.User == nil || u.User.Username() == "" {
		return Profile{}, fmt.Errorf("missing user (userinfo) in naive URI")
	}
	password, _ := u.User.Password()
	if password == "" {
		return Profile{}, fmt.Errorf("missing password in naive URI")
	}
	if u.Hostname() == "" {
		return Profile{}, fmt.Errorf("missing host in naive URI")
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return Profile{}, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
	}

	profile := Profile{
		Remark:   u.Fragment, // net/url percent-decodes this already
		Protocol: "naive",
		Address:  u.Hostname(),
		Port:     port,
		SNI:      u.Hostname(),
		User:     u.User.Username(),
		Password: password,
	}
	if profile.Remark == "" {
		profile.Remark = profile.Address
	}
	return profile, nil
}
