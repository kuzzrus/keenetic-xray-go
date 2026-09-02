package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseVLESSURI parses a single "vless://..." share link into a Profile.
// Only the fields this project needs to generate an Xray outbound are
// extracted; unrecognized query parameters are ignored rather than
// rejected, since providers vary in which optional fields they include.
func ParseVLESSURI(raw string) (Profile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Profile{}, fmt.Errorf("parsing vless URI: %w", err)
	}
	if u.Scheme != "vless" {
		return Profile{}, fmt.Errorf("not a vless:// URI (scheme %q)", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return Profile{}, fmt.Errorf("missing UUID (userinfo) in vless URI")
	}
	if u.Hostname() == "" {
		return Profile{}, fmt.Errorf("missing host in vless URI")
	}

	port := 443
	if portStr := u.Port(); portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return Profile{}, fmt.Errorf("invalid port %q: %w", portStr, err)
		}
	}

	q := u.Query()
	profile := Profile{
		Remark:     u.Fragment, // net/url percent-decodes this already
		UUID:       u.User.Username(),
		Address:    u.Hostname(),
		Port:       port,
		Encryption: firstNonEmpty(q.Get("encryption"), "none"),
		Flow:       q.Get("flow"),

		Network:  normalizeNetwork(firstNonEmpty(q.Get("type"), "tcp")),
		Security: firstNonEmpty(q.Get("security"), "none"),

		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		PublicKey:   q.Get("pbk"),
		ShortID:     q.Get("sid"),
		SpiderX:     q.Get("spx"),

		Path:        firstNonEmpty(q.Get("path"), q.Get("serviceName")),
		Host:        q.Get("host"),
		ServiceName: q.Get("serviceName"),
		HeaderType:  q.Get("headerType"),
		Mode:        q.Get("mode"),
	}
	if alpn := q.Get("alpn"); alpn != "" {
		profile.ALPN = strings.Split(alpn, ",")
	}
	if profile.Remark == "" {
		profile.Remark = profile.Address
	}
	return profile, nil
}

// URI formats a Profile back into a shareable "vless://..." link. It round
// trips every field ParseVLESSURI reads, but is not guaranteed to
// reproduce a provider's original link byte-for-byte (query parameter
// order and encoding may differ).
func (p Profile) URI() string {
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(p.UUID),
		Host:     fmt.Sprintf("%s:%d", p.Address, p.Port),
		Fragment: p.Remark,
	}

	q := url.Values{}
	q.Set("encryption", firstNonEmpty(p.Encryption, "none"))
	setIfNonEmpty(q, "flow", p.Flow)
	q.Set("type", firstNonEmpty(p.Network, "tcp"))
	q.Set("security", firstNonEmpty(p.Security, "none"))
	setIfNonEmpty(q, "sni", p.SNI)
	setIfNonEmpty(q, "fp", p.Fingerprint)
	setIfNonEmpty(q, "pbk", p.PublicKey)
	setIfNonEmpty(q, "sid", p.ShortID)
	setIfNonEmpty(q, "spx", p.SpiderX)
	setIfNonEmpty(q, "path", p.Path)
	setIfNonEmpty(q, "host", p.Host)
	setIfNonEmpty(q, "serviceName", p.ServiceName)
	setIfNonEmpty(q, "headerType", p.HeaderType)
	setIfNonEmpty(q, "mode", p.Mode)
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// normalizeNetwork maps share-link transport aliases onto the value Xray's
// config expects. "h2" is an older name some providers still emit for the
// HTTP/2 transport; Xray calls it "http".
func normalizeNetwork(n string) string {
	if n == "h2" {
		return "http"
	}
	return n
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func setIfNonEmpty(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}
