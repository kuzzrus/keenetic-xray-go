package keenetic

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// This file turns two more RCI reads into the exact indented `key: value`
// text their existing ndmc parsers expect, so `tryRead` can serve them
// over HTTP on firmware that fences off the ndmc binary:
//
//   show interface <iface>          -> /rci/show/interface/<iface>
//   show object-group fqdn <name>   -> /rci/show/object-group/fqdn/<name>
//
// The parsers on the other side (lanIPFromShowInterface,
// WGInterfacePublicKey, WGInterfaceUp, ShowWGTransport, objectGroupIPs)
// only ever do strings.Fields(line) and match on the first token, so the
// reformatters just need the right `key:` tokens in the right order --
// indentation and extra fields are ignored.

// interfaceTextFromRCI renders /rci/show/interface/<iface> JSON as
// `show interface` text. RCI may return the interface object bare or
// wrapped as {"<iface>": {...}}; both are handled.
func interfaceTextFromRCI(b []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return "", fmt.Errorf("show interface: RCI JSON: %w", err)
	}
	m := unwrapInterface(top)

	var sb strings.Builder
	emit := func(key string) {
		if raw, ok := m[key]; ok {
			if s := scalarString(raw); s != "" {
				fmt.Fprintf(&sb, "%s: %s\n", key, s)
			}
		}
	}
	// The flat fields the parsers read (state, mtu, address) plus the
	// context ones a human summary shows.
	for _, k := range []string{
		"id", "index", "type", "description", "interface-name",
		"link", "connected", "state", "mtu", "address", "mask", "uptime",
	} {
		emit(k)
	}

	// WireGuard sub-block: `wireguard:` then the interface `public-key:`,
	// then each `peer:` with its fields. Order matters --
	// WGInterfacePublicKey wants the interface key seen after `wireguard:`
	// and before any `peer:`.
	if wgRaw, ok := m["wireguard"]; ok {
		var wg struct {
			PublicKey string                       `json:"public-key"`
			Peer      []map[string]json.RawMessage `json:"peer"`
		}
		if json.Unmarshal(wgRaw, &wg) == nil {
			sb.WriteString("wireguard:\n")
			if wg.PublicKey != "" {
				fmt.Fprintf(&sb, "  public-key: %s\n", wg.PublicKey)
			}
			for _, p := range wg.Peer {
				sb.WriteString("  peer:\n")
				for _, k := range []string{
					"public-key", "endpoint", "last-handshake",
					"online", "rxbytes", "txbytes",
				} {
					if raw, ok := p[k]; ok {
						if s := scalarString(raw); s != "" {
							fmt.Fprintf(&sb, "    %s: %s\n", k, s)
						}
					}
				}
			}
		}
	}

	// Nothing recognisable -> let ndmcRun fall through to exec.
	if _, hasState := m["state"]; !hasState {
		if _, hasAddr := m["address"]; !hasAddr {
			if _, hasID := m["id"]; !hasID {
				return "", fmt.Errorf("show interface: RCI response has none of state/address/id")
			}
		}
	}
	return sb.String(), nil
}

// unwrapInterface descends into {"<name>": {...}} when RCI wraps the
// interface object under its own name, so the caller always sees the
// field map directly.
func unwrapInterface(top map[string]json.RawMessage) map[string]json.RawMessage {
	// Already the interface object.
	for _, k := range []string{"state", "address", "id", "mtu", "wireguard"} {
		if _, ok := top[k]; ok {
			return top
		}
	}
	// Exactly one key whose value is a JSON object -> descend.
	if len(top) == 1 {
		for _, raw := range top {
			var inner map[string]json.RawMessage
			if json.Unmarshal(raw, &inner) == nil && len(inner) > 0 {
				return inner
			}
		}
	}
	return top
}

// scalarString renders a JSON scalar the way ndmc text would: strings
// verbatim, integers without a decimal point, bools as yes/no. Anything
// else (objects, arrays, null) yields "".
func scalarString(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "yes"
		}
		return "no"
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}

// objectGroupTextFromRCI renders /rci/show/object-group/fqdn/<name> JSON
// as `show object-group fqdn` text: one resolved IPv4 per line.
// objectGroupIPs on the other side just harvests dotted-quads, so we
// walk the whole structure, collect every IPv4 string not under an
// "excluded-*" key, de-dup, and emit them. Valid JSON with zero
// addresses is still "handled" (an unresolved group legitimately has
// none) -- only a parse failure falls through to ndmc.
func objectGroupTextFromRCI(b []byte) (string, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("show object-group: RCI JSON: %w", err)
	}
	seen := map[string]bool{}
	var ips []string
	var walk func(node any, excluded bool)
	walk = func(node any, excluded bool) {
		switch n := node.(type) {
		case string:
			if !excluded && isDottedQuadV4(n) && !seen[n] {
				seen[n] = true
				ips = append(ips, n)
			}
		case []any:
			for _, e := range n {
				walk(e, excluded)
			}
		case map[string]any:
			for k, e := range n {
				walk(e, excluded || strings.Contains(strings.ToLower(k), "exclud"))
			}
		}
	}
	walk(v, false)
	sort.Strings(ips)
	if len(ips) == 0 {
		return "", nil
	}
	return strings.Join(ips, "\n") + "\n", nil
}

// isDottedQuadV4 reports whether s is a bare IPv4 dotted-quad (no CIDR,
// no port).
func isDottedQuadV4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && strings.Count(s, ".") == 3 && !strings.ContainsAny(s, ":/")
}
