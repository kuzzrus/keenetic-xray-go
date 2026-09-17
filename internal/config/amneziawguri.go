package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ParseAmneziaWGURI decodes a vpn:// link -- AmneziaWG's own share-link
// format, "vpn://" + base64 of a wg-quick-style [Interface]/[Peer] .conf
// -- into a Profile. Confirmed against two real links from the user's own
// panel: the base64 alphabet isn't consistent (one used the standard
// alphabet, the other the URL-safe one, both unpadded), so decoding tries
// both. Comment lines ("#"-prefixed) and blank lines are skipped;
// anything else must be a "key = value" line inside [Interface] or
// [Peer]. Every AWG-specific obfuscation field is carried through as a
// plain string, verbatim, with no parsing or validation -- see
// AmneziaWGParams' own doc comment for why (some are plain integers, some
// are min-max ranges, I1-I5 are amneziawg-go's own byte-blob/random-fill
// notation, and the patched xray-core's own UAPI bridge already knows
// how to convert what needs converting -- see docs/HANDOFF-amneziawg.md).
func ParseAmneziaWGURI(raw string) (Profile, error) {
	const prefix = "vpn://"
	if !strings.HasPrefix(raw, prefix) {
		return Profile{}, fmt.Errorf("not a vpn:// link")
	}
	payload, err := decodeAmneziaWGPayload(strings.TrimPrefix(raw, prefix))
	if err != nil {
		return Profile{}, fmt.Errorf("amneziawg: invalid link: %w", err)
	}

	p := Profile{Protocol: "amneziawg", AWG: &AmneziaWGParams{}}
	section := ""
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch section {
		case "interface":
			applyAmneziaWGInterfaceField(&p, key, value)
		case "peer":
			applyAmneziaWGPeerField(&p, key, value)
		}
	}

	if p.AWG.PrivateKey == "" {
		return Profile{}, fmt.Errorf("amneziawg: link has no PrivateKey")
	}
	if p.AWG.PeerPublicKey == "" {
		return Profile{}, fmt.Errorf("amneziawg: link has no peer PublicKey")
	}
	if p.Address == "" {
		return Profile{}, fmt.Errorf("amneziawg: link has no peer Endpoint")
	}
	if p.Remark == "" {
		p.Remark = "AmneziaWG " + p.Address
	}
	return p, nil
}

// decodeAmneziaWGPayload decodes the base64 body of a vpn:// link. Real
// links have come back in both the standard and URL-safe alphabets, both
// without padding -- trims any padding that is present and tries both
// raw (unpadded) decoders rather than assuming one.
func decodeAmneziaWGPayload(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("not valid base64 (tried standard and URL-safe alphabets)")
}

// applyAmneziaWGInterfaceField dispatches one "key = value" line from a
// vpn:// link's [Interface] section. Address is the tunnel-internal
// client address (AWG.Address) -- not to be confused with Profile.Address
// below, which is the *server's* endpoint host (set from the [Peer]
// section's Endpoint, matching every other protocol's "which server"
// convention -- see ImportKey's own doc comment).
func applyAmneziaWGInterfaceField(p *Profile, key, value string) {
	a := p.AWG
	switch key {
	case "privatekey":
		a.PrivateKey = value
	case "address":
		a.Address = value
	case "dns":
		a.DNS = splitTrimmedCSV(value)
	case "mtu":
		if n, err := strconv.Atoi(value); err == nil {
			a.MTU = n
		}
	case "jc":
		a.Jc = value
	case "jmin":
		a.Jmin = value
	case "jmax":
		a.Jmax = value
	case "s1":
		a.S1 = value
	case "s2":
		a.S2 = value
	case "s3":
		a.S3 = value
	case "s4":
		a.S4 = value
	case "h1":
		a.H1 = value
	case "h2":
		a.H2 = value
	case "h3":
		a.H3 = value
	case "h4":
		a.H4 = value
	case "i1":
		a.I1 = value
	case "i2":
		a.I2 = value
	case "i3":
		a.I3 = value
	case "i4":
		a.I4 = value
	case "i5":
		a.I5 = value
	case "headerprotectionkey":
		a.HeaderProtectionKey = value
	case "contentpaddingaddition":
		a.ContentPaddingAddition = value
	case "rekeyaftertime":
		a.RekeyAfterTime = value
	case "rekeytimeout":
		a.RekeyTimeout = value
	case "rejectaftertime":
		a.RejectAfterTime = value
	case "keepalivetimeout":
		a.KeepaliveTimeout = value
	case "maxhandshakeattempts":
		a.MaxHandshakeAttempts = value
	case "randomtrailers":
		a.RandomTrailers = value
	case "disablecookies":
		a.DisableCookies = value
	}
}

// applyAmneziaWGPeerField dispatches one "key = value" line from a
// vpn:// link's [Peer] section.
func applyAmneziaWGPeerField(p *Profile, key, value string) {
	a := p.AWG
	switch key {
	case "publickey":
		a.PeerPublicKey = value
	case "presharedkey":
		a.PresharedKey = value
	case "allowedips":
		a.AllowedIPs = splitTrimmedCSV(value)
	case "endpoint":
		host, port, err := net.SplitHostPort(value)
		if err != nil {
			return
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return
		}
		p.Address = host
		p.Port = n
	case "persistentkeepalive":
		if n, err := strconv.Atoi(value); err == nil {
			a.PersistentKeepalive = n
		}
	}
}

// splitTrimmedCSV splits a comma-separated .conf value ("8.8.8.8, 8.8.4.4")
// into a trimmed, non-empty slice.
func splitTrimmedCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
