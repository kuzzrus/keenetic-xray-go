// Package l7sni reads the real destination hostname directly off the
// wire -- a TLS ClientHello's server_name extension, or a plaintext
// HTTP/1.x request's Host header -- for traffic this project's DNS-based
// routing (internal/config's routes/presets) structurally cannot see:
// DoH/DoT clients that resolve entirely outside the router, and apps
// with a hardcoded destination IP and no DNS lookup at all. It's also a
// precise alternative to internal/classifier's ClrBlockPromote guessing
// a destination's identity from IP-range membership (known ranges,
// naive /24s) -- knowing the actual SNI means never having to guess.
//
// QUIC is deliberately out of scope: a QUIC Initial packet's ClientHello
// is wrapped in a real (if publicly-derivable) AEAD encryption keyed off
// the connection ID and the negotiated QUIC version, and Encrypted
// Client Hello (ECH, increasingly deployed by Cloudflare and some Google
// properties) hides the SNI behind a decoy name entirely -- both add
// real, open-ended maintenance cost and a hard blind spot this package
// doesn't take on. See the [[hydraroute-comparison]] memory for the
// research this package's technique is modeled on
// (Ground-Zerro/HydraRoute Neo's own L7 detector).
//
// This package is pure parsing logic -- no sockets, no iptables, no
// netlink -- same "decide, don't touch the system" split this project
// uses throughout (see internal/classifier's own package doc comment).
// The caller (an NFLOG capture loop, not implemented here yet) owns
// getting raw packet bytes in and turning a matched hostname into an
// actual routing action.
package l7sni

import "encoding/binary"

// ParseIPv4 extracts the L4 protocol, addresses, ports, and payload from
// a raw IPv4 packet -- the shape NFLOG delivers (see nflog_capture in
// Ground-Zerro/HydraRoute Neo for the netlink side this project doesn't
// implement yet). IPv6 is out of scope, same as the rest of this
// project's adaptive-routing stack (internal/classifier, internal/
// adaptiveroute, internal/knownranges are all IPv4-only today).
//
// ok is false for anything this package has no use for: not IPv4, a
// truncated header, IP options present (rare for the TCP/UDP traffic
// this cares about, and correctly handling them isn't worth the extra
// surface), or a protocol other than TCP/UDP.
func ParseIPv4(pkt []byte) (proto uint8, src, dst [4]byte, sport, dport uint16, payload []byte, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, src, dst, 0, 0, nil, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return 0, src, dst, 0, 0, nil, false
	}
	proto = pkt[9]
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	l4 := pkt[ihl:]

	switch proto {
	case 6: // TCP
		if len(l4) < 20 {
			return 0, src, dst, 0, 0, nil, false
		}
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
		dataOff := int(l4[12]>>4) * 4
		if dataOff < 20 || len(l4) < dataOff {
			return 0, src, dst, 0, 0, nil, false
		}
		return proto, src, dst, sport, dport, l4[dataOff:], true
	case 17: // UDP
		if len(l4) < 8 {
			return 0, src, dst, 0, 0, nil, false
		}
		sport = binary.BigEndian.Uint16(l4[0:2])
		dport = binary.BigEndian.Uint16(l4[2:4])
		return proto, src, dst, sport, dport, l4[8:], true
	default:
		return 0, src, dst, 0, 0, nil, false
	}
}
