package l7sni

import "strings"

// maxHostnameLen is the longest a DNS name can be in presentation form
// (RFC 1035: 255 octets on the wire, 253 as text without the root dot).
const maxHostnameLen = 253

// normalizeHostname lowercases a name taken off the wire, drops one
// trailing dot and reports whether what is left is usable as a hostname:
// 1..253 bytes of [a-z0-9._-]. Anything else -- a stray byte, an IPv6
// literal in a Host header, a name cut off mid-way -- is rejected rather
// than repaired, because the name goes into log lines, the bot and a
// suffix match against the operator's route lists: a truncated "chat"
// where "chatgpt.com" was meant would match the wrong list, and a name
// carrying a newline or a terminal escape would be written into the log
// verbatim (the SNI and the Host header are chosen by whoever sends the
// packet, not by us).
//
// Same rule HydraRoute Neo applies to every name its L7 channel extracts
// (host_copy); the character set is its, the reasoning is spelled out
// here because it is the part that matters for a log that people read.
func normalizeHostname(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || len(s) > maxHostnameLen {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			return "", false
		}
	}
	return s, true
}
