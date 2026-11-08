package l7sni

import "encoding/binary"

// ClientHelloInfo is what a TLS ClientHello gives away without any
// decryption: the name it asks for and whether it carries an Encrypted
// Client Hello extension.
type ClientHelloInfo struct {
	// Host is the server_name, lowercased and validated (see
	// normalizeHostname). Empty when the ClientHello has no usable
	// server_name: SNI is optional, and a client connecting straight to an
	// IP sends none.
	Host string

	// ECH reports an encrypted_client_hello extension (0xfe0d) in this
	// ClientHello. Read it with care: browsers send a *GREASE* ECH
	// extension to servers that publish no ECH configuration, precisely so
	// the extension is not a tell, and then Host is still the real name.
	// With genuine ECH the visible Host is only the client-facing server's
	// public name (cloudflare-ech.com for Cloudflare's customers) and the
	// real one is encrypted. The two cannot be told apart from this packet
	// alone, so ECH=true means "the real name may be hidden", not "is".
	ECH bool
}

const (
	extTypeServerName           = 0x0000
	extTypeEncryptedClientHello = 0xfe0d
)

// ParseClientHello reads a ClientHello handshake message -- msg_type (1),
// a 3-byte length, then the body -- the way it starts both inside a TLS
// record and at the head of a QUIC CRYPTO stream. ok is false when hs is
// not (all of) a ClientHello or its extensions block cannot be reached.
// It does not require a server_name: a ClientHello without one parses to
// an empty Host.
func ParseClientHello(hs []byte) (ClientHelloInfo, bool) {
	if len(hs) < 4 || hs[0] != 0x01 {
		return ClientHelloInfo{}, false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs)-4 < hsLen {
		return ClientHelloInfo{}, false // still incomplete -- caller keeps buffering
	}
	ext, ok := clientHelloExtensions(hs[4 : 4+hsLen])
	if !ok {
		return ClientHelloInfo{}, false
	}
	return scanExtensions(ext), true
}

// clientHelloExtensions walks past ClientHello's fixed and variable-
// length-prefixed fields -- legacy_version, random, legacy_session_id,
// cipher_suites, legacy_compression_methods -- to the start of its
// extensions block, and returns just that block (its own 2-byte length
// prefix already consumed, so callers only ever see extension entries).
func clientHelloExtensions(body []byte) ([]byte, bool) {
	// legacy_version(2) + random(32)
	if len(body) < 34 {
		return nil, false
	}
	pos := 34

	// legacy_session_id<0..32>: 1-byte length prefix
	if len(body) < pos+1 {
		return nil, false
	}
	pos += 1 + int(body[pos])
	if len(body) < pos {
		return nil, false
	}

	// cipher_suites<2..2^16-2>: 2-byte length prefix
	if len(body) < pos+2 {
		return nil, false
	}
	pos += 2 + int(binary.BigEndian.Uint16(body[pos:pos+2]))
	if len(body) < pos {
		return nil, false
	}

	// legacy_compression_methods<1..2^8-1>: 1-byte length prefix
	if len(body) < pos+1 {
		return nil, false
	}
	pos += 1 + int(body[pos])
	if len(body) < pos {
		return nil, false
	}

	// extensions<8..2^16-1>: 2-byte length prefix. Absent entirely on a
	// truly ancient client (pos == len(body)) -- that's just "no SNI",
	// not a parse error, so this returns ok=false via the length check
	// below rather than panicking.
	if len(body) < pos+2 {
		return nil, false
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if len(body) < pos+extLen {
		return nil, false
	}
	return body[pos : pos+extLen], true
}

// scanExtensions walks the extensions block once, picking out server_name
// and the ECH marker. A block that turns out truncated part-way keeps what
// was found before the damage.
func scanExtensions(ext []byte) ClientHelloInfo {
	var info ClientHelloInfo
	sawHost := false
	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if len(ext) < elen {
			break
		}
		data := ext[:elen]
		ext = ext[elen:]
		switch etype {
		case extTypeServerName:
			if !sawHost { // the first server_name wins
				sawHost = true
				info.Host, _ = parseServerNameList(data)
			}
		case extTypeEncryptedClientHello:
			info.ECH = true
		}
	}
	return info
}

const nameTypeHostName = 0

// parseServerNameList reads the first host_name entry out of a
// server_name extension's ServerNameList. TLS allows more than one
// entry in principle; every real client sends exactly one, so the first
// host_name found is returned.
func parseServerNameList(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		return "", false
	}
	data = data[:listLen]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return "", false
		}
		name := data[:nameLen]
		data = data[nameLen:]
		if nameType == nameTypeHostName {
			return normalizeHostname(string(name))
		}
	}
	return "", false
}
