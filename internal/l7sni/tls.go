package l7sni

import (
	"encoding/binary"
	"strings"
)

// tlsRecordHeaderLen is TLSPlaintext's own header: ContentType(1) +
// legacy_record_version(2) + length(2).
const tlsRecordHeaderLen = 5

// IsTLSClientHello reports whether data starts with a TLS handshake
// record (ContentType 0x16) whose first handshake message is a
// ClientHello (msg_type 0x01) -- true as soon as enough bytes have
// arrived to tell, even if the record itself is still incomplete.
func IsTLSClientHello(data []byte) bool {
	return len(data) >= 11 &&
		data[0] == 0x16 && // ContentType: handshake
		data[1] == 0x03 && // legacy_record_version major: SSL/TLS 3.x family
		data[5] == 0x01 // Handshake.msg_type: client_hello
}

// TLSRecordLen returns the outer TLSPlaintext record's total length --
// its own 5-byte header plus the `length` field it declares -- so a
// caller buffering a ClientHello split across TCP segments knows how
// many bytes to wait for before calling ExtractTLSSNI again. Only
// meaningful once IsTLSClientHello(data) is true.
func TLSRecordLen(data []byte) int {
	return int(binary.BigEndian.Uint16(data[3:5])) + tlsRecordHeaderLen
}

// ExtractTLSSNI parses a complete TLS record carrying a ClientHello and
// returns the hostname from its server_name extension, lowercased. ok is
// false if data isn't a (complete) ClientHello, or it has no
// server_name extension at all -- SNI is optional in the protocol, a
// client connecting straight to an IP with no hostname simply won't send
// one.
//
// Handles exactly one TLS record holding the whole ClientHello handshake
// message -- real clients always send it that way (a real client never
// splits ClientHello itself across multiple *TLS records*, only
// possibly across multiple *TCP segments*, which is a transport-layer
// concern the caller's reassembly buffer handles before calling this).
func ExtractTLSSNI(data []byte) (host string, ok bool) {
	if !IsTLSClientHello(data) {
		return "", false
	}
	reclen := TLSRecordLen(data)
	if reclen > len(data) {
		return "", false // still incomplete -- caller keeps buffering
	}
	data = data[:reclen]

	hs := data[tlsRecordHeaderLen:] // Handshake: msg_type(1) + length(3) + body
	if len(hs) < 4 {
		return "", false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if len(body) < hsLen {
		return "", false
	}
	body = body[:hsLen]

	ext, ok := clientHelloExtensions(body)
	if !ok {
		return "", false
	}
	return findServerName(ext)
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

const extTypeServerName = 0

// findServerName walks a ClientHello's extensions block looking for
// server_name (type 0) and hands its data off to parseServerNameList.
func findServerName(ext []byte) (string, bool) {
	for len(ext) >= 4 {
		etype := binary.BigEndian.Uint16(ext[0:2])
		elen := int(binary.BigEndian.Uint16(ext[2:4]))
		ext = ext[4:]
		if len(ext) < elen {
			return "", false
		}
		data := ext[:elen]
		ext = ext[elen:]
		if etype == extTypeServerName {
			return parseServerNameList(data)
		}
	}
	return "", false
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
			return strings.ToLower(string(name)), true
		}
	}
	return "", false
}
