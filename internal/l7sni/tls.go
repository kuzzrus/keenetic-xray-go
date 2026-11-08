package l7sni

import "encoding/binary"

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
// false if data isn't a (complete) ClientHello, or it has no (valid)
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
	info, ok := ExtractTLSInfo(data)
	if !ok || info.Host == "" {
		return "", false
	}
	return info.Host, true
}

// ExtractTLSInfo is ExtractTLSSNI plus the ECH marker: ok is true for any
// complete ClientHello whose extensions parse, with an empty Host when it
// carries no usable server_name. See ClientHelloInfo.ECH for what the
// marker does and does not tell.
func ExtractTLSInfo(data []byte) (ClientHelloInfo, bool) {
	if !IsTLSClientHello(data) {
		return ClientHelloInfo{}, false
	}
	reclen := TLSRecordLen(data)
	if reclen > len(data) {
		return ClientHelloInfo{}, false // still incomplete -- caller keeps buffering
	}
	return ParseClientHello(data[tlsRecordHeaderLen:reclen])
}
