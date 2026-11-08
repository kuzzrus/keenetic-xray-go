package l7sni

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// QUIC Initial packets: reading the ClientHello out of a client's first
// flight.
//
// A QUIC client's first packets are protected, but not secret: the keys come
// from the packet's own Destination Connection ID and a salt that is a
// constant of the protocol version (RFC 9001 section 5.2; RFC 9369 for
// version 2). Anyone on the path can derive them, which is what makes the
// SNI of an HTTP/3 connection readable to a router the same way it is on
// TCP -- unless the ClientHello uses Encrypted Client Hello, in which case
// only the public name is visible (see ClientHelloInfo.ECH).
//
// Written from the RFCs and checked against their Appendix A vectors
// (quic_vectors_test.go); HydraRoute Neo's QUIC path (AGPL-3.0) was read
// for what to cover -- version 2, every CRYPTO frame in any order, a
// ClientHello spanning several datagrams -- and not for its code.

const (
	// QUICVersion1 is QUIC version 1 (RFC 9000).
	QUICVersion1 uint32 = 0x00000001
	// QUICVersion2 is QUIC version 2 (RFC 9369).
	QUICVersion2 uint32 = 0x6b3343cf
)

// Initial salts: RFC 9001 section 5.2 (v1) and RFC 9369 section 3.3.1 (v2).
var (
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
)

// QUICStatus says how far ParseQUICInitial got. Everything but QUICOK is a
// reason the datagram yielded nothing; the capture loop counts them apart so
// "QUIC is invisible here" can be told from "QUIC is here but it is not v1".
type QUICStatus uint8

const (
	// QUICOK: an Initial packet whose payload decrypted and parsed.
	QUICOK QUICStatus = iota
	// QUICNotInitial: valid-looking QUIC, but not a v1/v2 client Initial --
	// a short-header packet, 0-RTT, Handshake, Retry, or something that is
	// not QUIC at all (the capture filter passes any UDP/443 datagram of
	// 1200+ bytes).
	QUICNotInitial
	// QUICUnsupportedVersion: a long header carrying a version whose keys
	// we cannot derive -- a draft version, version negotiation (0), or a
	// future one.
	QUICUnsupportedVersion
	// QUICMalformed: the header or the frames do not hold together.
	QUICMalformed
	// QUICAuthFailed: keys derived, but the AEAD tag did not verify -- not
	// an Initial for this Destination Connection ID, or damaged.
	QUICAuthFailed
)

// CryptoFragment is one CRYPTO frame's slice of the handshake byte stream.
type CryptoFragment struct {
	Offset uint64
	Data   []byte
}

// QUICInitial is what one Initial datagram gave up.
type QUICInitial struct {
	Version   uint32
	Fragments []CryptoFragment
}

// ParseQUICInitial decrypts the first packet of a UDP datagram, if it is a
// QUIC v1/v2 Initial, and returns the CRYPTO fragments inside it. Coalesced
// packets after the first are ignored: a client's Initial comes first.
//
// The AEAD tag is verified, so a datagram that merely looks like an Initial
// cannot feed garbage to the ClientHello parser.
func ParseQUICInitial(p []byte) (QUICInitial, QUICStatus) {
	var out QUICInitial
	if len(p) < 7 || p[0]&0x80 == 0 {
		return out, QUICNotInitial // short header, or too small to be anything
	}
	version := binary.BigEndian.Uint32(p[1:5])
	var initialType byte
	switch version {
	case QUICVersion1:
		initialType = 0
	case QUICVersion2:
		initialType = 1
	default:
		return out, QUICUnsupportedVersion
	}
	if p[0]&0x40 == 0 || (p[0]>>4)&0x03 != initialType {
		return out, QUICNotInitial
	}
	out.Version = version

	pos := 5
	dcil := int(p[pos])
	pos++
	if dcil > 20 || len(p) < pos+dcil+1 {
		return out, QUICMalformed
	}
	dcid := p[pos : pos+dcil]
	pos += dcil
	scil := int(p[pos])
	pos++
	if scil > 20 || len(p) < pos+scil {
		return out, QUICMalformed
	}
	pos += scil

	tokenLen, n := readVarint(p[pos:])
	if n == 0 || tokenLen > uint64(len(p)-pos-n) {
		return out, QUICMalformed
	}
	pos += n + int(tokenLen)

	length, n := readVarint(p[pos:])
	if n == 0 {
		return out, QUICMalformed
	}
	pos += n
	// The header protection sample is 16 bytes taken 4 bytes past the start
	// of the packet number, so a packet shorter than 20 cannot be unmasked.
	if length < 20 || length > uint64(len(p)-pos) {
		return out, QUICMalformed
	}
	pnOffset := pos
	end := pnOffset + int(length)

	key, iv, hp, err := initialKeys(version, dcid)
	if err != nil {
		return out, QUICMalformed
	}

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return out, QUICMalformed
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], p[pnOffset+4:pnOffset+20])

	first := p[0] ^ (mask[0] & 0x0f)
	pnLen := int(first&0x03) + 1
	if int(length) < pnLen+16 { // packet number plus the 16-byte tag
		return out, QUICMalformed
	}

	// The AAD is the header as the sender wrote it, i.e. unmasked.
	hdr := make([]byte, pnOffset+pnLen)
	copy(hdr, p[:pnOffset+pnLen])
	hdr[0] = first
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := 0; i < pnLen; i++ {
		hdr[pnOffset+i] ^= mask[1+i]
		nonce[len(nonce)-pnLen+i] ^= hdr[pnOffset+i]
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return out, QUICMalformed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return out, QUICMalformed
	}
	plain, err := aead.Open(nil, nonce, p[pnOffset+pnLen:end], hdr)
	if err != nil {
		return out, QUICAuthFailed
	}

	frags, ok := cryptoFragments(plain)
	out.Fragments = frags
	if !ok {
		return out, QUICMalformed
	}
	return out, QUICOK
}

// initialKeys derives the client's Initial packet protection keys for a
// Destination Connection ID (RFC 9001 section 5.1, RFC 9369 section 3.3.2).
func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte, err error) {
	salt := quicSaltV1
	keyLabel, ivLabel, hpLabel := "quic key", "quic iv", "quic hp"
	if version == QUICVersion2 {
		salt = quicSaltV2
		keyLabel, ivLabel, hpLabel = "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	secret, err := expandLabel(initial, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	if key, err = expandLabel(secret, keyLabel, 16); err != nil {
		return nil, nil, nil, err
	}
	if iv, err = expandLabel(secret, ivLabel, 12); err != nil {
		return nil, nil, nil, err
	}
	if hp, err = expandLabel(secret, hpLabel, 16); err != nil {
		return nil, nil, nil, err
	}
	return key, iv, hp, nil
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context
// (RFC 8446 section 7.1): the HkdfLabel struct is the output length, the
// label prefixed with "tls13 ", and the (empty) context, each length-
// prefixed.
func expandLabel(secret []byte, label string, n int) ([]byte, error) {
	full := "tls13 " + label
	info := make([]byte, 0, 2+1+len(full)+1)
	info = binary.BigEndian.AppendUint16(info, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}

// cryptoFragments walks the frames of a decrypted Initial payload and
// returns every CRYPTO frame in the order it appears, each with its own copy
// of the data. A client Initial may carry only PADDING, PING, ACK, CRYPTO and
// CONNECTION_CLOSE (RFC 9000 section 12.4), so the first frame of any other
// type ends the walk. ok is false when a frame it did recognise was cut off.
//
// Every CRYPTO frame is taken, not just the first: Chrome splits its
// ClientHello over several CRYPTO frames in any order, mixed with PADDING and
// PING, and an ACK can precede them.
func cryptoFragments(plain []byte) (frags []CryptoFragment, ok bool) {
	pos := 0
	skip := func(count int) bool { // count varints
		for i := 0; i < count; i++ {
			_, n := readVarint(plain[pos:])
			if n == 0 {
				return false
			}
			pos += n
		}
		return true
	}
	for pos < len(plain) {
		ftype, n := readVarint(plain[pos:])
		if n == 0 {
			return frags, false
		}
		pos += n
		switch ftype {
		case 0x00, 0x01: // PADDING, PING
		case 0x02, 0x03: // ACK, ACK_ECN
			// Largest Acknowledged, ACK Delay, ACK Range Count, First ACK
			// Range -- then Range Count (Gap, ACK Range) pairs, and for the
			// ECN variant three more counts. Walked in full rather than
			// given up on, so a CRYPTO frame that follows the ACK is found.
			if !skip(2) {
				return frags, false
			}
			rangeCount, n := readVarint(plain[pos:])
			if n == 0 {
				return frags, false
			}
			pos += n
			if !skip(1) { // First ACK Range
				return frags, false
			}
			// A count the payload cannot possibly hold is damage; bounding
			// it also keeps a hostile value from turning this into a loop.
			if rangeCount > uint64(len(plain)) || !skip(2*int(rangeCount)) {
				return frags, false
			}
			if ftype == 0x03 && !skip(3) {
				return frags, false
			}
		case 0x06: // CRYPTO
			off, n := readVarint(plain[pos:])
			if n == 0 {
				return frags, false
			}
			pos += n
			length, n := readVarint(plain[pos:])
			if n == 0 || length > uint64(len(plain)-pos-n) {
				return frags, false
			}
			pos += n
			data := make([]byte, length)
			copy(data, plain[pos:pos+int(length)])
			pos += int(length)
			frags = append(frags, CryptoFragment{Offset: off, Data: data})
		default: // CONNECTION_CLOSE or anything a client Initial may not carry
			return frags, true
		}
	}
	return frags, true
}

// readVarint decodes a QUIC variable-length integer (RFC 9000 section 16).
// n is the number of bytes consumed, 0 if b is too short.
func readVarint(b []byte) (v uint64, n int) {
	if len(b) == 0 {
		return 0, 0
	}
	n = 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0
	}
	v = uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n
}
