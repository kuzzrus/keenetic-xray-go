// Package l7snitest builds QUIC client Initial datagrams and TLS ClientHellos
// for the tests of code that consumes internal/l7sni. No non-test code
// imports it.
//
// The sealing here is written separately from internal/l7sni's own key
// derivation (RFC 9001 section 5, RFC 9369 section 3.3) on purpose: it is the
// sending side, and a test that decrypts what a second implementation
// produced says more than one that decrypts what the same code produced.
// TestBuildReproducesTheRFCPacket pins it to the RFC's own packet byte for
// byte.
package l7snitest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// QUIC versions with a known Initial salt.
const (
	Version1 uint32 = 0x00000001
	Version2 uint32 = 0x6b3343cf
)

// RFC9001DCID is the destination connection ID of the RFC's example packet.
var RFC9001DCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

// RFC9001ClientInitial returns the protected client Initial datagram of RFC
// 9001 appendix A.2: a ClientHello for example.com, 1200 bytes.
func RFC9001ClientInitial() []byte { return mustHex(rfc9001V1Packet) }

// Initial describes a client Initial packet for Datagram.
type Initial struct {
	Version uint32 // Version1 when zero
	DCID    []byte
	SCID    []byte
	Token   []byte
	PN      uint32
	PNLen   int    // bytes of packet number on the wire, 1..4; 4 when zero
	Frames  []byte // plaintext frames; zero-padded up to Len
	Len     int    // size of the packet; 1200 when zero
}

// Datagram seals the packet and returns it as it goes on the wire.
func (in Initial) Datagram() []byte {
	version, pnLen, size := in.Version, in.PNLen, in.Len
	if version == 0 {
		version = Version1
	}
	if pnLen == 0 {
		pnLen = 4
	}
	if size == 0 {
		size = 1200
	}
	typeBits := byte(0) // Initial is type 0 in v1, 1 in v2
	if version == Version2 {
		typeBits = 1
	}
	hdr := []byte{0xc0 | typeBits<<4 | byte(pnLen-1)}
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(in.DCID)))
	hdr = append(hdr, in.DCID...)
	hdr = append(hdr, byte(len(in.SCID)))
	hdr = append(hdr, in.SCID...)
	hdr = Varint(hdr, uint64(len(in.Token)))
	hdr = append(hdr, in.Token...)
	lengthAt := len(hdr)
	hdr = append(hdr, 0, 0)
	pnAt := len(hdr)
	pn := binary.BigEndian.AppendUint32(nil, in.PN)
	hdr = append(hdr, pn[4-pnLen:]...)

	plainLen := size - len(hdr) - 16
	if plainLen < len(in.Frames) {
		panic(fmt.Sprintf("l7snitest: %d bytes of frames do not fit a %d-byte packet", len(in.Frames), size))
	}
	plain := append(append([]byte(nil), in.Frames...), make([]byte, plainLen-len(in.Frames))...)
	binary.BigEndian.PutUint16(hdr[lengthAt:], 0x4000|uint16(pnLen+plainLen+16))

	key, iv, hp := initialKeys(version, in.DCID)
	nonce := append([]byte(nil), iv...)
	for i := 0; i < pnLen; i++ {
		nonce[len(nonce)-pnLen+i] ^= hdr[pnAt+i]
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	sealed := aead.Seal(nil, nonce, plain, hdr)

	hpBlock, _ := aes.NewCipher(hp)
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sealed[4-pnLen:20-pnLen])
	out := append(append([]byte(nil), hdr...), sealed...)
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[pnAt+i] ^= mask[1+i]
	}
	return out
}

var (
	saltV1 = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	saltV2 = mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
)

func initialKeys(version uint32, dcid []byte) (key, iv, hp []byte) {
	salt, k, i, h := saltV1, "quic key", "quic iv", "quic hp"
	if version == Version2 {
		salt, k, i, h = saltV2, "quicv2 key", "quicv2 iv", "quicv2 hp"
	}
	prk, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		panic(err)
	}
	secret := expandLabel(prk, "client in", 32)
	return expandLabel(secret, k, 16), expandLabel(secret, i, 12), expandLabel(secret, h, 16)
}

// expandLabel is TLS 1.3's HKDF-Expand-Label with an empty context.
func expandLabel(secret []byte, label string, n int) []byte {
	full := "tls13 " + label
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// Varint appends v as a QUIC variable-length integer, in its shortest form.
func Varint(b []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(b, byte(v))
	case v < 1<<14:
		return append(b, 0x40|byte(v>>8), byte(v))
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, 0x80000000|uint32(v))
	default:
		return binary.BigEndian.AppendUint64(b, 0xc000000000000000|v)
	}
}

// CryptoFrame encodes a CRYPTO frame carrying data at offset off.
func CryptoFrame(off uint64, data []byte) []byte {
	f := Varint([]byte{0x06}, off)
	f = Varint(f, uint64(len(data)))
	return append(f, data...)
}

// Extension encodes a TLS extension.
func Extension(typ uint16, data []byte) []byte {
	e := binary.BigEndian.AppendUint16(nil, typ)
	e = binary.BigEndian.AppendUint16(e, uint16(len(data)))
	return append(e, data...)
}

// ExtECH is the encrypted_client_hello extension type.
const ExtECH uint16 = 0xfe0d

// ClientHello returns a TLS ClientHello handshake message (msg_type, 3-byte
// length, body) with a server_name extension for host - none when host is
// empty - followed by the already-encoded extra extensions.
func ClientHello(host string, extra ...[]byte) []byte {
	var ext []byte
	if host != "" {
		name := []byte{0x00}
		name = binary.BigEndian.AppendUint16(name, uint16(len(host)))
		name = append(name, host...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(name)))
		ext = append(ext, Extension(0x0000, append(list, name...))...)
	}
	for _, e := range extra {
		ext = append(ext, e...)
	}
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // empty legacy_session_id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // null compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	msg := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// TLSRecord wraps a handshake message in a TLS record, as it travels over TCP.
func TLSRecord(hs []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
