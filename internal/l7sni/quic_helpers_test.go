package l7sni

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Test-only machinery for building QUIC Initial packets. It is the sending
// side of ParseQUICInitial, written independently of it from RFC 9001
// section 5; TestSealer_ReproducesRFCPackets pins it to the RFC's own
// packets, which is what makes the synthetic packets the other tests build
// with it worth anything.

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// appendVarint encodes v as a QUIC variable-length integer in the shortest
// form.
func appendVarint(b []byte, v uint64) []byte {
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

func cryptoFrame(off uint64, data []byte) []byte {
	f := []byte{0x06}
	f = appendVarint(f, off)
	f = appendVarint(f, uint64(len(data)))
	return append(f, data...)
}

func paddingFrames(n int) []byte { return make([]byte, n) }

func pingFrame() []byte { return []byte{0x01} }

// ackFrame builds an ACK frame (type 0x02, or 0x03 with ECN counts) with the
// given number of extra (gap, length) ranges, so the walker has something to
// skip before it reaches the CRYPTO frames.
func ackFrame(ecn bool, extraRanges int) []byte {
	f := []byte{0x02}
	if ecn {
		f[0] = 0x03
	}
	f = appendVarint(f, 10) // largest acknowledged
	f = appendVarint(f, 25) // ack delay
	f = appendVarint(f, uint64(extraRanges))
	f = appendVarint(f, 3) // first ack range
	for i := 0; i < extraRanges; i++ {
		f = appendVarint(f, uint64(1+i)) // gap
		f = appendVarint(f, 2)           // range length
	}
	if ecn {
		f = appendVarint(f, 1)
		f = appendVarint(f, 2)
		f = appendVarint(f, 3)
	}
	return f
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// sealInitialPacket protects plaintext with the client Initial keys of
// version/dcid. header is the unprotected header up to and including the
// packet number, whose last pnLen bytes sit at pnOffset; the returned slice
// is the finished packet.
func sealInitialPacket(t testing.TB, version uint32, dcid, header []byte, pnOffset, pnLen int, plaintext []byte) []byte {
	t.Helper()
	key, iv, hp, err := initialKeys(version, dcid)
	if err != nil {
		t.Fatalf("initialKeys: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < pnLen; i++ {
		nonce[len(nonce)-pnLen+i] ^= header[pnOffset+i]
	}
	sealed := aead.Seal(nil, nonce, plaintext, header)

	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sealed[4-pnLen:20-pnLen])

	out := append(append([]byte(nil), header...), sealed...)
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}

// buildInitial assembles a client Initial datagram of datagramLen bytes
// carrying frames (zero-padded up to the size), under dcid, with a 4-byte
// packet number.
func buildInitial(t testing.TB, version uint32, dcid []byte, pn uint32, frames []byte, datagramLen int) []byte {
	t.Helper()
	scid := []byte{1, 2, 3, 4}
	typeBits := byte(0)
	if version == QUICVersion2 {
		typeBits = 1
	}
	hdr := []byte{0xc0 | typeBits<<4 | 0x03} // long header, fixed bit, Initial, 4-byte packet number
	hdr = binary.BigEndian.AppendUint32(hdr, version)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, byte(len(scid)))
	hdr = append(hdr, scid...)
	hdr = append(hdr, 0) // token length
	lengthField := len(hdr)
	hdr = append(hdr, 0, 0) // 2-byte Length, filled in below
	pnOffset := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	plainLen := datagramLen - len(hdr) - 16
	if plainLen < len(frames) {
		t.Fatalf("frames (%d bytes) do not fit a %d-byte datagram", len(frames), datagramLen)
	}
	plain := append(append([]byte(nil), frames...), make([]byte, plainLen-len(frames))...)
	binary.BigEndian.PutUint16(hdr[lengthField:], 0x4000|uint16(4+plainLen+16))
	return sealInitialPacket(t, version, dcid, hdr, pnOffset, 4, plain)
}

// buildClientHelloMsg returns a ClientHello handshake message (msg_type,
// 3-byte length, body) with a server_name extension for host (none when
// host is "") followed by the already-encoded extra extensions.
func buildClientHelloMsg(host string, extra ...[]byte) []byte {
	var ext []byte
	if host != "" {
		sn := []byte{0x00}
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(host)))
		sn = append(sn, host...)
		list := binary.BigEndian.AppendUint16(nil, uint16(len(sn)))
		list = append(list, sn...)
		ext = append(ext, encodeExt(extTypeServerName, list)...)
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

func encodeExt(typ uint16, data []byte) []byte {
	e := binary.BigEndian.AppendUint16(nil, typ)
	e = binary.BigEndian.AppendUint16(e, uint16(len(data)))
	return append(e, data...)
}
