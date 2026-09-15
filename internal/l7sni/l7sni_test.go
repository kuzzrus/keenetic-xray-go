package l7sni

import (
	"encoding/binary"
	"testing"
)

func buildIPv4TCP(src, dst [4]byte, sport, dport uint16, seq uint32, payload []byte) []byte {
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version 4, IHL 5 (20 bytes, no options)
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+20+len(payload)))
	ipHdr[9] = 6 // TCP
	copy(ipHdr[12:16], src[:])
	copy(ipHdr[16:20], dst[:])

	tcpHdr := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHdr[0:2], sport)
	binary.BigEndian.PutUint16(tcpHdr[2:4], dport)
	binary.BigEndian.PutUint32(tcpHdr[4:8], seq)
	tcpHdr[12] = 5 << 4 // data offset: 5 words, no options

	pkt := append(ipHdr, tcpHdr...)
	return append(pkt, payload...)
}

func buildIPv4UDP(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(20+8+len(payload)))
	ipHdr[9] = 17 // UDP
	copy(ipHdr[12:16], src[:])
	copy(ipHdr[16:20], dst[:])

	udpHdr := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHdr[0:2], sport)
	binary.BigEndian.PutUint16(udpHdr[2:4], dport)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(payload)))

	pkt := append(ipHdr, udpHdr...)
	return append(pkt, payload...)
}

func TestParseIPv4_TCP(t *testing.T) {
	src := [4]byte{192, 168, 1, 5}
	dst := [4]byte{93, 184, 216, 34}
	pkt := buildIPv4TCP(src, dst, 54321, 443, 0xDEADBEEF, []byte("hello"))

	proto, gotSrc, gotDst, sport, dport, seq, payload, ok := ParseIPv4(pkt)
	if !ok {
		t.Fatal("ParseIPv4: want ok=true")
	}
	if proto != 6 || gotSrc != src || gotDst != dst || sport != 54321 || dport != 443 {
		t.Errorf("ParseIPv4 = proto=%d src=%v dst=%v sport=%d dport=%d, want 6 %v %v 54321 443",
			proto, gotSrc, gotDst, sport, dport, src, dst)
	}
	if seq != 0xDEADBEEF {
		t.Errorf("seq = %#x, want 0xdeadbeef", seq)
	}
	if string(payload) != "hello" {
		t.Errorf("payload = %q, want %q", payload, "hello")
	}
}

func TestParseIPv4_UDP(t *testing.T) {
	src := [4]byte{192, 168, 1, 5}
	dst := [4]byte{8, 8, 8, 8}
	pkt := buildIPv4UDP(src, dst, 55555, 443, []byte("quic-init-bytes"))

	proto, _, _, sport, dport, seq, payload, ok := ParseIPv4(pkt)
	if !ok || proto != 17 || sport != 55555 || dport != 443 {
		t.Fatalf("ParseIPv4 = proto=%d ok=%v sport=%d dport=%d, want 17 true 55555 443", proto, ok, sport, dport)
	}
	if seq != 0 {
		t.Errorf("seq = %d, want 0 (meaningless for UDP)", seq)
	}
	if string(payload) != "quic-init-bytes" {
		t.Errorf("payload = %q, want %q", payload, "quic-init-bytes")
	}
}

func TestParseIPv4_RejectsNonV4(t *testing.T) {
	pkt := []byte{0x60, 0, 0, 0, 0, 0, 6, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, _, _, _, _, _, _, ok := ParseIPv4(pkt); ok {
		t.Error("ParseIPv4 on an IPv6-versioned packet: want ok=false")
	}
}

func TestParseIPv4_RejectsTruncated(t *testing.T) {
	if _, _, _, _, _, _, _, ok := ParseIPv4([]byte{0x45, 0, 0, 10}); ok {
		t.Error("ParseIPv4 on a truncated packet: want ok=false")
	}
}

func TestParseIPv4_RejectsUnknownProto(t *testing.T) {
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], 20)
	ipHdr[9] = 1 // ICMP
	copy(ipHdr[12:16], []byte{1, 2, 3, 4})
	copy(ipHdr[16:20], []byte{5, 6, 7, 8})
	if _, _, _, _, _, _, _, ok := ParseIPv4(ipHdr); ok {
		t.Error("ParseIPv4 on ICMP: want ok=false (not TCP/UDP)")
	}
}

func TestParseIPv4_RejectsShortTCPHeader(t *testing.T) {
	src := [4]byte{1, 2, 3, 4}
	dst := [4]byte{5, 6, 7, 8}
	pkt := buildIPv4TCP(src, dst, 1, 2, 0, nil)
	pkt = pkt[:len(pkt)-5] // truncate into the TCP header itself
	if _, _, _, _, _, _, _, ok := ParseIPv4(pkt); ok {
		t.Error("ParseIPv4 with a truncated TCP header: want ok=false")
	}
}
