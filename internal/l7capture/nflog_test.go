//go:build linux

package l7capture

import (
	"bytes"
	"testing"
)

// buildPacketMsg builds a complete NFULNL_MSG_PACKET netlink message
// carrying a single NFULA_PAYLOAD attribute -- the same shape a real
// NFLOG delivery has, minus the mark/ifindex attributes parsePacketAttrs
// is already independently tested against (nflog_proto_test.go).
func buildPacketMsg(seq uint32, payload []byte) []byte {
	payloadAttrLen := nlaAlign(nlaHdrLen + len(payload))
	total := nlHdrLen + nfgenLen + payloadAttrLen
	buf := make([]byte, total)
	putNlHeader(buf, uint32(total), (nflogSubsys<<8)|nfulnlMsgPacket, 0, seq, 0)
	putNfgenmsg(buf[nlHdrLen:], 0, 0)
	attrs := buf[nlHdrLen+nfgenLen:]
	putAttrHeader(attrs, nfulaPayload, len(payload))
	copy(attrs[nlaHdrLen:], payload)
	return buf
}

func TestParsePackets_SingleMessage(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x28, 0xDE, 0xAD}
	buf := buildPacketMsg(1, payload)

	got := parsePackets(buf)
	if len(got) != 1 {
		t.Fatalf("parsePackets returned %d packets, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Errorf("Payload = % x, want % x", got[0].Payload, payload)
	}
}

// TestParsePackets_BatchedMessagesAllReturned is the regression test for
// L7-02: a single recv() can carry more than one NFLOG message when the
// kernel batches them under load. The pre-fix code returned only the
// first match found in the parsed message list and silently discarded
// the rest -- this confirms every message in one buffer is extracted,
// not just the first.
func TestParsePackets_BatchedMessagesAllReturned(t *testing.T) {
	p1 := []byte{0x11, 0x11, 0x11, 0x11}
	p2 := []byte{0x22, 0x22, 0x22, 0x22}
	p3 := []byte{0x33, 0x33, 0x33, 0x33}
	var buf []byte
	buf = append(buf, buildPacketMsg(1, p1)...)
	buf = append(buf, buildPacketMsg(2, p2)...)
	buf = append(buf, buildPacketMsg(3, p3)...)

	got := parsePackets(buf)
	if len(got) != 3 {
		t.Fatalf("parsePackets returned %d packets, want 3 (one recv() batched three NFLOG messages)", len(got))
	}
	for i, want := range [][]byte{p1, p2, p3} {
		if !bytes.Equal(got[i].Payload, want) {
			t.Errorf("packet %d payload = % x, want % x", i, got[i].Payload, want)
		}
	}
}

// TestParsePackets_PayloadsAreIndependentCopies confirms each returned
// Packet's Payload is its own copy, not a slice aliasing the input
// buffer -- Read's own caller (Capture.recvBuf) is reused and
// overwritten by the very next syscall.Read, so a pending packet that
// still aliased it would be corrupted before it's ever returned.
func TestParsePackets_PayloadsAreIndependentCopies(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	buf := buildPacketMsg(1, payload)

	got := parsePackets(buf)
	if len(got) != 1 {
		t.Fatalf("parsePackets returned %d packets, want 1", len(got))
	}
	// Mutate the source buffer (simulating recvBuf being overwritten by
	// a later read) and confirm the returned Payload is unaffected.
	for i := range buf {
		buf[i] = 0
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Errorf("Payload = % x after mutating the source buffer, want unaffected % x", got[0].Payload, payload)
	}
}

func TestParsePackets_EmptyInput(t *testing.T) {
	if got := parsePackets(nil); got != nil {
		t.Errorf("parsePackets(nil) = %v, want nil", got)
	}
}

// TestParsePackets_IgnoresNonPacketMessages confirms a config-reply
// message (NFULNL_MSG_CONFIG, not _PACKET) interleaved in the same
// buffer is skipped rather than mistaken for a packet.
func TestParsePackets_IgnoresNonPacketMessages(t *testing.T) {
	configMsg := buildConfigCmd(1, 0, 0, 0, nfulnlCfgCmdPFBind)
	packetMsg := buildPacketMsg(2, []byte{0x01, 0x02})
	buf := append(append([]byte{}, configMsg...), packetMsg...)

	got := parsePackets(buf)
	if len(got) != 1 {
		t.Fatalf("parsePackets returned %d packets, want 1 (the config message must be skipped)", len(got))
	}
	if !bytes.Equal(got[0].Payload, []byte{0x01, 0x02}) {
		t.Errorf("Payload = % x, want the packet message's own payload", got[0].Payload)
	}
}
