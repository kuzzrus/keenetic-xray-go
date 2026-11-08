package l7capture

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestBuildConfigCmd_ExactBytes checks a full, literal expected byte
// sequence -- not just a round-trip against this package's own parser --
// for buildConfigCmd(seq=1, pid=100, group=0, family=AF_INET(2),
// cmd=PF_BIND(3)). Little-endian throughout for the native-order
// fields: this project's actual deployment targets (arm64, mipsle) are
// both little-endian, same as the machine running this test, so this is
// the layout that matters in practice, not just an assumption.
func TestBuildConfigCmd_ExactBytes(t *testing.T) {
	got := buildConfigCmd(1, 100, 0, 2, nfulnlCfgCmdPFBind)
	want := []byte{
		0x1C, 0x00, 0x00, 0x00, // nlmsg_len = 28
		0x01, 0x04, // nlmsg_type = (4<<8)|1 = 0x0401, LE
		0x05, 0x00, // nlmsg_flags = REQUEST|ACK = 0x5, LE
		0x01, 0x00, 0x00, 0x00, // nlmsg_seq = 1
		0x64, 0x00, 0x00, 0x00, // nlmsg_pid = 100
		0x02, 0x00, 0x00, 0x00, // nfgenmsg: family=2, version=0, res_id=0 (BE)
		0x05, 0x00, 0x01, 0x00, // nlattr: len=5, type=NFULA_CFG_CMD(1)
		0x03, 0x00, 0x00, 0x00, // command byte (3=PF_BIND) + 3 padding bytes
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("buildConfigCmd bytes =\n% x\nwant\n% x", got, want)
	}
}

func TestBuildConfigCmd_Length(t *testing.T) {
	buf := buildConfigCmd(7, 42, 5, 2, nfulnlCfgCmdBind)
	gotLen := binary.NativeEndian.Uint32(buf[0:4])
	if int(gotLen) != len(buf) {
		t.Errorf("nlmsg_len = %d, want %d (the buffer's own length)", gotLen, len(buf))
	}
}

// TestBuildConfigMode_ExactBytes checks a literal byte sequence, not a
// round trip through this package's own parser, for
// buildConfigMode(seq=3, pid=200, group=9, copyRange=2048, nlbufsiz=16384,
// timeout=2 cs, qthresh=8) -- the values nflog.go actually sends. Layout
// per linux/netfilter/nfnetlink_log.h: NFULA_CFG_MODE (2) carrying
// struct nfulnl_msg_config_mode {be32 copy_range; u8 copy_mode; u8 pad},
// NFULA_CFG_NLBUFSIZ (3), NFULA_CFG_TIMEOUT (4) and NFULA_CFG_QTHRESH (5),
// each a be32; attribute headers native-endian (little-endian on the
// arm64 and mipsle targets, same as the machine running this test).
func TestBuildConfigMode_ExactBytes(t *testing.T) {
	got := buildConfigMode(3, 200, 9, 2048, 16384, 2, 8)
	want := []byte{
		0x38, 0x00, 0x00, 0x00, // nlmsg_len = 56
		0x01, 0x04, // nlmsg_type = (4<<8)|1
		0x05, 0x00, // flags = REQUEST|ACK
		0x03, 0x00, 0x00, 0x00, // seq = 3
		0xC8, 0x00, 0x00, 0x00, // pid = 200
		0x00, 0x00, 0x00, 0x09, // nfgenmsg: family 0, version 0, res_id = 9 (BE)
		0x0A, 0x00, 0x02, 0x00, // nlattr len=10, type=NFULA_CFG_MODE
		0x00, 0x00, 0x08, 0x00, // copy_range = 2048 (BE)
		0x02, 0x00, // copy_mode = NFULNL_COPY_PACKET, pad
		0x00, 0x00, // attribute padding to 4 bytes
		0x08, 0x00, 0x03, 0x00, // nlattr len=8, type=NFULA_CFG_NLBUFSIZ
		0x00, 0x00, 0x40, 0x00, // 16384 (BE)
		0x08, 0x00, 0x04, 0x00, // nlattr len=8, type=NFULA_CFG_TIMEOUT
		0x00, 0x00, 0x00, 0x02, // 2 centiseconds (BE)
		0x08, 0x00, 0x05, 0x00, // nlattr len=8, type=NFULA_CFG_QTHRESH
		0x00, 0x00, 0x00, 0x08, // 8 packets (BE)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("buildConfigMode bytes =\n% x\nwant\n% x", got, want)
	}
}

func TestBuildConfigMode_FieldPlacement(t *testing.T) {
	buf := buildConfigMode(3, 200, 9, 0, 131072, 0, 0)

	gotType := binary.NativeEndian.Uint16(buf[4:6])
	if want := uint16((nflogSubsys << 8) | nfulnlMsgConfig); gotType != want {
		t.Errorf("nlmsg_type = %#x, want %#x", gotType, want)
	}

	group := binary.BigEndian.Uint16(buf[nlHdrLen+2 : nlHdrLen+4])
	if group != 9 {
		t.Errorf("nfgenmsg.res_id (group) = %d, want 9", group)
	}

	modeAttr := buf[nlHdrLen+nfgenLen:]
	modeType := binary.NativeEndian.Uint16(modeAttr[2:4])
	if modeType != nfulaCfgMode {
		t.Errorf("first attribute type = %d, want NFULA_CFG_MODE(%d)", modeType, nfulaCfgMode)
	}
	copyMode := modeAttr[nlaHdrLen+4]
	if copyMode != nfulnlCopyPacket {
		t.Errorf("copy_mode = %d, want NFULNL_COPY_PACKET(%d)", copyMode, nfulnlCopyPacket)
	}

	bufsizAttr := modeAttr[nlaAlign(nlaHdrLen+6):]
	bufsizType := binary.NativeEndian.Uint16(bufsizAttr[2:4])
	if bufsizType != nfulaCfgNLBufSiz {
		t.Errorf("second attribute type = %d, want NFULA_CFG_NLBUFSIZ(%d)", bufsizType, nfulaCfgNLBufSiz)
	}
	gotBufsiz := binary.BigEndian.Uint32(bufsizAttr[nlaHdrLen : nlaHdrLen+4])
	if gotBufsiz != 131072 {
		t.Errorf("nlbufsiz value = %d, want 131072 (big-endian)", gotBufsiz)
	}
}

func TestParsePacketAttrs_ExtractsPayloadAndMetadata(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x28, 0xDE, 0xAD, 0xBE, 0xEF} // fake IPv4-ish bytes

	var buf []byte
	// NFULA_MARK = 0xAABBCCDD (big-endian value)
	markAttr := make([]byte, nlaAlign(nlaHdrLen+4))
	putAttrHeader(markAttr, nfulaMark, 4)
	binary.BigEndian.PutUint32(markAttr[nlaHdrLen:nlaHdrLen+4], 0xAABBCCDD)
	buf = append(buf, markAttr...)

	// NFULA_IFINDEX_INDEV = 3
	ifinAttr := make([]byte, nlaAlign(nlaHdrLen+4))
	putAttrHeader(ifinAttr, nfulaIfindexIn, 4)
	binary.BigEndian.PutUint32(ifinAttr[nlaHdrLen:nlaHdrLen+4], 3)
	buf = append(buf, ifinAttr...)

	// NFULA_PAYLOAD, with the NLA_F_NET_BYTEORDER flag bit set on the
	// type (as real payload attributes carry it) -- parsePacketAttrs
	// must mask that off to recognize the attribute.
	payloadAttr := make([]byte, nlaAlign(nlaHdrLen+len(payload)))
	putAttrHeader(payloadAttr, nfulaPayload|nlaFNetByteorder, len(payload))
	copy(payloadAttr[nlaHdrLen:], payload)
	buf = append(buf, payloadAttr...)

	gotPayload, mark, ifin, ifout := parsePacketAttrs(buf)
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload = % x, want % x", gotPayload, payload)
	}
	if mark != 0xAABBCCDD {
		t.Errorf("mark = %#x, want 0xaabbccdd", mark)
	}
	if ifin != 3 {
		t.Errorf("ifin = %d, want 3", ifin)
	}
	if ifout != 0 {
		t.Errorf("ifout = %d, want 0 (attribute absent)", ifout)
	}
}

func TestParsePacketAttrs_EmptyInput(t *testing.T) {
	payload, mark, ifin, ifout := parsePacketAttrs(nil)
	if payload != nil || mark != 0 || ifin != 0 || ifout != 0 {
		t.Errorf("parsePacketAttrs(nil) = %v %d %d %d, want all zero", payload, mark, ifin, ifout)
	}
}

func TestParsePacketAttrs_TruncatedAttributeStopsCleanly(t *testing.T) {
	// A well-formed first attribute, then a header claiming more data
	// than actually follows -- must not panic, must still return what
	// it already had.
	payload := []byte{1, 2, 3, 4}
	payloadAttr := make([]byte, nlaAlign(nlaHdrLen+len(payload)))
	putAttrHeader(payloadAttr, nfulaPayload, len(payload))
	copy(payloadAttr[nlaHdrLen:], payload)

	truncated := append([]byte{}, payloadAttr...)
	truncated = append(truncated, 0x20, 0x00, 0x02, 0x00) // claims 32 bytes of data that aren't there

	gotPayload, _, _, _ := parsePacketAttrs(truncated)
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload = % x, want % x (the well-formed attribute before the truncated one)", gotPayload, payload)
	}
}

func TestNlaAlign(t *testing.T) {
	cases := map[int]int{0: 0, 1: 4, 3: 4, 4: 4, 5: 8, 8: 8, 9: 12}
	for in, want := range cases {
		if got := nlaAlign(in); got != want {
			t.Errorf("nlaAlign(%d) = %d, want %d", in, got, want)
		}
	}
}
