// Package l7capture is the I/O layer for internal/l7sni's hostname
// detection: NFLOG packet capture (reading raw packets straight from
// the kernel's netfilter logging subsystem) and, in a later step, the
// iptables rules that feed it -- modeled directly on Ground-Zerro/
// HydraRoute Neo's own design. See the hydraroute-comparison and
// l7sni-build-plan memory files for the research and plan this
// implements.
//
// Hand-rolls the netfilter-log (NFLOG) netlink protocol directly on top
// of golang.org/x/sys/unix's raw socket primitives, rather than pulling
// in a third-party netlink library: this project's go.mod has stayed to
// golang.org/x/* packages only throughout (the same trust tier as the
// standard library, maintained by the Go team), and HydraRoute's own C
// implementation (nflog_capture.c) shows the protocol itself is small
// enough that hand-rolling it isn't a meaningful maintenance burden.
//
// The parts of this package that only build or parse byte buffers
// (this file) are pure and fully unit-tested without a real socket. The
// parts that actually open an AF_NETLINK socket and talk to the
// kernel's netfilter subsystem (nflog.go) cannot be exercised in this
// project's CI or in any Windows development environment -- NFLOG only
// exists on Linux, and needs a real kernel with the nfnetlink_log module
// loaded. That socket-facing code is real-hardware-verification-pending;
// see nflog.go's own doc comment.
package l7capture

import "encoding/binary"

// Netfilter-log (NFLOG) netlink protocol constants -- mirrors
// linux/netfilter/nfnetlink_log.h and linux/netfilter/nfnetlink.h.
// Named and grouped to match HydraRoute Neo's own nflog_capture.c,
// which is what this file's encoding/decoding was checked against line
// by line.
const (
	nflogSubsys = 4 // NFNL_SUBSYS_ULOG

	nfulnlMsgPacket = 0
	nfulnlMsgConfig = 1

	nfulnlCfgCmdBind     = 1
	nfulnlCfgCmdUnbind   = 2
	nfulnlCfgCmdPFBind   = 3
	nfulnlCfgCmdPFUnbind = 4

	nfulaCfgCmd      = 1
	nfulaCfgMode     = 2
	nfulaCfgNLBufSiz = 3

	nfulnlCopyPacket = 2

	nfulaMark       = 2
	nfulaIfindexIn  = 4
	nfulaIfindexOut = 5
	nfulaPayload    = 9

	nfnetlinkV0 = 0

	nlaFNested       = 0x8000
	nlaFNetByteorder = 0x4000

	nlmFRequest = 0x1
	nlmFAck     = 0x4

	nlHdrLen  = 16 // sizeof(struct nlmsghdr)
	nfgenLen  = 4  // sizeof(struct nfgenmsg)
	nlaHdrLen = 4  // sizeof(struct nlattr)
)

func nlaAlign(n int) int { return (n + 3) &^ 3 }

// putNlHeader writes nlmsghdr's 16 bytes into buf[0:16]. Native byte
// order throughout -- netlink is a local kernel<->userspace IPC
// mechanism, not a network protocol, so its own framing (unlike the
// netfilter-specific attribute values put*NF* functions below write)
// uses whatever order the local machine's integers already are in.
func putNlHeader(buf []byte, msgLen uint32, msgType, flags uint16, seq, pid uint32) {
	binary.NativeEndian.PutUint32(buf[0:4], msgLen)
	binary.NativeEndian.PutUint16(buf[4:6], msgType)
	binary.NativeEndian.PutUint16(buf[6:8], flags)
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	binary.NativeEndian.PutUint32(buf[12:16], pid)
}

// putNfgenmsg writes nfgenmsg's 4 bytes: address family, a fixed
// protocol version, and res_id -- which the config-command messages
// below use to carry the NFLOG group number. res_id is big-endian:
// netfilter's own attribute *values* are big-endian throughout, even
// though the enclosing netlink message framing (nlmsghdr, and nlattr's
// own length/type header) stays native-endian -- confirmed against
// HydraRoute Neo's nflog_capture.c (its put_be16 specifically here).
func putNfgenmsg(buf []byte, family uint8, resID uint16) {
	buf[0] = family
	buf[1] = nfnetlinkV0
	binary.BigEndian.PutUint16(buf[2:4], resID)
}

// putAttrHeader writes one nlattr's 4-byte header -- length (including
// this header itself) then type, both native-endian, matching generic
// netlink attribute framing -- and returns the 4-byte-aligned total
// length a caller should advance its write cursor by. Doesn't write any
// alignment padding itself: callers work in an already zero-initialized
// buffer (make([]byte, n) is always zeroed), matching HydraRoute's own
// memset-then-fill approach, so padding bytes are correctly zero without
// this function touching them.
func putAttrHeader(buf []byte, attrType uint16, dataLen int) int {
	total := nlaHdrLen + dataLen
	binary.NativeEndian.PutUint16(buf[0:2], uint16(total))
	binary.NativeEndian.PutUint16(buf[2:4], attrType)
	return nlaAlign(total)
}

// buildConfigCmd builds a complete NFULNL_MSG_CONFIG message carrying
// one NFULA_CFG_CMD attribute (a single command byte) -- used for
// BIND/UNBIND/PF_BIND/PF_UNBIND, mirroring HydraRoute's own
// nflog_cfg_cmd/nflog_send_config.
func buildConfigCmd(seq, pid uint32, group uint16, family, cmd uint8) []byte {
	attrsLen := nlaAlign(nlaHdrLen + 1)
	total := nlHdrLen + nfgenLen + attrsLen
	buf := make([]byte, total)

	putNlHeader(buf, uint32(total), (nflogSubsys<<8)|nfulnlMsgConfig, nlmFRequest|nlmFAck, seq, pid)
	putNfgenmsg(buf[nlHdrLen:], family, group)

	attrs := buf[nlHdrLen+nfgenLen:]
	putAttrHeader(attrs, nfulaCfgCmd, 1)
	attrs[nlaHdrLen] = cmd
	return buf
}

// buildConfigMode builds a complete NFULNL_MSG_CONFIG message carrying
// NFULA_CFG_MODE (copyRange + NFULNL_COPY_PACKET) and
// NFULA_CFG_NLBUFSIZ -- mirroring HydraRoute's own nflog_cfg_mode.
// copyRange and nlbufsiz are netfilter attribute *values*, so
// big-endian (see putNfgenmsg's doc comment) -- unlike the attribute
// headers' own length/type fields, written by putAttrHeader in native
// order.
func buildConfigMode(seq, pid uint32, group uint16, copyRange, nlbufsiz uint32) []byte {
	const modeDataLen = 6 // copy_range(4) + copy_mode(1) + pad(1)
	modeAttrLen := nlaAlign(nlaHdrLen + modeDataLen)
	bufsizAttrLen := nlaAlign(nlaHdrLen + 4)
	total := nlHdrLen + nfgenLen + modeAttrLen + bufsizAttrLen
	buf := make([]byte, total)

	putNlHeader(buf, uint32(total), (nflogSubsys<<8)|nfulnlMsgConfig, nlmFRequest|nlmFAck, seq, pid)
	putNfgenmsg(buf[nlHdrLen:], 0, group)

	attrs := buf[nlHdrLen+nfgenLen:]
	putAttrHeader(attrs, nfulaCfgMode, modeDataLen)
	binary.BigEndian.PutUint32(attrs[nlaHdrLen:nlaHdrLen+4], copyRange)
	attrs[nlaHdrLen+4] = nfulnlCopyPacket
	// attrs[nlaHdrLen+5] is the struct's pad byte -- already zero.

	attrs2 := attrs[modeAttrLen:]
	putAttrHeader(attrs2, nfulaCfgNLBufSiz, 4)
	binary.BigEndian.PutUint32(attrs2[nlaHdrLen:nlaHdrLen+4], nlbufsiz)

	return buf
}

// parsePacketAttrs walks an NFULNL_MSG_PACKET message's attributes
// (everything after its own 4-byte nfgenmsg header) and extracts the
// raw packet payload plus the connmark/interface-index metadata
// HydraRoute's own nflog_parse_packet also pulls out. mark/ifin/ifout
// are 0 if the corresponding attribute is absent -- indistinguishable
// from a genuine 0 value, same simplification HydraRoute's own code
// makes (this package never acts on ifin/ifout being exactly 0 as
// meaningful either way).
func parsePacketAttrs(data []byte) (payload []byte, mark, ifin, ifout uint32) {
	pos := 0
	for pos+nlaHdrLen <= len(data) {
		nlaLen := int(binary.NativeEndian.Uint16(data[pos : pos+2]))
		nlaType := binary.NativeEndian.Uint16(data[pos+2 : pos+4])
		attrType := nlaType &^ (nlaFNested | nlaFNetByteorder)
		if nlaLen < nlaHdrLen {
			break
		}
		aligned := nlaAlign(nlaLen)
		if pos+aligned > len(data) {
			break
		}
		body := data[pos+nlaHdrLen : pos+nlaLen]
		switch attrType {
		case nfulaPayload:
			payload = body
		case nfulaMark:
			if len(body) >= 4 {
				mark = binary.BigEndian.Uint32(body)
			}
		case nfulaIfindexIn:
			if len(body) >= 4 {
				ifin = binary.BigEndian.Uint32(body)
			}
		case nfulaIfindexOut:
			if len(body) >= 4 {
				ifout = binary.BigEndian.Uint32(body)
			}
		}
		pos += aligned
	}
	return payload, mark, ifin, ifout
}
