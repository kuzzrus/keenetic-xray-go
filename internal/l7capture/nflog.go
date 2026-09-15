//go:build linux

// NFLOG (netfilter logging) is a Linux-kernel-specific subsystem --
// this file's raw AF_NETLINK/NETLINK_NETFILTER socket code has no
// meaning on any other OS, including other Unix variants (this isn't
// the broader "unix" build tag cmd/keenetic-xray's own daemonctl_restart
// files use for something POSIX-portable; NFLOG genuinely doesn't exist
// outside Linux). Excluding it elsewhere is what lets the rest of this
// package -- nflog_proto.go's pure message encoding/decoding, and its
// tests -- build and run on any platform, including the Windows box
// this project is developed on.

package l7capture

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// nflogCopyRange/nflogBufSize are the per-packet copy size and the
// kernel-side netlink buffer size hint this package asks for -- large
// enough to comfortably hold a TLS ClientHello (even a large post-
// quantum one) or an HTTP request line plus Host header, without
// copying more of each packet than internal/l7sni's parsers ever look
// at.
const (
	nflogCopyRange = 2048
	nflogBufSize   = 131072
)

// Capture is one open NFLOG group subscription. Not safe for concurrent
// use from multiple goroutines -- one capture loop per Capture, same as
// HydraRoute Neo's own single-threaded design.
//
// Built on the standard library's syscall package rather than a netlink
// library: syscall already has everything this needs (raw AF_NETLINK
// sockets, SockaddrNetlink, ParseNetlinkMessage for the generic message-
// splitting HydraRoute's own C code hand-rolls) with zero new
// dependencies -- this project's go.mod has stayed to golang.org/x/*
// packages plus the standard library throughout, and syscall is the
// more conservative of the two for something this narrowly Linux-
// specific.
//
// REAL-HARDWARE-VERIFICATION-PENDING: everything in this file that
// touches a real socket has not been exercised against a real Linux
// kernel's netfilter_log subsystem -- this project's CI and its Windows
// development environment can't do that (see nflog_proto.go's package
// doc comment). The message encoding/decoding this file calls into is
// independently unit-tested against hand-computed byte sequences, which
// is the part most likely to silently produce wrong bytes; the socket
// plumbing itself is standard socket()/bind()/sendto()/read(), so the
// realistic remaining risk is a wrong constant or a missing capability
// (NFLOG needs CAP_NET_ADMIN -- this daemon already runs as root for
// its other iptables/ipset work, so that's expected to already be
// satisfied, not a new requirement this feature adds).
type Capture struct {
	fd      int
	group   uint16
	seq     uint32
	portID  uint32
	recvBuf []byte
}

// Open binds to nflogGroup and configures it for packet capture.
// Mirrors HydraRoute Neo's own nflog_capture_init step for step:
// unbind then rebind the AF_INET and AF_INET6 protocol families first
// (a previous, uncleanly-stopped instance can leave a stale PF binding
// that a plain bind would otherwise silently no-op against -- the
// unbind's own result is intentionally ignored, matching upstream),
// then bind the specific group and set copy-packet mode with this
// package's own buffer sizing.
func Open(nflogGroup uint16) (*Capture, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("l7capture: socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("l7capture: bind: %w", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("l7capture: getsockname: %w", err)
	}
	nl, ok := sa.(*syscall.SockaddrNetlink)
	if !ok {
		syscall.Close(fd)
		return nil, fmt.Errorf("l7capture: getsockname returned %T, want *syscall.SockaddrNetlink", sa)
	}

	c := &Capture{fd: fd, group: nflogGroup, portID: nl.Pid, recvBuf: make([]byte, 65536)}

	_ = c.sendAndAck(buildConfigCmd(c.nextSeq(), c.portID, 0, syscall.AF_INET, nfulnlCfgCmdPFUnbind))
	_ = c.sendAndAck(buildConfigCmd(c.nextSeq(), c.portID, 0, syscall.AF_INET, nfulnlCfgCmdPFBind))
	_ = c.sendAndAck(buildConfigCmd(c.nextSeq(), c.portID, 0, syscall.AF_INET6, nfulnlCfgCmdPFBind))

	if err := c.sendAndAck(buildConfigCmd(c.nextSeq(), c.portID, nflogGroup, syscall.AF_UNSPEC, nfulnlCfgCmdBind)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("l7capture: bind group %d: %w", nflogGroup, err)
	}
	if err := c.sendAndAck(buildConfigMode(c.nextSeq(), c.portID, nflogGroup, nflogCopyRange, nflogBufSize)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("l7capture: set mode on group %d: %w", nflogGroup, err)
	}
	return c, nil
}

func (c *Capture) nextSeq() uint32 {
	c.seq++
	return c.seq
}

// sendAndAck sends a config message and waits for the kernel's
// ack/error response -- config commands are request/reply, unlike the
// asynchronous packet stream Read consumes.
func (c *Capture) sendAndAck(msg []byte) error {
	dst := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK} // pid 0: the kernel itself
	if err := syscall.Sendto(c.fd, msg, 0, dst); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}
	n, err := syscall.Read(c.fd, c.recvBuf)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(c.recvBuf[:n])
	if err != nil {
		return fmt.Errorf("parse netlink reply: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type != syscall.NLMSG_ERROR {
			continue
		}
		if errno := parseNlmsgerrCode(m.Data); errno != 0 {
			return fmt.Errorf("netlink error %d", errno)
		}
	}
	return nil
}

// parseNlmsgerrCode reads struct nlmsgerr's leading `error` field --
// native-endian (part of netlink's own message framing, not a
// netfilter attribute value), 0 on success, a negative errno otherwise.
func parseNlmsgerrCode(data []byte) int32 {
	if len(data) < 4 {
		return 0
	}
	return int32(binary.NativeEndian.Uint32(data[0:4]))
}

// Packet is one captured, NFLOG-delivered frame's raw IPv4 bytes plus
// the connmark and interface indices HydraRoute Neo's own design also
// surfaces (unused by this project so far, kept for parity and because
// a future caller may want to gate on the capturing interface).
type Packet struct {
	Payload    []byte
	Mark       uint32
	IfIndexIn  uint32
	IfIndexOut uint32
}

// Read blocks until the next NFLOG-delivered packet arrives (skipping
// any other netlink traffic on this socket) and returns it. Payload
// aliases Capture's own internal receive buffer -- valid only until the
// next call to Read; a caller that needs to keep the bytes longer (a
// Reassembler buffering a still-incomplete ClientHello, for instance)
// must copy them.
func (c *Capture) Read() (Packet, error) {
	for {
		n, err := syscall.Read(c.fd, c.recvBuf)
		if err != nil {
			return Packet{}, fmt.Errorf("l7capture: read: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(c.recvBuf[:n])
		if err != nil {
			continue // a malformed frame from the kernel would be a kernel bug; skip and keep reading
		}
		for _, m := range msgs {
			subsys := uint8(m.Header.Type >> 8)
			msgType := uint8(m.Header.Type & 0xff)
			if subsys != nflogSubsys || msgType != nfulnlMsgPacket || len(m.Data) < nfgenLen {
				continue
			}
			payload, mark, ifin, ifout := parsePacketAttrs(m.Data[nfgenLen:])
			if payload == nil {
				continue
			}
			return Packet{Payload: payload, Mark: mark, IfIndexIn: ifin, IfIndexOut: ifout}, nil
		}
	}
}

// Close unbinds the group and releases the socket. Best-effort on the
// unbind -- a failure there shouldn't stop the fd from being released.
func (c *Capture) Close() error {
	_ = c.sendAndAck(buildConfigCmd(c.nextSeq(), c.portID, c.group, syscall.AF_UNSPEC, nfulnlCfgCmdUnbind))
	return syscall.Close(c.fd)
}
