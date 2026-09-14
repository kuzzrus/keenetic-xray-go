// Package classifier is a native Go port of Susanin.Keenetic's
// conntrack-based blocked-destination detector (github.com/R17a/
// Susanin.Keenetic, MIT, pinned v0.3.8 -- src/classifier.c, src/
// conntrack.c, src/state.c, src/config.c) for Susanin Phase 2 (see
// docs/HANDOFF-susanin.md). Pure logic: this package never shells out or
// touches the filesystem beyond reading /proc/net/nf_conntrack --
// internal/adaptiveroute (ipset) and internal/keenetic (conntrack -D)
// carry out the Actions a classification pass returns.
//
// One deliberate divergence from upstream throughout: upstream tells
// "is this destination currently routed through me" apart via a
// conntrack mark its own mark+policy-routing dataplane sets. This
// project's dataplane (internal/adaptiveroute) is plain iptables
// REDIRECT -- it never marks anything -- so this port answers that
// question with a State lookup instead (see ClrJudge). Functionally
// identical, and actually cheaper: a Go map lookup instead of a kernel
// round-trip upstream only needed because C had no cheaper way to ask.
package classifier

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// Flow mirrors upstream's ct_flow (src/conntrack.h) -- one parsed line
// from /proc/net/nf_conntrack.
type Flow struct {
	L4Proto        int    // 6=tcp, 17=udp (icmp/others are parsed but never classified)
	Proto          string // "tcp"/"udp"/"icmp"
	Src, Dst       string
	SPort, DPort   uint
	RSPort, RDPort uint   // reply-direction ports
	TCPState       string // tcp only: SYN_SENT/ESTABLISHED/CLOSE/...
	OP, OB         uint64 // original-direction packets/bytes
	RP, RB         uint64 // reply-direction packets/bytes
	CTMark         uint64
	HasReply       bool
	FastNAT        bool
}

// DefaultConntrackPath is where ScanConntrack reads from when given "".
const DefaultConntrackPath = "/proc/net/nf_conntrack"

// ParseConntrackLine parses one /proc/net/nf_conntrack line, mirroring
// upstream's conntrack_parse_line (src/conntrack.c) field for field:
//   - only the *first* src=/dst= pair is kept (the original-direction
//     tuple) -- a NAT'd/bidirectional entry repeats both with the reply
//     tuple, which this doesn't need;
//   - sport=/dport=/packets=/bytes= alternate original then reply on
//     their second occurrence;
//   - the TCP state is read positionally, the 6th whitespace-separated
//     field, and only once the protocol is already known to be tcp --
//     matches the fixed `<nfproto> <nfproto_num> tcp 6 <timeout> <state>
//     ...` preamble nf_conntrack actually writes for TCP entries (a UDP
//     entry has no state field there at all, so the l4proto==6 guard is
//     what keeps this from misreading a UDP line's 6th field as one).
func ParseConntrackLine(line string) (Flow, bool) {
	var f Flow
	var seenSrc, seenDst, seenSPort, seenDPort, seenPackets, seenBytes bool

	for i, tok := range strings.Fields(line) {
		switch {
		case strings.HasPrefix(tok, "src="):
			if !seenSrc {
				f.Src, seenSrc = tok[4:], true
			}
		case strings.HasPrefix(tok, "dst="):
			if !seenDst {
				f.Dst, seenDst = tok[4:], true
			}
		case strings.HasPrefix(tok, "sport="):
			v, _ := strconv.ParseUint(tok[6:], 10, 32)
			if !seenSPort {
				f.SPort, seenSPort = uint(v), true
			} else {
				f.RSPort = uint(v)
			}
		case strings.HasPrefix(tok, "dport="):
			v, _ := strconv.ParseUint(tok[6:], 10, 32)
			if !seenDPort {
				f.DPort, seenDPort = uint(v), true
			} else {
				f.RDPort = uint(v)
			}
		case strings.HasPrefix(tok, "packets="):
			v, _ := strconv.ParseUint(tok[8:], 10, 64)
			if !seenPackets {
				f.OP, seenPackets = v, true
			} else {
				f.RP = v
			}
		case strings.HasPrefix(tok, "bytes="):
			v, _ := strconv.ParseUint(tok[6:], 10, 64)
			if !seenBytes {
				f.OB, seenBytes = v, true
			} else {
				f.RB = v
			}
		case strings.HasPrefix(tok, "mark="):
			// Base 0: accepts a bare decimal or a "0x..." hex value,
			// same as upstream's strtoul(tok+5, NULL, 0).
			v, _ := strconv.ParseUint(tok[5:], 0, 64)
			f.CTMark = v
		case tok == "tcp" || tok == "udp" || tok == "icmp":
			f.Proto = tok
			switch tok {
			case "tcp":
				f.L4Proto = 6
			case "udp":
				f.L4Proto = 17
			default:
				f.L4Proto = 1
			}
		case i == 5 && f.L4Proto == 6:
			f.TCPState = tok
		case strings.Contains(tok, "FASTNAT"):
			f.FastNAT = true
		}
	}

	f.HasReply = f.RP > 0
	if f.Proto == "" || f.Dst == "" || f.Src == "" {
		return Flow{}, false
	}
	return f, true
}

// ScanConntrack reads and parses every valid line from path (""
// defaults to DefaultConntrackPath). Invalid lines (conntrack_parse_line
// returning false upstream) are silently skipped, same as upstream.
func ScanConntrack(path string) ([]Flow, error) {
	if path == "" {
		path = DefaultConntrackPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// bufio.Scanner's default 64KiB max line length is already far more
	// generous than upstream's own fixed 4KiB fgets() buffer -- no real
	// nf_conntrack line comes anywhere close to either.
	var flows []Flow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if flow, ok := ParseConntrackLine(sc.Text()); ok {
			flows = append(flows, flow)
		}
	}
	return flows, sc.Err()
}
