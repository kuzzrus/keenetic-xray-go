package l7sni

import (
	"sync"
	"time"
)

// FlowKey identifies one TCP flow by its outbound 4-tuple, as seen by
// the router capturing LAN->WAN traffic.
type FlowKey struct {
	Src, Dst     [4]byte
	SPort, DPort uint16
}

type reassembly struct {
	buf      []byte // buf[:filled] is the contiguous prefix received so far
	filled   int
	want     int // total record length, from TLSRecordLen
	startSeq uint32
	lastSeen time.Time
}

// Reassembler buffers a TLS ClientHello split across multiple TCP
// segments, keyed by flow, so ExtractTLSSNI can be retried once the full
// record has arrived -- large ClientHellos (post-quantum key shares in
// particular) routinely don't fit in one segment.
//
// Deliberately simple, not a general-purpose TCP reassembler: assumes
// segments for one flow arrive in order, which holds at this capture
// point (packets are captured as they leave the router itself, right
// next to the LAN client -- essentially no reordering has had a chance
// to happen yet), and tracks only the single contiguous run from the
// first byte seen. An out-of-order or retransmitted segment is dropped
// rather than held for later: that flow simply fails to reassemble
// (missed SNI detection for one connection), not a wrong result.
//
// Not internal/classifier.State-shaped -- this doesn't need persistence
// across restarts. A lost in-flight ClientHello just means that one
// connection doesn't get recognized by SNI; the client's own retry (or,
// worst case, internal/classifier's ordinary pattern-based detection)
// is the fallback, not a correctness gap this package has to cover.
type Reassembler struct {
	mu      sync.Mutex
	maxAge  time.Duration
	maxSize int
	flows   map[FlowKey]*reassembly
}

// NewReassembler returns a ready-to-use Reassembler. maxAge bounds how
// long an incomplete flow is held before Expire drops it; maxSize caps
// how large a single ClientHello this will ever buffer -- Start refuses
// anything larger outright, since nothing legitimate needs it and it
// bounds worst-case memory under a flood of bogus "TLS" traffic.
func NewReassembler(maxAge time.Duration, maxSize int) *Reassembler {
	return &Reassembler{maxAge: maxAge, maxSize: maxSize, flows: map[FlowKey]*reassembly{}}
}

// Start begins buffering a new flow: data is the first segment seen
// (already confirmed to look like the start of a ClientHello via
// IsTLSClientHello), seq is its TCP sequence number, and want is the
// full record length from TLSRecordLen. Replaces any prior incomplete
// buffer for the same key -- a fresh ClientHello attempt (e.g. after a
// retransmit-triggered reconnect) supersedes whatever was there.
func (r *Reassembler) Start(key FlowKey, seq uint32, data []byte, want int) {
	if want <= 0 || want > r.maxSize || len(data) > want {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	buf := make([]byte, want)
	n := copy(buf, data)
	r.flows[key] = &reassembly{buf: buf, filled: n, want: want, startSeq: seq, lastSeen: time.Now()}
}

// Feed appends a later segment for a flow Start already began. seq is
// that segment's own TCP sequence number, used to compute its offset
// relative to the flow's start. Returns the complete record and true
// once enough contiguous bytes have arrived; the flow is removed from
// the table either way once this call completes it.
func (r *Reassembler) Feed(key FlowKey, seq uint32, data []byte) (full []byte, complete bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fl, ok := r.flows[key]
	if !ok {
		return nil, false
	}
	fl.lastSeen = time.Now()

	// Wraps correctly for the realistic (small, positive) deltas a
	// genuine next-in-order segment produces; any other value -- a
	// retransmit, an out-of-order segment, a wrapped/negative delta --
	// simply won't equal fl.filled below and gets skipped. offset is
	// never used as an index, only compared, so there's no unsafe
	// access hiding in a wrapped value either way.
	offset := int(seq - fl.startSeq)
	if offset != fl.filled {
		return nil, false
	}
	n := copy(fl.buf[fl.filled:], data)
	fl.filled += n
	if fl.filled < fl.want {
		return nil, false
	}
	delete(r.flows, key)
	return fl.buf, true
}

// Lookup reports whether key has an in-progress reassembly, so a caller
// deciding whether a fresh packet belongs to Start or Feed doesn't have
// to keep its own parallel bookkeeping.
func (r *Reassembler) Lookup(key FlowKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.flows[key]
	return ok
}

// Drop removes key's in-progress reassembly without completing it, e.g.
// once a caller has otherwise decided the flow no longer needs watching
// (a FIN/RST seen, the connection's own conntrack entry gone, ...).
func (r *Reassembler) Drop(key FlowKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.flows, key)
}

// Expire drops any flow that's been incomplete for longer than maxAge --
// bounds memory when a ClientHello never finishes arriving (a dropped
// segment, a connection reset mid-handshake, ...).
func (r *Reassembler) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, fl := range r.flows {
		if now.Sub(fl.lastSeen) > r.maxAge {
			delete(r.flows, k)
		}
	}
}
