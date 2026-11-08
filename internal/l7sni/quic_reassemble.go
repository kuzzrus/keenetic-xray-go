package l7sni

import (
	"sync"
	"time"
)

type quicFlow struct {
	stream   cryptoStream
	lastSeen time.Time
}

// QUICReassembler puts a ClientHello back together when a client's first
// flight spans several Initial datagrams -- which the post-quantum key shares
// browsers now send make routine -- keyed by the UDP flow. Like Reassembler
// for TCP it keeps nothing worth persisting: a flight that never completes
// just means that one connection is not recognised by name.
//
// It also remembers, for maxAge, the flows whose ClientHello it has already
// handed out. A client sends its first flight in several datagrams and
// repeats it when it hears nothing back, and the capture filter passes the
// first four datagrams of every flow, so without this the same connection
// would be reported -- and acted on -- again for each retransmission.
type QUICReassembler struct {
	mu       sync.Mutex
	maxAge   time.Duration
	maxFlows int
	maxDone  int // how many finished flows are remembered
	flows    map[FlowKey]*quicFlow
	finished map[FlowKey]time.Time
}

// finishedPerFlight sizes the memory of finished flows relative to the cap
// on incomplete flights. Finished flows are by far the common case (a
// ClientHello that fits one datagram never becomes a flight at all), so
// they get a table of their own, several times larger: sharing the small
// cap made the memory stop working at about 50 new connections a second.
const finishedPerFlight = 4

// NewQUICReassembler returns a ready-to-use QUICReassembler. maxAge bounds
// how long an incomplete flight is held (Expire drops it) and how long a
// finished one is remembered; maxFlows caps how many incomplete flights are
// kept at once (and, times finishedPerFlight, how many finished flows are
// remembered), which bounds worst-case memory under a flood of UDP/443
// datagrams that look like Initials -- beyond it new flights that do not
// complete in their first datagram are simply not tracked, and finished
// ones are not remembered.
func NewQUICReassembler(maxAge time.Duration, maxFlows int) *QUICReassembler {
	return &QUICReassembler{
		maxAge: maxAge, maxFlows: maxFlows, maxDone: maxFlows * finishedPerFlight,
		flows:    map[FlowKey]*quicFlow{},
		finished: map[FlowKey]time.Time{},
	}
}

// Feed adds the CRYPTO fragments of one Initial datagram of flow key and
// returns the ClientHello handshake message as soon as the flight holds all
// of it. A flight that begins with something other than a ClientHello is
// dropped on the spot, and a flow whose ClientHello was already returned
// less than maxAge ago yields nothing more. The common case -- the whole
// ClientHello in the first datagram -- never stores a partial flight.
func (r *QUICReassembler) Feed(key FlowKey, frags []CryptoFragment, now time.Time) (hs []byte, done bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if at, ok := r.finished[key]; ok && now.Sub(at) <= r.maxAge {
		return nil, false
	}

	fl, known := r.flows[key]
	if !known {
		fl = &quicFlow{}
	}
	for _, f := range frags {
		if !fl.stream.add(f.Offset, f.Data) {
			delete(r.flows, key)
			return nil, false
		}
	}
	if len(frags) > 0 { // a datagram with no CRYPTO frame (ACK, PING, padding) is no progress
		fl.lastSeen = now
	}

	msg, state := clientHelloIn(fl.stream.prefix())
	switch state {
	case helloComplete:
		delete(r.flows, key)
		if len(r.finished) < r.maxDone {
			r.finished[key] = now
		}
		return msg, true
	case helloNot:
		delete(r.flows, key)
		return nil, false
	}
	if !known && len(frags) > 0 {
		if len(r.flows) >= r.maxFlows {
			return nil, false
		}
		r.flows[key] = fl
	}
	return nil, false
}

// Expire drops every flight that has been incomplete for longer than maxAge
// and forgets every finished flow older than that.
func (r *QUICReassembler) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, fl := range r.flows {
		if now.Sub(fl.lastSeen) > r.maxAge {
			delete(r.flows, k)
		}
	}
	for k, at := range r.finished {
		if now.Sub(at) > r.maxAge {
			delete(r.finished, k)
		}
	}
}

// Len reports how many incomplete flights are being held.
func (r *QUICReassembler) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.flows)
}
