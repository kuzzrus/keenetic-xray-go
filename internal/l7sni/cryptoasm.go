package l7sni

import "sort"

const (
	// maxCryptoStream bounds how much of a handshake stream is ever kept: a
	// ClientHello with post-quantum key shares is around 2 KiB, and 16 KiB
	// is what the TCP reassembler allows a record to be.
	maxCryptoStream = 16384
	// maxCryptoSpans bounds how fragmented the received part may be.
	// Chrome cuts a ClientHello into five or six CRYPTO frames; more holes
	// than this is not a handshake worth chasing.
	maxCryptoSpans = 8
)

type span struct{ lo, hi int }

// cryptoStream collects the pieces of one handshake byte stream (the
// concatenated CRYPTO frames of a QUIC connection, addressed by offset) as
// they arrive, in any order and with overlaps, and exposes the contiguous
// part from offset 0.
type cryptoStream struct {
	buf   []byte
	spans []span // sorted, non-overlapping, non-adjacent
}

// add stores data at offset off. It returns false when the piece cannot be
// kept -- it reaches past maxCryptoStream or leaves too many holes -- and
// the stream is then useless.
func (s *cryptoStream) add(off uint64, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if off > maxCryptoStream || uint64(len(data)) > maxCryptoStream-off {
		return false
	}
	lo, hi := int(off), int(off)+len(data)
	if len(s.buf) < hi {
		grown := make([]byte, hi)
		copy(grown, s.buf)
		s.buf = grown
	}
	copy(s.buf[lo:hi], data)

	s.spans = append(s.spans, span{lo, hi})
	sort.Slice(s.spans, func(i, j int) bool { return s.spans[i].lo < s.spans[j].lo })
	merged := s.spans[:1]
	for _, sp := range s.spans[1:] {
		last := &merged[len(merged)-1]
		if sp.lo <= last.hi { // overlapping or touching
			if sp.hi > last.hi {
				last.hi = sp.hi
			}
			continue
		}
		merged = append(merged, sp)
	}
	s.spans = merged
	return len(s.spans) <= maxCryptoSpans
}

// prefix returns the contiguous bytes from offset 0, nil when offset 0 has
// not arrived yet. The slice aliases the stream's buffer.
func (s *cryptoStream) prefix() []byte {
	if len(s.spans) == 0 || s.spans[0].lo != 0 {
		return nil
	}
	return s.buf[:s.spans[0].hi]
}

type helloState uint8

const (
	helloNeedMore helloState = iota // a ClientHello so far, not all of it
	helloComplete
	helloNot // the stream does not begin with a ClientHello, or it is too large
)

// clientHelloIn looks at the start of a handshake stream and returns the
// ClientHello message once all of it is there.
func clientHelloIn(prefix []byte) ([]byte, helloState) {
	if len(prefix) == 0 {
		return nil, helloNeedMore
	}
	if prefix[0] != 0x01 {
		return nil, helloNot
	}
	if len(prefix) < 4 {
		return nil, helloNeedMore
	}
	total := 4 + (int(prefix[1])<<16 | int(prefix[2])<<8 | int(prefix[3]))
	if total > maxCryptoStream {
		return nil, helloNot
	}
	if len(prefix) < total {
		return nil, helloNeedMore
	}
	return prefix[:total], helloComplete
}
