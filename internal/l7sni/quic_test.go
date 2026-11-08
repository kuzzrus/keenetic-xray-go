package l7sni

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

var rfcDCID = []byte{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08}

type rfcVector struct {
	name    string
	version uint32
	header  string
	frames  string
	packet  string
}

func rfcVectors() []rfcVector {
	return []rfcVector{
		{"RFC 9001 A.2 (v1)", QUICVersion1, rfc9001V1Header, rfc9001V1Frames, rfc9001V1Packet},
		{"RFC 9369 A.2 (v2)", QUICVersion2, rfc9369V2Header, rfc9369V2Frames, rfc9369V2Packet},
	}
}

// TestParseQUICInitial_RFCVectors: the packets of RFC 9001 A.2 and RFC 9369
// A.2 decrypt, and the ClientHello inside names example.com.
func TestParseQUICInitial_RFCVectors(t *testing.T) {
	for _, v := range rfcVectors() {
		t.Run(v.name, func(t *testing.T) {
			got, st := ParseQUICInitial(mustHex(t, v.packet))
			if st != QUICOK {
				t.Fatalf("status = %d, want QUICOK", st)
			}
			if got.Version != v.version {
				t.Errorf("version = %#x, want %#x", got.Version, v.version)
			}
			if len(got.Fragments) != 1 || got.Fragments[0].Offset != 0 {
				t.Fatalf("fragments = %+v, want exactly one at offset 0", got.Fragments)
			}
			frames := mustHex(t, v.frames)
			if !bytes.Equal(got.Fragments[0].Data, frames[4:]) { // 0x06, offset 0, 2-byte length
				t.Errorf("CRYPTO data differs from the RFC's ClientHello (%d vs %d bytes)", len(got.Fragments[0].Data), len(frames)-4)
			}
			info, ok := ParseClientHello(got.Fragments[0].Data)
			if !ok || info.Host != "example.com" || info.ECH {
				t.Errorf("ParseClientHello = %+v, %v, want example.com without ECH", info, ok)
			}
		})
	}
}

// TestSealer_ReproducesRFCPackets pins the test-only sealer to the RFC: it
// must turn the RFC's plaintext into the RFC's packet byte for byte. Without
// this the synthetic packets of the other tests would only prove that the
// parser and the sealer agree with each other.
func TestSealer_ReproducesRFCPackets(t *testing.T) {
	for _, v := range rfcVectors() {
		t.Run(v.name, func(t *testing.T) {
			header := mustHex(t, v.header)
			plain := append(mustHex(t, v.frames), make([]byte, 1162-len(mustHex(t, v.frames)))...)
			got := sealInitialPacket(t, v.version, rfcDCID, header, len(header)-4, 4, plain)
			want := mustHex(t, v.packet)
			if !bytes.Equal(got, want) {
				t.Fatalf("sealed packet differs from the RFC's (%d vs %d bytes)", len(got), len(want))
			}
		})
	}
}

func TestParseQUICInitial_TamperedPacketFailsAuth(t *testing.T) {
	good := mustHex(t, rfc9001V1Packet)
	for _, tc := range []struct {
		name string
		at   int
	}{
		{"last byte (tag)", len(good) - 1},
		{"a ciphertext byte", 600},
		{"a Destination Connection ID byte", 8}, // different keys
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := append([]byte(nil), good...)
			pkt[tc.at] ^= 0x01
			if _, st := ParseQUICInitial(pkt); st != QUICAuthFailed {
				t.Errorf("status = %d, want QUICAuthFailed", st)
			}
		})
	}
}

func TestParseQUICInitial_NotInitialAndUnsupported(t *testing.T) {
	good := mustHex(t, rfc9001V1Packet)
	with := func(mod func([]byte)) []byte {
		p := append([]byte(nil), good...)
		mod(p)
		return p
	}
	cases := []struct {
		name string
		pkt  []byte
		want QUICStatus
	}{
		{"empty", nil, QUICNotInitial},
		{"short header", with(func(p []byte) { p[0] = 0x40 }), QUICNotInitial},
		{"v1 Handshake packet", with(func(p []byte) { p[0] = 0xe0 }), QUICNotInitial},
		{"v1 0-RTT packet", with(func(p []byte) { p[0] = 0xd0 }), QUICNotInitial},
		{"fixed bit clear", with(func(p []byte) { p[0] = 0x80 }), QUICNotInitial},
		{"v2 with v1 type bits", with(func(p []byte) { copy(p[1:5], []byte{0x6b, 0x33, 0x43, 0xcf}) }), QUICNotInitial},
		{"version negotiation (0)", with(func(p []byte) { copy(p[1:5], []byte{0, 0, 0, 0}) }), QUICUnsupportedVersion},
		{"draft-29", with(func(p []byte) { copy(p[1:5], []byte{0xff, 0x00, 0x00, 0x1d}) }), QUICUnsupportedVersion},
		{"a future version", with(func(p []byte) { copy(p[1:5], []byte{0x70, 0x00, 0x00, 0x01}) }), QUICUnsupportedVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, st := ParseQUICInitial(tc.pkt); st != tc.want {
				t.Errorf("status = %d, want %d", st, tc.want)
			}
		})
	}
}

// TestParseQUICInitial_TruncationNeverSucceedsOrPanics: every proper prefix
// of a valid datagram is rejected, none of them panics.
func TestParseQUICInitial_TruncationNeverSucceedsOrPanics(t *testing.T) {
	good := mustHex(t, rfc9369V2Packet)
	for n := 0; n < len(good); n++ {
		if _, st := ParseQUICInitial(good[:n]); st == QUICOK {
			t.Fatalf("a %d-byte prefix of a %d-byte Initial parsed as QUICOK", n, len(good))
		}
	}
}

// TestParseQUICInitial_GarbageDoesNotPanic throws random UDP payloads, many
// of them shaped like long headers of a supported version, at the parser.
func TestParseQUICInitial_GarbageDoesNotPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		p := make([]byte, rng.Intn(1500))
		rng.Read(p)
		if len(p) > 6 && i%2 == 0 {
			p[0] = 0xc0 | byte(rng.Intn(4))<<4 | byte(rng.Intn(4))
			if i%4 == 0 {
				copy(p[1:5], []byte{0, 0, 0, 1})
			} else {
				copy(p[1:5], []byte{0x6b, 0x33, 0x43, 0xcf})
			}
			p[5] = byte(rng.Intn(24)) // DCID length, sometimes out of range
		}
		ParseQUICInitial(p)
	}
}

// TestCryptoFragments walks hand-built frame sequences, including the
// layouts Chrome produces (CRYPTO frames in any order between PADDING and
// PING) and an ACK ahead of them.
func TestCryptoFragments(t *testing.T) {
	a, b, c := []byte("AAAA"), []byte("BB"), []byte("CCCCCC")
	t.Run("order and interleaving preserved", func(t *testing.T) {
		plain := concat(paddingFrames(3), cryptoFrame(6, c), pingFrame(), cryptoFrame(0, a), paddingFrames(5), cryptoFrame(4, b))
		frags, ok := cryptoFragments(plain)
		if !ok || len(frags) != 3 {
			t.Fatalf("got %d fragments, ok=%v", len(frags), ok)
		}
		want := []CryptoFragment{{6, c}, {0, a}, {4, b}}
		for i, w := range want {
			if frags[i].Offset != w.Offset || !bytes.Equal(frags[i].Data, w.Data) {
				t.Errorf("fragment %d = %+v, want %+v", i, frags[i], w)
			}
		}
	})
	t.Run("CRYPTO after ACK and ACK_ECN", func(t *testing.T) {
		for _, ecn := range []bool{false, true} {
			plain := concat(ackFrame(ecn, 3), cryptoFrame(0, a))
			frags, ok := cryptoFragments(plain)
			if !ok || len(frags) != 1 || !bytes.Equal(frags[0].Data, a) {
				t.Errorf("ecn=%v: got %+v, ok=%v, want the CRYPTO frame behind the ACK", ecn, frags, ok)
			}
		}
	})
	t.Run("stops at a frame a client Initial may not carry", func(t *testing.T) {
		plain := concat(cryptoFrame(0, a), []byte{0x1e /* HANDSHAKE_DONE */}, cryptoFrame(4, b))
		frags, ok := cryptoFragments(plain)
		if !ok || len(frags) != 1 {
			t.Errorf("got %d fragments, ok=%v, want the one before the forbidden frame", len(frags), ok)
		}
	})
	t.Run("a CRYPTO frame longer than the payload is malformed", func(t *testing.T) {
		plain := cryptoFrame(0, a)
		if _, ok := cryptoFragments(plain[:len(plain)-1]); ok {
			t.Error("a truncated CRYPTO frame parsed as ok")
		}
	})
	t.Run("a huge ACK range count is malformed, not a loop", func(t *testing.T) {
		plain := []byte{0x02}
		plain = appendVarint(plain, 1)
		plain = appendVarint(plain, 1)
		plain = appendVarint(plain, 1<<40) // range count
		plain = appendVarint(plain, 1)
		if _, ok := cryptoFragments(plain); ok {
			t.Error("an ACK frame claiming 2^40 ranges parsed as ok")
		}
	})
}

// TestQUICFlight_ChromeStyleSingleDatagram: a ClientHello cut into six CRYPTO
// frames, sent out of order with PADDING, PING and an ACK between them, in
// one datagram: ParseQUICInitial plus the reassembler give back the original
// message, and the name in it.
func TestQUICFlight_ChromeStyleSingleDatagram(t *testing.T) {
	for _, version := range []uint32{QUICVersion1, QUICVersion2} {
		ch := buildClientHelloMsg("rr1---sn-abc.googlevideo.com", encodeExt(0x0010, make([]byte, 500)))
		if len(ch) < 400 {
			t.Fatalf("setup: ClientHello is only %d bytes, the cuts below need more", len(ch))
		}
		cuts := []int{0, 100, 101, 180, 260, 330, len(ch)}
		piece := func(i int) []byte { return cryptoFrame(uint64(cuts[i]), ch[cuts[i]:cuts[i+1]]) }
		frames := concat(
			ackFrame(false, 2), paddingFrames(7),
			piece(3), pingFrame(), piece(0), piece(5), paddingFrames(3), piece(1), piece(4), pingFrame(), piece(2),
		)
		pkt := buildInitial(t, version, rfcDCID, 7, frames, 1252)
		if len(pkt) != 1252 {
			t.Fatalf("datagram is %d bytes", len(pkt))
		}

		init, st := ParseQUICInitial(pkt)
		if st != QUICOK || len(init.Fragments) != 6 {
			t.Fatalf("v%#x: status %d, %d fragments, want OK and 6", version, st, len(init.Fragments))
		}
		r := NewQUICReassembler(5*time.Second, 16)
		key := FlowKey{Src: [4]byte{192, 168, 1, 2}, Dst: [4]byte{142, 250, 1, 1}, SPort: 50000, DPort: 443}
		hs, done := r.Feed(key, init.Fragments, time.Now())
		if !done || !bytes.Equal(hs, ch) {
			t.Fatalf("v%#x: Feed done=%v, message equal=%v", version, done, bytes.Equal(hs, ch))
		}
		if r.Len() != 0 {
			t.Errorf("a flight finished in one datagram left %d flows behind", r.Len())
		}
		info, ok := ParseClientHello(hs)
		if !ok || info.Host != "rr1---sn-abc.googlevideo.com" {
			t.Errorf("ParseClientHello = %+v, %v", info, ok)
		}
	}
}

// TestQUICFlight_PostQuantumClientHelloSpansTwoDatagrams: a ClientHello with
// a post-quantum-sized key share does not fit one Initial; its CRYPTO stream
// continues in the next datagram. Fed in either order the message comes back
// whole once the second one is in.
func TestQUICFlight_PostQuantumClientHelloSpansTwoDatagrams(t *testing.T) {
	// 1500 bytes of key_share: X25519 + ML-KEM-768 is 1216, and browsers add
	// more, so this is the size a real ClientHello has now.
	ch := buildClientHelloMsg("www.instagram.com", encodeExt(0x0033, bytes.Repeat([]byte{0x5a}, 1500)))
	if len(ch) < 1500 {
		t.Fatalf("setup: ClientHello is only %d bytes", len(ch))
	}
	split := 900
	dg1 := buildInitial(t, QUICVersion1, rfcDCID, 0, cryptoFrame(0, ch[:split]), 1252)
	dg2 := buildInitial(t, QUICVersion1, rfcDCID, 1, cryptoFrame(uint64(split), ch[split:]), 1252)

	for _, order := range []struct {
		name string
		seq  [][]byte
	}{{"in order", [][]byte{dg1, dg2}}, {"reversed", [][]byte{dg2, dg1}}} {
		t.Run(order.name, func(t *testing.T) {
			r := NewQUICReassembler(5*time.Second, 16)
			key := FlowKey{Src: [4]byte{10, 0, 0, 2}, Dst: [4]byte{157, 240, 1, 1}, SPort: 41000, DPort: 443}
			for i, dg := range order.seq {
				init, st := ParseQUICInitial(dg)
				if st != QUICOK {
					t.Fatalf("datagram %d: status %d", i, st)
				}
				hs, done := r.Feed(key, init.Fragments, time.Now())
				if i == 0 {
					if done {
						t.Fatal("the first datagram alone completed the ClientHello")
					}
					if r.Len() != 1 {
						t.Fatalf("after the first datagram the reassembler holds %d flights, want 1", r.Len())
					}
					continue
				}
				if !done || !bytes.Equal(hs, ch) {
					t.Fatalf("second datagram: done=%v, message equal=%v", done, bytes.Equal(hs, ch))
				}
			}
			if r.Len() != 0 {
				t.Errorf("%d flights left after completion", r.Len())
			}
		})
	}
}

func TestQUICReassembler_Bounds(t *testing.T) {
	now := time.Now()
	half := func(n int) []CryptoFragment { // the start of a ClientHello that promises more
		return []CryptoFragment{{0, append([]byte{0x01, 0x00, 0x04, 0x00}, make([]byte, n)...)}}
	}
	keyN := func(n int) FlowKey { return FlowKey{SPort: uint16(1000 + n), DPort: 443} }

	t.Run("flights beyond maxFlows are not tracked", func(t *testing.T) {
		r := NewQUICReassembler(time.Second, 2)
		for i := 0; i < 5; i++ {
			r.Feed(keyN(i), half(10), now)
		}
		if r.Len() != 2 {
			t.Errorf("holds %d flights, want the cap of 2", r.Len())
		}
	})
	t.Run("Expire drops stale flights", func(t *testing.T) {
		r := NewQUICReassembler(time.Second, 8)
		r.Feed(keyN(0), half(10), now)
		r.Feed(keyN(1), half(10), now.Add(3*time.Second))
		r.Expire(now.Add(4 * time.Second))
		if r.Len() != 1 {
			t.Errorf("holds %d flights after Expire, want 1 (only the recent one)", r.Len())
		}
	})
	t.Run("a stream that does not start with a ClientHello is dropped at once", func(t *testing.T) {
		r := NewQUICReassembler(time.Second, 8)
		if _, done := r.Feed(keyN(0), []CryptoFragment{{0, []byte{0x02, 0, 0, 1, 9}}}, now); done || r.Len() != 0 {
			t.Errorf("done=%v, holds %d", done, r.Len())
		}
	})
	t.Run("a fragment beyond the stream cap drops the flight", func(t *testing.T) {
		r := NewQUICReassembler(time.Second, 8)
		r.Feed(keyN(0), half(10), now)
		r.Feed(keyN(0), []CryptoFragment{{maxCryptoStream + 1, []byte{1}}}, now)
		if r.Len() != 0 {
			t.Errorf("holds %d flights, want the damaged one gone", r.Len())
		}
	})
	t.Run("too many holes drops the flight", func(t *testing.T) {
		r := NewQUICReassembler(time.Second, 8)
		var frags []CryptoFragment
		for i := 0; i <= maxCryptoSpans; i++ {
			frags = append(frags, CryptoFragment{uint64(i * 10), []byte{0x01, 0x00}}) // disjoint 2-byte pieces
		}
		if _, done := r.Feed(keyN(0), frags, now); done || r.Len() != 0 {
			t.Errorf("done=%v, holds %d", done, r.Len())
		}
	})
}

func TestCryptoStream_MergesOverlapsAndRetransmissions(t *testing.T) {
	var s cryptoStream
	if !s.add(5, []byte("56789")) || s.prefix() != nil {
		t.Fatal("a piece that does not start at 0 must not produce a prefix")
	}
	if !s.add(0, []byte("01234")) || string(s.prefix()) != "0123456789" {
		t.Fatalf("prefix = %q, want the two touching pieces joined", s.prefix())
	}
	if !s.add(3, []byte("34567")) || string(s.prefix()) != "0123456789" { // a retransmission of the middle
		t.Fatalf("prefix = %q after an overlapping retransmission", s.prefix())
	}
	if !s.add(10, []byte("ab")) || string(s.prefix()) != "0123456789ab" {
		t.Fatalf("prefix = %q after an extension", s.prefix())
	}
}

// TestQUICReassembler_RetransmittedFlightIsReportedOnce: a client repeats
// its first flight when it hears nothing back, and the capture filter lets
// the first four datagrams of a flow through, so the same ClientHello comes
// round again. It must be handed out once, then again only after the memory
// of it has expired (a new connection from the same port).
func TestQUICReassembler_RetransmittedFlightIsReportedOnce(t *testing.T) {
	ch := buildClientHelloMsg("www.youtube.com")
	frags := []CryptoFragment{{0, ch}}
	r := NewQUICReassembler(3*time.Second, 16)
	key := FlowKey{Src: [4]byte{192, 168, 1, 7}, Dst: [4]byte{142, 250, 74, 14}, SPort: 52000, DPort: 443}
	t0 := time.Now()

	if hs, done := r.Feed(key, frags, t0); !done || !bytes.Equal(hs, ch) {
		t.Fatalf("first flight: done=%v", done)
	}
	if _, done := r.Feed(key, frags, t0.Add(300*time.Millisecond)); done {
		t.Error("the retransmitted flight was handed out a second time")
	}
	if _, done := r.Feed(key, frags, t0.Add(2900*time.Millisecond)); done {
		t.Error("a retransmission inside the memory window was handed out again")
	}
	r.Expire(t0.Add(10 * time.Second))
	if _, done := r.Feed(key, frags, t0.Add(10*time.Second)); !done {
		t.Error("after the memory expired, a new connection on the same flow key was ignored")
	}
}

func TestQUICReassembler_FinishedMemoryIsBounded(t *testing.T) {
	ch := buildClientHelloMsg("example.com")
	r := NewQUICReassembler(time.Minute, 4)
	now := time.Now()
	for i := 0; i < 50; i++ {
		r.Feed(FlowKey{SPort: uint16(2000 + i), DPort: 443}, []CryptoFragment{{0, ch}}, now)
	}
	r.mu.Lock()
	n := len(r.finished)
	r.mu.Unlock()
	if n > 4 {
		t.Errorf("remembers %d finished flows, want at most maxFlows (4)", n)
	}
}
