package l7sni

import (
	"bytes"
	"testing"
	"time"
)

func testKey() FlowKey {
	return FlowKey{
		Src: [4]byte{192, 168, 1, 5}, Dst: [4]byte{93, 184, 216, 34},
		SPort: 54321, DPort: 443,
	}
}

func TestReassembler_TwoSegmentClientHello(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	first, second := rec[:20], rec[20:]

	r := NewReassembler(time.Minute, 4096)
	key := testKey()
	const startSeq = uint32(1000)

	r.Start(key, startSeq, first, len(rec))
	if !r.Lookup(key) {
		t.Fatal("Lookup after Start: want true")
	}

	full, complete := r.Feed(key, startSeq+uint32(len(first)), second)
	if !complete {
		t.Fatal("Feed with the remaining bytes: want complete=true")
	}
	if !bytes.Equal(full, rec) {
		t.Fatalf("reassembled record does not match the original (%d vs %d bytes)", len(full), len(rec))
	}
	if r.Lookup(key) {
		t.Error("flow should be removed from the table once complete")
	}

	host, ok := ExtractTLSSNI(full)
	if !ok || host != "example.com" {
		t.Fatalf("ExtractTLSSNI(reassembled) = %q, %v, want example.com, true", host, ok)
	}
}

func TestReassembler_ThreeSegments(t *testing.T) {
	rec := buildTLSClientHello("split-three-ways.example", false)
	third := len(rec) / 3
	seg1, seg2, seg3 := rec[:third], rec[third:2*third], rec[2*third:]

	r := NewReassembler(time.Minute, 4096)
	key := testKey()
	const startSeq = uint32(5000)

	r.Start(key, startSeq, seg1, len(rec))
	if _, complete := r.Feed(key, startSeq+uint32(len(seg1)), seg2); complete {
		t.Fatal("Feed after 2 of 3 segments: want complete=false")
	}
	full, complete := r.Feed(key, startSeq+uint32(len(seg1)+len(seg2)), seg3)
	if !complete || !bytes.Equal(full, rec) {
		t.Fatalf("Feed with the final segment: complete=%v, want true and matching bytes", complete)
	}
}

func TestReassembler_OutOfOrderSegmentIsDropped(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	first, second := rec[:20], rec[20:]

	r := NewReassembler(time.Minute, 4096)
	key := testKey()
	const startSeq = uint32(1000)

	r.Start(key, startSeq, first, len(rec))
	// Wrong offset -- as if a segment further ahead arrived first.
	if _, complete := r.Feed(key, startSeq+uint32(len(second)), second); complete {
		t.Error("Feed with a segment at the wrong offset: want complete=false, not a corrupted merge")
	}
	// The flow is still there, still waiting for the *correct* next segment.
	if !r.Lookup(key) {
		t.Error("flow should still be waiting after an out-of-order segment was dropped")
	}
}

func TestReassembler_UnknownFlowFeedIsNoop(t *testing.T) {
	r := NewReassembler(time.Minute, 4096)
	if _, complete := r.Feed(testKey(), 0, []byte("x")); complete {
		t.Error("Feed on a flow that was never Start'd: want complete=false")
	}
}

func TestReassembler_StartRefusesOversized(t *testing.T) {
	r := NewReassembler(time.Minute, 100)
	key := testKey()
	r.Start(key, 1000, []byte("short prefix"), 100000) // want > maxSize
	if r.Lookup(key) {
		t.Error("Start with want > maxSize: should not have started buffering")
	}
}

func TestReassembler_Drop(t *testing.T) {
	r := NewReassembler(time.Minute, 4096)
	key := testKey()
	r.Start(key, 1000, []byte("partial"), 500)
	r.Drop(key)
	if r.Lookup(key) {
		t.Error("Drop should remove the in-progress flow")
	}
}

func TestReassembler_Expire(t *testing.T) {
	r := NewReassembler(time.Minute, 4096)
	key := testKey()
	t0 := time.Now()

	r.Start(key, 1000, []byte("partial"), 500)
	r.Expire(t0.Add(30 * time.Second)) // younger than maxAge
	if !r.Lookup(key) {
		t.Error("Expire before maxAge elapsed: flow should still be there")
	}

	r.Expire(t0.Add(2 * time.Minute)) // older than maxAge
	if r.Lookup(key) {
		t.Error("Expire after maxAge elapsed: flow should be gone")
	}
}

func TestReassembler_ReplacesPriorIncompleteFlow(t *testing.T) {
	rec := buildTLSClientHello("second-attempt.example", false)
	r := NewReassembler(time.Minute, 4096)
	key := testKey()

	r.Start(key, 1000, []byte("stale first attempt"), 999) // never completed
	r.Start(key, 2000, rec[:20], len(rec))                 // a fresh attempt on the same flow

	full, complete := r.Feed(key, 2000+uint32(20), rec[20:])
	if !complete || !bytes.Equal(full, rec) {
		t.Fatalf("Feed against the replaced attempt: complete=%v, want true with the second record's bytes", complete)
	}
}
