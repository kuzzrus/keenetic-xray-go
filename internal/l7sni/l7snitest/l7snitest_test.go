package l7snitest

import (
	"bytes"
	"testing"
)

// TestBuildReproducesTheRFCPacket: the builder turns the RFC's plaintext
// frames into the RFC's protected packet byte for byte. This is what makes
// the datagrams other packages' tests build with it worth anything.
func TestBuildReproducesTheRFCPacket(t *testing.T) {
	got := Initial{
		Version: Version1, DCID: RFC9001DCID, PN: 2, PNLen: 4,
		Frames: mustHex(rfc9001V1Frames), Len: 1200,
	}.Datagram()
	if want := mustHex(rfc9001V1Packet); !bytes.Equal(got, want) {
		t.Fatalf("built packet differs from the RFC's (%d vs %d bytes)", len(got), len(want))
	}
}

func TestRFC9001ClientInitialIsA1200ByteDatagram(t *testing.T) {
	if p := RFC9001ClientInitial(); len(p) != 1200 || p[0]&0x80 == 0 {
		t.Errorf("RFC9001ClientInitial() = %d bytes, first byte %#x", len(p), p[0])
	}
}
