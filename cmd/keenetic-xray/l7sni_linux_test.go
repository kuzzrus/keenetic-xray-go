//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7sni"
)

// rawTCPv4 builds an IPv4 packet carrying one TCP segment with the given
// options and payload. Checksums stay zero: ParseIPv4 does not verify them.
func rawTCPv4(src, dst [4]byte, sport, dport uint16, seq uint32, opts, payload []byte) []byte {
	tcpLen := 20 + len(opts)
	total := 20 + tcpLen + len(payload)
	b := make([]byte, total)
	b[0] = 0x45 // IPv4, 20-byte header
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8], b[9] = 64, 6
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	tcp := b[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = 0x10 // ACK
	copy(tcp[20:], opts)
	copy(b[20+tcpLen:], payload)
	return b
}

// TestL7SNIHandlePacket_EmptyACKDoesNotKeepReassemblyAlive: the NFLOG
// filter's 41-byte bound lets a client's empty ACK carrying a TCP timestamp
// (52 bytes) through, and one arriving at exactly the sequence number a
// half-built ClientHello is waiting for used to refresh that flow's expiry.
// Such an ACK has to be dropped without being treated as activity, so the
// flow still times out.
func TestL7SNIHandlePacket_EmptyACKDoesNotKeepReassemblyAlive(t *testing.T) {
	src, dst := [4]byte{192, 168, 1, 5}, [4]byte{93, 184, 216, 34}
	key := l7sni.FlowKey{Src: src, Dst: dst, SPort: 54321, DPort: 443}
	const startSeq = uint32(1000)

	// the first 11 bytes of a TLS record that promises 512 more
	first := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}
	reasm := l7sni.NewReassembler(50*time.Millisecond, 16384)
	reasm.Start(key, startSeq, first, l7sni.TLSRecordLen(first))
	if !reasm.Lookup(key) {
		t.Fatal("setup: the reassembly did not start")
	}

	time.Sleep(150 * time.Millisecond) // well past maxAge

	timestampOpts := []byte{0x01, 0x01, 0x08, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2} // NOP NOP TS(val=1, ecr=2)
	ack := rawTCPv4(src, dst, 54321, 443, startSeq+uint32(len(first)), timestampOpts, nil)
	if len(ack) != 52 {
		t.Fatalf("setup: the ACK is %d bytes, want the 52 a timestamp ACK has", len(ack))
	}
	snap := l7sniSnapshot{enabled: true, ttl: time.Hour, domains: l7sniDomainSet{"example.com": {}}}
	l7SNIHandlePacket(context.Background(), ack, reasm, newL7SNISharedIPTracker(), snap, func(string, ...any) {})

	reasm.Expire(time.Now())
	if reasm.Lookup(key) {
		t.Error("the flow survived Expire: the empty ACK counted as activity and kept a half-built ClientHello alive")
	}
}

// TestL7SNIClassifySession_DisabledReturnsNotStarted confirms the
// contract l7SNIClassifyLoop's own retry logic depends on (L7-02): a
// session that never actually began capturing must report
// started=false, so the outer loop doesn't spin retrying a condition
// (the feature being off) that won't resolve itself moments later.
func TestL7SNIClassifySession_DisabledReturnsNotStarted(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = false
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	started, err := l7SNIClassifySession(context.Background(), func(string, ...any) {})
	if started {
		t.Error("started = true, want false -- L7SNI.Enabled is off")
	}
	if err != nil {
		t.Errorf("err = %v, want nil for a deliberately-off feature", err)
	}
}

// TestL7SNIClassifySession_NoRouterReturnsNotStarted mirrors
// adaptiveRouteClassifyLoop's own no-router test: this dev/CI
// environment has no real keenetic.Available(), so an enabled feature
// still can't actually start, and must report that cleanly (not
// started, no error) rather than being treated as a failure worth
// retrying.
func TestL7SNIClassifySession_NoRouterReturnsNotStarted(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = true
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	started, err := l7SNIClassifySession(context.Background(), func(string, ...any) {})
	if started {
		t.Error("started = true, want false -- no real router in this environment")
	}
	if err != nil {
		t.Errorf("err = %v, want nil -- no ndmc is a clean not-started outcome, not a failure", err)
	}
}

// TestL7SNIClassifyLoop_DisabledStopsWithoutRetrying is L7-02's own
// regression test for the retry-vs-give-up split: a genuinely disabled
// feature must not spin l7SNIClassifyLoop's new retry loop -- it should
// return promptly, the same one-shot behavior the pre-L7-02 code always
// had for this exact case. Uses an uncancelled context deliberately: if
// this regressed into retrying a condition that will never resolve, the
// goroutine would still be running when the timeout below fires, which
// is exactly the failure this guards against.
func TestL7SNIClassifyLoop_DisabledStopsWithoutRetrying(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = false
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		l7SNIClassifyLoop(context.Background(), func(string, ...any) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("l7SNIClassifyLoop did not return promptly for a disabled feature -- it must not retry a condition that won't resolve on its own")
	}
}
