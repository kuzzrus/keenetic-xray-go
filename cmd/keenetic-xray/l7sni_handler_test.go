package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7sni"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7sni/l7snitest"
)

var (
	testClient = [4]byte{192, 168, 1, 5}
	testServer = [4]byte{93, 184, 216, 34}
)

// rawIPv4 wraps an L4 segment in a 20-byte IPv4 header. Checksums stay zero:
// ParseIPv4 does not verify them.
func rawIPv4(proto byte, src, dst [4]byte, l4 []byte) []byte {
	b := make([]byte, 20+len(l4))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8], b[9] = 64, proto
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	copy(b[20:], l4)
	return b
}

// rawTCPv4 builds an IPv4 packet carrying one TCP segment with the given
// options and payload.
func rawTCPv4(src, dst [4]byte, sport, dport uint16, seq uint32, opts, payload []byte) []byte {
	tcpLen := 20 + len(opts)
	tcp := make([]byte, tcpLen+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = byte(tcpLen/4) << 4
	tcp[13] = 0x10 // ACK
	copy(tcp[20:], opts)
	copy(tcp[tcpLen:], payload)
	return rawIPv4(6, src, dst, tcp)
}

func rawUDPv4(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return rawIPv4(17, src, dst, udp)
}

type redirectCall struct {
	ip  string
	ttl time.Duration
}

type dropCall struct {
	proto, src, dst string
	sport, dport    uint
}

// handlerRig is a handler whose side effects are recorded instead of run.
type handlerRig struct {
	h         *l7sniHandler
	stats     *l7sniStats
	mu        sync.Mutex
	redirects []redirectCall
	drops     []dropCall
	logs      []string
	redirErr  error
}

func newRig(t *testing.T) *handlerRig {
	t.Helper()
	resetL7SNIExcludedLog()
	t.Cleanup(resetL7SNIExcludedLog)
	r := &handlerRig{stats: newL7SNIStats(time.Now())}
	r.h = newL7SNIHandler(r.stats)
	r.h.redirect = func(_ context.Context, ip string, ttl time.Duration) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.redirErr != nil {
			return r.redirErr
		}
		r.redirects = append(r.redirects, redirectCall{ip, ttl})
		return nil
	}
	r.h.dropFlow = func(_ context.Context, proto, src, dst string, sport, dport uint) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.drops = append(r.drops, dropCall{proto, src, dst, sport, dport})
	}
	base := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	r.h.now = func() time.Time { return base }
	return r
}

func (r *handlerRig) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (r *handlerRig) count(key string) uint64 {
	return r.stats.snapshot(time.Now(), "").Counts[key]
}

func (r *handlerRig) feed(raw []byte, snap l7sniSnapshot) {
	r.h.handle(context.Background(), raw, snap, r.logf)
}

func (r *handlerRig) logged(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func tcpSnap(domains ...string) l7sniSnapshot {
	set := l7sniDomainSet{}
	for _, d := range domains {
		set[d] = struct{}{}
	}
	return l7sniSnapshot{enabled: true, ttl: time.Hour, domains: set, quic: config.L7SNIQUICOff}
}

func quicSnap(mode string, domains ...string) l7sniSnapshot {
	s := tcpSnap(domains...)
	s.quic = mode
	return s
}

func clientHelloPacket(host string, dport uint16, extra ...[]byte) []byte {
	rec := l7snitest.TLSRecord(l7snitest.ClientHello(host, extra...))
	return rawTCPv4(testClient, testServer, 54321, dport, 1000, nil, rec)
}

// --- TLS / HTTP --------------------------------------------------------

func TestHandler_EmptyACKDoesNotKeepReassemblyAlive(t *testing.T) {
	r := newRig(t)
	r.h.reasm = l7sni.NewReassembler(50*time.Millisecond, 16384)
	key := l7sni.FlowKey{Src: testClient, Dst: testServer, SPort: 54321, DPort: 443}
	const startSeq = uint32(1000)

	// the first 11 bytes of a TLS record that promises 512 more
	first := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}
	r.h.reasm.Start(key, startSeq, first, l7sni.TLSRecordLen(first))
	time.Sleep(150 * time.Millisecond) // well past maxAge

	timestampOpts := []byte{0x01, 0x01, 0x08, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2} // NOP NOP TS
	ack := rawTCPv4(testClient, testServer, 54321, 443, startSeq+uint32(len(first)), timestampOpts, nil)
	if len(ack) != 52 {
		t.Fatalf("setup: the ACK is %d bytes, want the 52 a timestamp ACK has", len(ack))
	}
	r.feed(ack, tcpSnap("example.com"))

	r.h.reasm.Expire(time.Now())
	if r.h.reasm.Lookup(key) {
		t.Error("the flow survived Expire: the empty ACK counted as activity and kept a half-built ClientHello alive")
	}
}

func TestHandler_TLSMatchRedirects(t *testing.T) {
	r := newRig(t)
	r.feed(clientHelloPacket("www.youtube.com", 443), tcpSnap("youtube.com"))

	if len(r.redirects) != 1 || r.redirects[0].ip != "93.184.216.34" || r.redirects[0].ttl != time.Hour {
		t.Fatalf("redirects = %+v, want one for 93.184.216.34 with the configured TTL", r.redirects)
	}
	if len(r.drops) != 1 || r.drops[0].proto != "tcp" || r.drops[0].src != "192.168.1.5" || r.drops[0].dport != 443 || r.drops[0].sport != 54321 {
		t.Errorf("drops = %+v, want the triggering TCP flow", r.drops)
	}
	for _, k := range []string{statTLSHello, statTLSName, statTLSMatch, statTLSActed} {
		if r.count(k) != 1 {
			t.Errorf("%s = %d, want 1", k, r.count(k))
		}
	}
	if !r.logged("www.youtube.com -> 93.184.216.34:443 matched a routes list, redirecting") {
		t.Errorf("log = %q", r.logs)
	}
}

func TestHandler_TLSNoMatchIsCountedButNotActedOn(t *testing.T) {
	r := newRig(t)
	r.feed(clientHelloPacket("www.example.net", 443), tcpSnap("youtube.com"))
	if len(r.redirects) != 0 || len(r.drops) != 0 {
		t.Errorf("acted on a name that is on no list: %+v %+v", r.redirects, r.drops)
	}
	if r.count(statTLSName) != 1 || r.count(statTLSMatch) != 0 {
		t.Errorf("name=%d match=%d", r.count(statTLSName), r.count(statTLSMatch))
	}
}

func TestHandler_TLSECHExtensionIsCounted(t *testing.T) {
	r := newRig(t)
	ech := l7snitest.Extension(l7snitest.ExtECH, make([]byte, 40))
	r.feed(clientHelloPacket("cloudflare-ech.com", 443, ech), tcpSnap("youtube.com"))
	if r.count(statTLSECH) != 1 || r.count(statTLSName) != 1 {
		t.Errorf("ech=%d name=%d, want 1 and 1", r.count(statTLSECH), r.count(statTLSName))
	}
	top := r.stats.snapshot(time.Now(), "").Top
	if len(top) != 1 || top[0].Host != "cloudflare-ech.com" || top[0].ECH != 1 {
		t.Errorf("top = %+v", top)
	}
}

func TestHandler_TLSDisabledOrNoDomainsDoesNothing(t *testing.T) {
	for name, snap := range map[string]l7sniSnapshot{
		"adaptive routing / l7sni off": {enabled: false, domains: l7sniDomainSet{"youtube.com": {}}, quic: config.L7SNIQUICOff},
		"no route lists":               {enabled: true, ttl: time.Hour, quic: config.L7SNIQUICOff},
	} {
		r := newRig(t)
		r.feed(clientHelloPacket("www.youtube.com", 443), snap)
		if len(r.redirects) != 0 || r.count(statTLSHello) != 0 {
			t.Errorf("%s: acted or counted: %+v hello=%d", name, r.redirects, r.count(statTLSHello))
		}
	}
}

func TestHandler_HTTPHostMatchRedirects(t *testing.T) {
	r := newRig(t)
	req := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
	r.feed(rawTCPv4(testClient, testServer, 40000, 80, 1, nil, req), tcpSnap("blocked.example"))
	if len(r.redirects) != 1 || len(r.drops) != 1 || r.drops[0].dport != 80 {
		t.Fatalf("redirects %+v drops %+v", r.redirects, r.drops)
	}
	if r.count(statHTTPHost) != 1 || r.count(statHTTPMatch) != 1 || r.count(statHTTPActed) != 1 {
		t.Errorf("http counters: host=%d match=%d acted=%d", r.count(statHTTPHost), r.count(statHTTPMatch), r.count(statHTTPActed))
	}
}

// AR-07: a second name on an address that just carried another gets the
// short TTL, so one match cannot drag a shared CDN address into the tunnel
// for hours.
func TestHandler_SharedAddressGetsTheShortTTL(t *testing.T) {
	r := newRig(t)
	snap := tcpSnap("youtube.com")
	r.feed(clientHelloPacket("other.example", 443), snap) // seen first, no match
	r.feed(clientHelloPacket("www.youtube.com", 443), snap)
	if len(r.redirects) != 1 || r.redirects[0].ttl != l7sniSharedIPRedirectTTL {
		t.Fatalf("redirects = %+v, want one with the short shared-IP TTL", r.redirects)
	}
}

func TestHandler_ExcludedAddressIsNotRedirected(t *testing.T) {
	r := newRig(t)
	snap := tcpSnap("youtube.com")
	snap.excluded = exclusionsFrom(t, "93.184.216.34  # the test server\n")
	r.feed(clientHelloPacket("www.youtube.com", 443), snap)
	if len(r.redirects) != 0 || len(r.drops) != 0 {
		t.Errorf("an excluded address was redirected: %+v %+v", r.redirects, r.drops)
	}
	if r.count(statTLSMatch) != 1 || r.count(statTLSActed) != 0 {
		t.Errorf("match=%d acted=%d", r.count(statTLSMatch), r.count(statTLSActed))
	}
}

// L7-01: a redirect that failed must not tear down the connection that
// triggered it - the next attempt would go straight back out direct.
func TestHandler_FailedRedirectKeepsTheConnection(t *testing.T) {
	r := newRig(t)
	r.redirErr = errors.New("ipset: boom")
	r.feed(clientHelloPacket("www.youtube.com", 443), tcpSnap("youtube.com"))
	if len(r.drops) != 0 {
		t.Errorf("conntrack entry deleted although the redirect failed: %+v", r.drops)
	}
	if r.count(statTLSMatch) != 1 || r.count(statTLSActed) != 0 || !r.logged("redirecting failed") {
		t.Errorf("match=%d acted=%d log=%q", r.count(statTLSMatch), r.count(statTLSActed), r.logs)
	}
}

// --- QUIC --------------------------------------------------------------

func quicPacket(dgram []byte) []byte { return rawUDPv4(testClient, testServer, 52000, 443, dgram) }

func TestHandler_QUICObserveCountsAndNeverActs(t *testing.T) {
	r := newRig(t)
	r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), quicSnap(config.L7SNIQUICObserve, "example.com"))

	if len(r.redirects) != 0 || len(r.drops) != 0 {
		t.Fatalf("observe mode acted: %+v %+v", r.redirects, r.drops)
	}
	for _, k := range []string{statQUICDatagram, statQUICInitial, statQUICHello, statQUICName, statQUICMatch} {
		if r.count(k) != 1 {
			t.Errorf("%s = %d, want 1", k, r.count(k))
		}
	}
	if r.count(statQUICActed) != 0 || r.count(statQUICECH) != 0 {
		t.Errorf("acted=%d ech=%d", r.count(statQUICActed), r.count(statQUICECH))
	}
	if !r.logged("[наблюдение] QUIC example.com -> 93.184.216.34:443") {
		t.Errorf("log = %q, want the observe line", r.logs)
	}
	top := r.stats.snapshot(time.Now(), "").Top
	if len(top) != 1 || top[0].Proto != "quic" || top[0].Host != "example.com" {
		t.Errorf("top = %+v", top)
	}
}

func TestHandler_QUICObserveLogLineIsRateLimited(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 3; i++ {
		// the same flow again later: a new connection each time
		r.h.qreasm = l7sni.NewQUICReassembler(l7sniReassembleMaxAge, 16)
		r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), quicSnap(config.L7SNIQUICObserve, "example.com"))
	}
	n := 0
	for _, l := range r.logs {
		if strings.Contains(l, "[наблюдение]") {
			n++
		}
	}
	if n != 1 || r.count(statQUICMatch) != 3 {
		t.Errorf("observe lines = %d (want 1), matches counted = %d (want 3)", n, r.count(statQUICMatch))
	}
}

func TestHandler_QUICActRedirectsAndDropsTheUDPFlow(t *testing.T) {
	r := newRig(t)
	r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), quicSnap(config.L7SNIQUICAct, "example.com"))

	if len(r.redirects) != 1 || r.redirects[0].ip != "93.184.216.34" {
		t.Fatalf("redirects = %+v", r.redirects)
	}
	if len(r.drops) != 1 || r.drops[0].proto != "udp" || r.drops[0].sport != 52000 || r.drops[0].dport != 443 {
		t.Errorf("drops = %+v, want the UDP flow of the datagram", r.drops)
	}
	if r.count(statQUICMatch) != 1 || r.count(statQUICActed) != 1 {
		t.Errorf("match=%d acted=%d", r.count(statQUICMatch), r.count(statQUICActed))
	}
	if !r.logged("example.com -> 93.184.216.34:443 (QUIC) matched a routes list, redirecting") {
		t.Errorf("log = %q", r.logs)
	}
}

// With adaptive routing off there is nowhere to redirect to: act degrades to
// observe (the snapshot says enabled=false), counting but not acting.
func TestHandler_QUICActWithoutAdaptiveRoutingOnlyObserves(t *testing.T) {
	r := newRig(t)
	snap := quicSnap(config.L7SNIQUICAct, "example.com")
	snap.enabled = false
	r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), snap)
	if len(r.redirects) != 0 || r.count(statQUICActed) != 0 || r.count(statQUICMatch) != 1 {
		t.Errorf("redirects %+v acted=%d match=%d", r.redirects, r.count(statQUICActed), r.count(statQUICMatch))
	}
}

func TestHandler_QUICOffIgnoresUDP(t *testing.T) {
	r := newRig(t)
	r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), quicSnap(config.L7SNIQUICOff, "example.com"))
	if r.count(statQUICDatagram) != 0 || len(r.redirects) != 0 {
		t.Errorf("QUIC off, but datagram=%d redirects=%+v", r.count(statQUICDatagram), r.redirects)
	}
}

func TestHandler_QUICOnlyOnPort443(t *testing.T) {
	r := newRig(t)
	r.feed(rawUDPv4(testClient, testServer, 52000, 8443, l7snitest.RFC9001ClientInitial()), quicSnap(config.L7SNIQUICObserve, "example.com"))
	if r.count(statQUICDatagram) != 0 {
		t.Error("a datagram to UDP/8443 was parsed as QUIC")
	}
}

// QUIC observe needs no route list and no adaptive routing: it only counts.
func TestHandler_QUICObserveWorksWithoutRouteLists(t *testing.T) {
	r := newRig(t)
	snap := l7sniSnapshot{quic: config.L7SNIQUICObserve} // nothing else configured
	r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), snap)
	if r.count(statQUICName) != 1 || r.count(statQUICMatch) != 0 {
		t.Errorf("name=%d match=%d", r.count(statQUICName), r.count(statQUICMatch))
	}
}

// A client repeats its first flight; the capture filter lets the first four
// datagrams of a flow through. The connection is still counted once.
func TestHandler_QUICRetransmissionIsCountedOnce(t *testing.T) {
	r := newRig(t)
	snap := quicSnap(config.L7SNIQUICAct, "example.com")
	for i := 0; i < 3; i++ {
		r.feed(quicPacket(l7snitest.RFC9001ClientInitial()), snap)
	}
	if r.count(statQUICHello) != 1 || len(r.redirects) != 1 || len(r.drops) != 1 {
		t.Errorf("hello=%d redirects=%d drops=%d, want 1 each", r.count(statQUICHello), len(r.redirects), len(r.drops))
	}
	if r.count(statQUICInitial) != 3 {
		t.Errorf("initials decrypted = %d, want 3 (each datagram is still parsed)", r.count(statQUICInitial))
	}
	// the repeats are not a ClientHello that goes on in a later datagram
	if r.count(statQUICWaiting) != 0 {
		t.Errorf("waiting = %d, want 0: retransmissions of a finished ClientHello counted as pending", r.count(statQUICWaiting))
	}
}

// A post-quantum-sized ClientHello continues in a second datagram.
func TestHandler_QUICClientHelloAcrossTwoDatagrams(t *testing.T) {
	r := newRig(t)
	ch := l7snitest.ClientHello("www.instagram.com", l7snitest.Extension(0x0033, make([]byte, 1500)))
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	dg1 := l7snitest.Initial{DCID: dcid, PN: 0, PNLen: 1, Frames: l7snitest.CryptoFrame(0, ch[:900]), Len: 1252}.Datagram()
	dg2 := l7snitest.Initial{DCID: dcid, PN: 1, PNLen: 1, Frames: l7snitest.CryptoFrame(900, ch[900:]), Len: 1252}.Datagram()
	snap := quicSnap(config.L7SNIQUICAct, "instagram.com")

	r.feed(quicPacket(dg1), snap)
	if r.count(statQUICWaiting) != 1 || r.count(statQUICHello) != 0 || len(r.redirects) != 0 {
		t.Fatalf("after the first datagram: waiting=%d hello=%d redirects=%d", r.count(statQUICWaiting), r.count(statQUICHello), len(r.redirects))
	}
	r.feed(quicPacket(dg2), snap)
	if r.count(statQUICHello) != 1 || r.count(statQUICName) != 1 || len(r.redirects) != 1 {
		t.Errorf("after the second: hello=%d name=%d redirects=%d", r.count(statQUICHello), r.count(statQUICName), len(r.redirects))
	}
	if r.count(statQUICWaiting) != 1 {
		t.Errorf("waiting = %d, want 1: only the first datagram left the ClientHello incomplete", r.count(statQUICWaiting))
	}
}

func TestHandler_QUICECHExtensionIsCounted(t *testing.T) {
	r := newRig(t)
	ch := l7snitest.ClientHello("cloudflare-ech.com", l7snitest.Extension(l7snitest.ExtECH, make([]byte, 100)))
	dg := l7snitest.Initial{DCID: l7snitest.RFC9001DCID, PN: 0, Frames: l7snitest.CryptoFrame(0, ch)}.Datagram()
	r.feed(quicPacket(dg), quicSnap(config.L7SNIQUICObserve))
	if r.count(statQUICECH) != 1 || r.count(statQUICHello) != 1 || r.count(statQUICName) != 1 {
		t.Errorf("ech=%d hello=%d name=%d", r.count(statQUICECH), r.count(statQUICHello), r.count(statQUICName))
	}
}

func TestHandler_QUICUnparseableDatagramsAreCountedByReason(t *testing.T) {
	r := newRig(t)
	snap := quicSnap(config.L7SNIQUICObserve)
	good := l7snitest.RFC9001ClientInitial()

	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 1
	r.feed(quicPacket(tampered), snap)

	short := append([]byte(nil), good...)
	short[0] = 0x40 // a short header
	r.feed(quicPacket(short), snap)

	draft := append([]byte(nil), good...)
	copy(draft[1:5], []byte{0xff, 0x00, 0x00, 0x1d})
	r.feed(quicPacket(draft), snap)

	rng := rand.New(rand.NewSource(7))
	noise := make([]byte, 1250)
	rng.Read(noise)
	noise[0] = 0xc0
	copy(noise[1:5], []byte{0, 0, 0, 1})
	noise[5] = 8
	r.feed(quicPacket(noise), snap)

	if r.count(statQUICDatagram) != 4 || r.count(statQUICInitial) != 0 {
		t.Fatalf("datagram=%d initial=%d", r.count(statQUICDatagram), r.count(statQUICInitial))
	}
	if r.count(statQUICAuthFailed) < 1 || r.count(statQUICNotInitial) != 1 || r.count(statQUICBadVersion) != 1 {
		t.Errorf("auth=%d notInitial=%d badVersion=%d malformed=%d",
			r.count(statQUICAuthFailed), r.count(statQUICNotInitial), r.count(statQUICBadVersion), r.count(statQUICMalformed))
	}
}
