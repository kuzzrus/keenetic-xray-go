package dnsupstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// probeName is the domain the probe resolves. Something that always
// exists and every resolver will answer.
const probeName = "example.com"

// newDoTTLSConfig builds the client TLS config for a DoT probe; a test
// hook swaps in one that skips verification against a self-signed
// fixture.
var newDoTTLSConfig = func(sni string) *tls.Config {
	return &tls.Config{ServerName: sni, MinVersion: tls.VersionTLS12}
}

// ProbeTimeout bounds a single DoT or DoH check on a capable host.
const ProbeTimeout = 3 * time.Second

// probeBudget scales the DNS latency probe to the host CPU. A weak
// MIPS/ARMv7 router does TLS handshakes in software an order of
// magnitude slower than an arm64/amd64 box (no AES/SHA acceleration),
// so 20+ handshakes in flight there just thrash the scheduler and every
// probe overruns its deadline -- the table then reads "timeout" for
// resolvers that are actually reachable. On those arches: only a few in
// flight, a provider's DoT and DoH run one after the other, and a
// longer per-probe budget.
func probeBudget() (concurrency int, timeout time.Duration, sequential bool) {
	switch runtime.GOARCH {
	case "mips", "mipsle", "mips64", "mips64le", "arm", "386":
		return 3, 6 * time.Second, true
	default:
		return 12, ProbeTimeout, false
	}
}

// Budget exposes the per-probe timeout and fan-out chosen for this host,
// so `dns test` can print the number it's actually using.
func Budget() (concurrency int, timeout time.Duration) {
	c, t, _ := probeBudget()
	return c, t
}

// Timing is the outcome of one endpoint probe.
type Timing struct {
	OK      bool
	Latency time.Duration
	Err     string // set when !OK
}

func (t Timing) String() string {
	if t.OK {
		return fmt.Sprintf("%d мс", t.Latency.Milliseconds())
	}
	if t.Err != "" {
		return "— (" + t.Err + ")"
	}
	return "—"
}

// Result is a provider's DoT and DoH timings.
type Result struct {
	Provider Provider
	DoT      Timing
	DoH      Timing
}

// Best is the lower of the two successful latencies, or 0 if neither
// worked -- used to sort.
func (r Result) Best() time.Duration {
	switch {
	case r.DoT.OK && r.DoH.OK:
		if r.DoT.Latency < r.DoH.Latency {
			return r.DoT.Latency
		}
		return r.DoH.Latency
	case r.DoT.OK:
		return r.DoT.Latency
	case r.DoH.OK:
		return r.DoH.Latency
	default:
		return 0
	}
}

// ProbeAll checks every provider's first DoT and first DoH endpoint
// concurrently and returns the results sorted: working ones first by
// best latency, dead ones last in catalogue order.
func ProbeAll(ctx context.Context, ps []Provider) []Result {
	conc, _, _ := probeBudget()
	out := make([]Result, len(ps))
	sem := make(chan struct{}, conc)
	done := make(chan int, len(ps))
	for i, p := range ps {
		go func(i int, p Provider) {
			sem <- struct{}{}
			defer func() { <-sem; done <- i }()
			out[i] = ProbeProvider(ctx, p)
		}(i, p)
	}
	for range ps {
		<-done
	}
	sort.SliceStable(out, func(a, b int) bool {
		ba, bb := out[a].Best(), out[b].Best()
		switch {
		case ba > 0 && bb > 0:
			return ba < bb
		case ba > 0:
			return true
		case bb > 0:
			return false
		default:
			return false
		}
	})
	return out
}

// ProbeProvider probes p's first DoT and first DoH endpoint. On a
// capable host the two run in parallel; on a weak arch (see
// probeBudget) they run one after the other to halve the peak
// handshake load.
func ProbeProvider(ctx context.Context, p Provider) Result {
	r := Result{Provider: p}
	_, timeout, sequential := probeBudget()

	dot := func() {
		if len(p.DoT) == 0 {
			r.DoT = Timing{Err: "нет DoT"}
			return
		}
		r.DoT = time1(func() error { return probeDoT(ctx, p.DoT[0].IP, p.DoT[0].SNI, timeout) })
	}
	doh := func() {
		if len(p.DoH) == 0 {
			r.DoH = Timing{Err: "нет DoH"}
			return
		}
		r.DoH = time1(func() error { return probeDoH(ctx, p.DoH[0].URL, timeout) })
	}

	if sequential {
		dot()
		doh()
		return r
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); dot() }()
	go func() { defer wg.Done(); doh() }()
	wg.Wait()
	return r
}

func time1(fn func() error) Timing {
	start := time.Now()
	if err := fn(); err != nil {
		return Timing{Err: shortErr(err)}
	}
	return Timing{OK: true, Latency: time.Since(start)}
}

// probeDoT dials <ip>:853, does a TLS handshake with the given SNI, sends
// one A query for probeName over DNS-over-TCP framing and checks the
// reply header.
func probeDoT(ctx context.Context, ip, sni string, timeout time.Duration) error {
	return probeDoTAddr(ctx, net.JoinHostPort(ip, "853"), sni, timeout)
}

func probeDoTAddr(ctx context.Context, addr, sni string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}

	conn := tls.Client(raw, newDoTTLSConfig(sni))
	if err := conn.HandshakeContext(ctx); err != nil {
		return err
	}

	q, id := dnsQuery(probeName)
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		return err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n < 12 || n > 4096 {
		return fmt.Errorf("bad reply length %d", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	return checkDNSReply(resp, id)
}

// probeDoH POSTs one A query for probeName as application/dns-message and
// checks the reply header. The DoH host is resolved via the system
// resolver (the current one -- this is just a reachability check).
func probeDoH(ctx context.Context, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	q, id := dnsQuery(probeName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(q))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "keenetic-xray dns-probe")

	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	return checkDNSReply(body, id)
}

// ProbePlain sends one A query for probeName over plain DNS-over-UDP to
// hostport (e.g. "127.0.0.1:5335") and checks the reply header. Used to
// verify a locally-installed resolver (unbound / dnscrypt-proxy) is
// actually answering, not just listening.
func ProbePlain(ctx context.Context, hostport string) error {
	_, timeout, _ := probeBudget()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", hostport)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	q, id := dnsQuery(probeName)
	if _, err := conn.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	return checkDNSReply(buf[:n], id)
}

// dnsQuery builds a minimal A/IN query with RD=1 and returns it with its
// transaction ID.
func dnsQuery(name string) ([]byte, uint16) {
	id := uint16(rand.Intn(0xffff)) //nolint:gosec // not security-sensitive
	var b bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(hdr[4:], 1)      // QDCOUNT
	b.Write(hdr)
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:], 1) // QTYPE A
	binary.BigEndian.PutUint16(qtail[2:], 1) // QCLASS IN
	b.Write(qtail)
	return b.Bytes(), id
}

// checkDNSReply accepts a message that is a response (QR=1) to our query
// id with a non-error RCODE.
func checkDNSReply(msg []byte, wantID uint16) error {
	if len(msg) < 12 {
		return fmt.Errorf("short reply")
	}
	if binary.BigEndian.Uint16(msg[0:]) != wantID {
		return fmt.Errorf("wrong id")
	}
	if msg[2]&0x80 == 0 {
		return fmt.Errorf("not a response")
	}
	if rcode := msg[3] & 0x0f; rcode != 0 {
		return fmt.Errorf("RCODE %d", rcode)
	}
	return nil
}

func shortErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "context deadline exceeded"), strings.Contains(s, "i/o timeout"), strings.Contains(s, "Client.Timeout"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "refused"
	case strings.Contains(s, "no such host"):
		return "DNS хоста не резолвится"
	case strings.Contains(s, "certificate"):
		return "TLS-сертификат"
	case strings.Contains(s, "network is unreachable"), strings.Contains(s, "no route to host"):
		return "нет маршрута"
	}
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	return s
}
