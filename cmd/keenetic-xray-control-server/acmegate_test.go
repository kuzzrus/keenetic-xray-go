package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// gateProbe records what a gate does with its port and its log.
type gateProbe struct {
	mu      sync.Mutex
	addrs   []string // every address a listener was bound on, in order
	bindErr error    // when set, binding fails with it
	logs    []string
}

func (p *gateProbe) listen(network, addr string) (net.Listener, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.bindErr != nil {
		return nil, p.bindErr
	}
	ln, err := net.Listen(network, addr)
	if err == nil {
		p.addrs = append(p.addrs, ln.Addr().String())
	}
	return ln, err
}

func (p *gateProbe) logf(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logs = append(p.logs, fmt.Sprintf(format, args...))
}

func (p *gateProbe) binds() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.addrs)
}

// addr is the address of the most recent listener ("" before the first).
func (p *gateProbe) addr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.addrs) == 0 {
		return ""
	}
	return p.addrs[len(p.addrs)-1]
}

func (p *gateProbe) logged(sub string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, l := range p.logs {
		if strings.Contains(l, sub) {
			n++
		}
	}
	return n
}

// lines is a copy of the log so far.
func (p *gateProbe) lines() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.logs...)
}

// idleTimers stands in for time.AfterFunc: nothing fires until a test says
// so, and a test can fire a timer that was already stopped -- which is what
// a real one that had started running when Stop was called amounts to.
type idleTimers struct {
	mu    sync.Mutex
	timer []*fakeIdleTimer
}

type fakeIdleTimer struct {
	d       time.Duration
	f       func()
	stopped bool
}

func (c *idleTimers) after(d time.Duration, f func()) func() bool {
	t := &fakeIdleTimer{d: d, f: f}
	c.mu.Lock()
	c.timer = append(c.timer, t)
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

func (c *idleTimers) scheduled() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timer)
}

func (c *idleTimers) stopped(i int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timer[i].stopped
}

func (c *idleTimers) fire(i int) {
	c.mu.Lock()
	f := c.timer[i].f
	c.mu.Unlock()
	f()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func okTransport(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// newUnitGate is a gate on an ephemeral loopback port whose timers the test
// drives by hand.
func newUnitGate(t *testing.T, base func(*http.Request) (*http.Response, error)) (*acmeGate, *gateProbe, *idleTimers) {
	t.Helper()
	probe, timers := &gateProbe{}, &idleTimers{}
	g := newACMEGate("127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "challenge answer")
	}), probe.logf)
	g.listen, g.afterFunc, g.base = probe.listen, timers.after, roundTripFunc(base)
	t.Cleanup(g.Close)
	return g, probe, timers
}

func callCA(t *testing.T, g *acmeGate) {
	t.Helper()
	req, err := http.NewRequest("GET", "http://ca.invalid/directory", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := g.RoundTrip(req)
	if err != nil {
		t.Fatalf("request to the CA: %v", err)
	}
	res.Body.Close()
}

// answers asks the port what it serves; "" if it does not answer at all.
func answers(addr string) string {
	c := http.Client{Timeout: 2 * time.Second}
	res, err := c.Get("http://" + addr + "/.well-known/acme-challenge/x")
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b)
}

func isOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func TestACMEGate_ClosedUntilTheCAIsContacted(t *testing.T) {
	g, probe, timers := newUnitGate(t, okTransport)
	if probe.binds() != 0 || timers.scheduled() != 0 {
		t.Fatalf("a fresh gate holds the port: binds=%d timers=%d", probe.binds(), timers.scheduled())
	}
	callCA(t, g)
	if probe.binds() != 1 || !isOpen(probe.addr()) {
		t.Fatalf("the first request did not open the port: binds=%d", probe.binds())
	}
}

func TestACMEGate_AnswersWhileTheRequestIsInFlightAndStaysForTheIdlePeriod(t *testing.T) {
	var during string
	var g *acmeGate
	var probe *gateProbe
	g, probe, timers := newUnitGate(t, func(req *http.Request) (*http.Response, error) {
		during = answers(probe.addr()) // the CA checking while it handles our request
		return okTransport(req)
	})
	callCA(t, g)
	if during != "challenge answer" {
		t.Errorf("the port answered %q while the request was in flight", during)
	}
	// After the request: still open, with exactly one timer for the idle period.
	if timers.scheduled() != 1 || timers.timer[0].d != g.idle {
		t.Fatalf("timers after the request: %d (want one for %v)", timers.scheduled(), g.idle)
	}
	if answers(probe.addr()) != "challenge answer" {
		t.Error("the port closed with the request, before the idle period -- the CA validates after the client accepted, not during the request")
	}
	timers.fire(0)
	if isOpen(probe.addr()) {
		t.Error("the port is still open after the idle timer fired")
	}
	if probe.logged("opened") != 1 || probe.logged("closed") != 1 {
		t.Errorf("log = %q: want one 'opened' and one 'closed'", probe.lines())
	}
}

func TestACMEGate_ARequestInsideTheWindowKeepsItOpen(t *testing.T) {
	g, probe, timers := newUnitGate(t, okTransport)
	callCA(t, g)
	callCA(t, g)
	if probe.binds() != 1 {
		t.Fatalf("binds = %d: the second request must reuse the open port", probe.binds())
	}
	if timers.scheduled() != 2 || !timers.stopped(0) || timers.stopped(1) {
		t.Fatalf("timers: scheduled=%d first stopped=%v: the first countdown must be cancelled by the second request", timers.scheduled(), timers.stopped(0))
	}
	// The first countdown had already fired when it was cancelled: it must
	// not close what the newer request is holding.
	timers.fire(0)
	if !isOpen(probe.addr()) {
		t.Fatal("a stale idle timer closed the port of a newer window")
	}
	timers.fire(1)
	if isOpen(probe.addr()) {
		t.Error("the live idle timer did not close the port")
	}
}

func TestACMEGate_AStaleTimerFiringMidRequestChangesNothing(t *testing.T) {
	enter, leave := make(chan struct{}), make(chan struct{})
	n := 0
	g, probe, timers := newUnitGate(t, func(req *http.Request) (*http.Response, error) {
		n++
		if n == 2 {
			close(enter)
			<-leave
		}
		return okTransport(req)
	})
	callCA(t, g) // arms timer 0
	done := make(chan struct{})
	go func() { defer close(done); callCA(t, g) }() // cancels timer 0, then waits inside the CA call
	<-enter
	timers.fire(0) // it had already started when the request cancelled it
	if !isOpen(probe.addr()) {
		t.Fatal("a stale timer closed the port in the middle of a request")
	}
	close(leave)
	<-done
	if timers.scheduled() != 2 {
		t.Errorf("scheduled = %d, want a fresh countdown after the second request", timers.scheduled())
	}
	timers.fire(1)
	if isOpen(probe.addr()) {
		t.Error("still open after the live idle timer")
	}
}

func TestACMEGate_ConcurrentRequestsHoldItUntilTheLastOneIsDone(t *testing.T) {
	enter, leave := make(chan struct{}), make(chan struct{})
	slow := make(chan struct{}, 1)
	slow <- struct{}{} // the first request to arrive is the slow one
	g, probe, timers := newUnitGate(t, func(req *http.Request) (*http.Response, error) {
		select {
		case <-slow:
			close(enter)
			<-leave
		default:
		}
		return okTransport(req)
	})
	done := make(chan struct{})
	go func() { defer close(done); callCA(t, g) }()
	<-enter
	callCA(t, g) // a quick one finishes while the slow one is still going
	if timers.scheduled() != 0 {
		t.Errorf("a countdown started with a request still in flight (scheduled=%d)", timers.scheduled())
	}
	close(leave)
	<-done
	if timers.scheduled() != 1 || !isOpen(probe.addr()) {
		t.Errorf("after the last request: scheduled=%d open=%v, want one countdown and an open port", timers.scheduled(), isOpen(probe.addr()))
	}
}

func TestACMEGate_ReopensForTheNextConversation(t *testing.T) {
	g, probe, timers := newUnitGate(t, okTransport)
	callCA(t, g)
	first := probe.addr()
	timers.fire(0)
	if isOpen(first) {
		t.Fatal("not closed")
	}
	callCA(t, g)
	if probe.binds() != 2 || answers(probe.addr()) != "challenge answer" {
		t.Errorf("binds=%d: a later request must open the port again", probe.binds())
	}
	if probe.logged("opened") != 2 || probe.logged("closed") != 1 {
		t.Errorf("log = %q", probe.lines())
	}
}

func TestACMEGate_ARequestThatFailsStillStartsTheCountdown(t *testing.T) {
	boom := errors.New("connection reset by peer")
	g, probe, timers := newUnitGate(t, func(*http.Request) (*http.Response, error) { return nil, boom })
	req, _ := http.NewRequest("GET", "http://ca.invalid/directory", nil)
	if _, err := g.RoundTrip(req); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the transport's own", err)
	}
	if timers.scheduled() != 1 {
		t.Fatalf("scheduled = %d: a failed request has to release the port too, or it would stay open for good", timers.scheduled())
	}
	timers.fire(0)
	if isOpen(probe.addr()) {
		t.Error("not closed")
	}
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestACMEGate_CannotBindFailsTheRequestAndSaysWhy(t *testing.T) {
	called := false
	g, probe, timers := newUnitGate(t, func(req *http.Request) (*http.Response, error) {
		called = true
		return okTransport(req)
	})
	probe.bindErr = errors.New("listen tcp :80: bind: address already in use")
	body := &closeRecorder{Reader: strings.NewReader("{}")}
	req, _ := http.NewRequest("POST", "http://ca.invalid/new-order", body)
	_, err := g.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "address already in use") || !strings.Contains(err.Error(), "Let's Encrypt") {
		t.Fatalf("err = %v, want the reason and what it was for", err)
	}
	if called || !body.closed {
		t.Errorf("transport called=%v, body closed=%v: nothing may go to the CA when its check can't be served, and a RoundTripper closes the body", called, body.closed)
	}
	if probe.logged("address already in use") != 1 {
		t.Errorf("log = %q: renewals run in the background and autocert logs nothing, so the gate has to", probe.lines())
	}
	if timers.scheduled() != 0 {
		t.Error("a countdown for a port that was never opened")
	}
	// The failure leaves nothing behind: once the port is free, it works.
	probe.mu.Lock()
	probe.bindErr = nil
	probe.mu.Unlock()
	callCA(t, g)
	if !called || !isOpen(probe.addr()) {
		t.Error("the gate did not recover once the port was free")
	}
}

func TestACMEGate_CloseIsFinal(t *testing.T) {
	enter, leave := make(chan struct{}), make(chan struct{})
	calls := 0
	g, probe, timers := newUnitGate(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			close(enter)
			<-leave
		}
		return okTransport(req)
	})
	done := make(chan struct{})
	go func() { defer close(done); callCA(t, g) }()
	<-enter
	addr := probe.addr()
	g.Close()
	if isOpen(addr) {
		t.Fatal("Close left the port open")
	}
	close(leave)
	<-done // the request that was under way finishes normally
	if timers.scheduled() != 0 {
		t.Error("a countdown after Close")
	}
	req, _ := http.NewRequest("GET", "http://ca.invalid/directory", nil)
	if _, err := g.RoundTrip(req); !errors.Is(err, errACMEGateClosed) {
		t.Errorf("a request after Close: err = %v", err)
	}
	if calls != 1 || probe.binds() != 1 {
		t.Errorf("calls=%d binds=%d: nothing may reach the CA or the port after Close", calls, probe.binds())
	}
	g.Close() // twice is fine
}

func TestACMEGate_RealTimerClosesItAfterTheIdlePeriod(t *testing.T) {
	probe := &gateProbe{}
	g := newACMEGate("127.0.0.1:0", http.NotFoundHandler(), probe.logf)
	g.listen, g.idle, g.base = probe.listen, 100*time.Millisecond, roundTripFunc(okTransport)
	t.Cleanup(g.Close)
	callCA(t, g)
	addr := probe.addr()
	if probe.binds() != 1 {
		t.Fatalf("binds = %d, want the request to have opened the port", probe.binds())
	}
	deadline := time.Now().Add(5 * time.Second)
	for isOpen(addr) {
		if time.Now().After(deadline) {
			t.Fatal("the port was still open long after the idle period")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestACMEClient_RunsThroughTheGate(t *testing.T) {
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "{}") }))
	defer ca.Close()
	probe := &gateProbe{}
	g := newACMEGate("127.0.0.1:0", http.NotFoundHandler(), probe.logf)
	g.listen = probe.listen
	t.Cleanup(g.Close)
	c := g.acmeClient()
	if c.DirectoryURL != autocert.DefaultACMEDirectory {
		t.Errorf("DirectoryURL = %q, want Let's Encrypt's production directory (what autocert uses when no client is set)", c.DirectoryURL)
	}
	res, err := c.HTTPClient.Get(ca.URL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if probe.binds() != 1 {
		t.Errorf("binds = %d: the client's requests must open the port", probe.binds())
	}
}

// What is on the port besides challenges: the library's default would
// answer a redirect to https://<host>/ on 443, where this server does not
// listen.
func TestAttachACMEGate_EverythingButAChallengeIs404(t *testing.T) {
	mgr := newAutocertManager("vps.example.test", t.TempDir())
	probe := &gateProbe{}
	g := attachACMEGate(mgr, "127.0.0.1:0", probe.logf)
	g.listen = probe.listen
	g.base = roundTripFunc(okTransport)
	t.Cleanup(g.Close)
	if mgr.Client == nil || mgr.Client.HTTPClient == nil || mgr.Client.HTTPClient.Transport != g {
		t.Fatal("attachACMEGate did not route the manager's CA traffic through the gate")
	}
	callCA(t, g)

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 2 * time.Second}
	for _, tc := range []struct {
		path, host string
		want       int
	}{
		{"/", "vps.example.test", 404},
		{"/some/page", "vps.example.test", 404},
		{"/", "203.0.113.7", 404},
		{"/.well-known/acme-challenge/unknown-token", "vps.example.test", 404},   // no such token pending
		{"/.well-known/acme-challenge/unknown-token", "other.example.test", 403}, // not our domain
	} {
		req, _ := http.NewRequest("GET", "http://"+probe.addr()+tc.path, nil)
		req.Host = tc.host
		res, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("GET %s (Host %s): %v", tc.path, tc.host, err)
		}
		res.Body.Close()
		if res.StatusCode != tc.want {
			t.Errorf("GET %s (Host %s) = %d, want %d", tc.path, tc.host, res.StatusCode, tc.want)
		}
	}
}
