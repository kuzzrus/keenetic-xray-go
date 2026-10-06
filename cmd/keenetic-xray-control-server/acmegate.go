package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// acmeIdle is how long :80 stays open after the last request to the ACME
// CA. It has to outlast the quiet stretches inside one issuance -- the
// client polls for the validation result every second or so (a CA may ask
// for longer with Retry-After, in seconds), and the authorization clean-up
// autocert runs afterwards -- and nothing else; against a renewal cycle of
// about 60 days it is noise.
const acmeIdle = 3 * time.Minute

var errACMEGateClosed = errors.New("acme: the control server is shutting down")

// acmeGate keeps the plain-HTTP :80 listener -- the one Let's Encrypt's
// HTTP-01 challenge dials -- closed except while this process is itself
// talking to the ACME CA.
//
// It is built around the connection to the CA rather than around a
// schedule because a challenge only ever happens when we asked for one,
// and autocert decides when to ask: the first TLS handshake for the
// domain, then an internal renewal timer, then retries every half hour or
// so after a failure. It offers no hook for "I am about to need the port",
// but every one of those conversations is a series of HTTP requests from a
// single *acme.Client, so the client's transport -- this gate, see
// acmeClient -- sees all of them. The first request opens :80; it closes
// after acmeIdle without a further request. The CA validates in between
// (after the client accepted the challenge, while it merely polls), which
// is why the window outlives the requests and not just the request that
// carries the accept.
//
// With a valid certificate in the cache the CA is not contacted until a
// renewal is due, so the port is shut for all but a few minutes per
// renewal.
type acmeGate struct {
	addr    string
	handler http.Handler
	idle    time.Duration
	base    http.RoundTripper
	logf    func(format string, args ...any)

	// Seams for tests: how the port is bound, and the idle timer (stop
	// reports whether it stopped the callback before it started).
	listen    func(network, addr string) (net.Listener, error)
	afterFunc func(d time.Duration, f func()) (stop func() bool)

	mu       sync.Mutex
	srv      *http.Server // non-nil exactly while the port is open
	ln       net.Listener
	inflight int         // requests to the CA being made right now
	idleStop func() bool // the pending idle timer, if any
	gen      uint64      // bumped whenever the pending idle timer is replaced or cancelled
	closed   bool
}

func newACMEGate(addr string, handler http.Handler, logf func(string, ...any)) *acmeGate {
	return &acmeGate{
		addr:      addr,
		handler:   handler,
		idle:      acmeIdle,
		base:      http.DefaultTransport,
		logf:      logf,
		listen:    net.Listen,
		afterFunc: func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop },
	}
}

// attachACMEGate makes mgr's every request to the CA open addr, and serves
// mgr's HTTP-01 answers there. Anything on the port that is not a
// challenge gets a plain 404: the library's default is a redirect to the
// https:// URL on port 443, where this server does not listen. It has to
// run before mgr is first used -- autocert ignores a Client set later.
func attachACMEGate(mgr *autocert.Manager, addr string, logf func(string, ...any)) *acmeGate {
	g := newACMEGate(addr, mgr.HTTPHandler(http.NotFoundHandler()), logf)
	mgr.Client = g.acmeClient()
	return g
}

// acmeClient is the ACME client for autocert.Manager.Client: Let's
// Encrypt's production directory (what autocert uses when the field is
// nil), reached through the gate.
func (g *acmeGate) acmeClient() *acme.Client {
	return &acme.Client{
		DirectoryURL: autocert.DefaultACMEDirectory,
		HTTPClient:   &http.Client{Transport: g},
	}
}

// RoundTrip implements http.RoundTripper: it holds :80 open for as long as
// the request takes and for acmeIdle after it. A port that cannot be bound
// fails the request -- with the reason, which renewals would otherwise
// swallow: autocert does not log them.
func (g *acmeGate) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.acquire(); err != nil {
		if req.Body != nil {
			req.Body.Close() // the contract of RoundTrip, errors included
		}
		return nil, err
	}
	defer g.release()
	return g.base.RoundTrip(req)
}

func (g *acmeGate) acquire() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return errACMEGateClosed
	}
	g.cancelIdleLocked()
	if g.srv == nil {
		ln, err := g.listen("tcp", g.addr)
		if err != nil {
			err = fmt.Errorf("acme: cannot open %s for Let's Encrypt to check the domain (something else may hold the port, or the service lacks CAP_NET_BIND_SERVICE): %w", g.addr, err)
			g.log("%v", err)
			return err
		}
		srv := acmeChallengeServer(g.addr, g.handler)
		g.srv, g.ln = srv, ln
		go func() { _ = srv.Serve(ln) }() // only ever ends by closeLocked
		g.log("acme: %s opened for the Let's Encrypt check; it closes after %s without requests to the CA", g.addr, g.idle)
	}
	g.inflight++
	return nil
}

func (g *acmeGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inflight--
	if g.inflight > 0 || g.srv == nil || g.closed {
		return
	}
	g.gen++
	gen := g.gen
	g.idleStop = g.afterFunc(g.idle, func() { g.closeIdle(gen) })
}

// closeIdle is the idle timer's callback. gen tells it whether it is still
// the timer that counts: one that had already fired when a newer request
// cancelled it still gets here, and must not close the port under the
// conversation that request started.
func (g *acmeGate) closeIdle(gen uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gen != gen || g.inflight > 0 || g.srv == nil {
		return
	}
	g.idleStop = nil
	g.closeLocked()
}

// Close shuts :80 for good: requests already under way finish, new ones
// fail. Safe to call more than once.
func (g *acmeGate) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	g.cancelIdleLocked()
	if g.srv != nil {
		g.closeLocked()
	}
}

func (g *acmeGate) cancelIdleLocked() {
	if g.idleStop != nil {
		g.idleStop()
		g.idleStop = nil
	}
	g.gen++
}

// closeLocked frees the port before it returns -- a request that arrives
// right after must be able to bind it again -- and drops whatever
// connection is still open: none is worth waiting for, as the CA only
// connects while a request of ours is under way or has just finished.
func (g *acmeGate) closeLocked() {
	srv, ln := g.srv, g.ln
	g.srv, g.ln = nil, nil
	_ = ln.Close()
	_ = srv.Close()
	g.log("acme: %s closed", g.addr)
}

func (g *acmeGate) log(format string, args ...any) {
	if g.logf != nil {
		g.logf(format, args...)
	}
}
