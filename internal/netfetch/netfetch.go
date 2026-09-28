// Package netfetch is how this project's own downloads get past a
// network that won't let a plain request through: a DPI box that chokes
// on a large TLS ClientHello, a broken IPv6 route, or a host that is
// simply unreachable from inside Russia (it has happened: see
// cmd/keenetic-xray/georanges.go). A request goes out the ordinary way
// first. Only if that fails at the transport level -- no connection, no
// TLS handshake, no response headers -- is it tried again over IPv4 with
// a small ClientHello (X25519 only), and then through the router's own
// tunnel: the production xray's local SOCKS inbound.
//
// Why a small ClientHello: since Go 1.24, crypto/tls offers the
// X25519MLKEM768 post-quantum key exchange by default, which makes the
// ClientHello about 1.2 KB bigger and splits it over two TCP segments --
// the shape some middleboxes mishandle. curl on a modern OpenSSL does the
// same; install.sh's fetch() has the matching `-4 --curves X25519` step.
//
// Every caller checks what it downloaded (sha256, or parses and validates
// it), so which way a file came doesn't matter.
package netfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// TunnelSOCKS returns host:port of the running production xray's local
// SOCKS inbound, or "" when there is none. Set by cmd/keenetic-xray; nil
// leaves out the tunnel step.
var TunnelSOCKS func() string

// Logf, when set, is told which way a request got through after the
// direct way failed. Only the host is logged: a subscription URL's path
// is often its access token.
var Logf func(format string, args ...any)

// Per-attempt bounds, short enough that a blocked path gives way to the
// next one well inside a caller's overall timeout.
const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
	headerTimeout    = 30 * time.Second
)

// Client is an *http.Client with the fallback chain and an overall
// timeout covering every attempt.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport()}
}

// Transport is the fallback chain as an http.RoundTripper, for a client
// that needs settings of its own.
func Transport() http.RoundTripper { return chain{} }

// The chain's steps. Vars so tests can stand in for them.
var (
	direct     http.RoundTripper = newTransport(false)
	smallHello http.RoundTripper = newTransport(true)
	viaSOCKS                     = socksTransport
)

func newTransport(small bool) *http.Transport {
	d := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	t := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   handshakeTimeout,
		ResponseHeaderTimeout: headerTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          8,
	}
	if small {
		t.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		}
		t.TLSClientConfig = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519}}
	}
	return t
}

var (
	socksMu    sync.Mutex
	socksCache = map[string]*http.Transport{}
)

// socksTransport sends requests through the SOCKS5 proxy at addr, with
// the target's name resolved on the far side -- past a DNS-level block
// too.
func socksTransport(addr string) http.RoundTripper {
	socksMu.Lock()
	defer socksMu.Unlock()
	if t, ok := socksCache[addr]; ok {
		return t
	}
	t := newTransport(false)
	t.Proxy = http.ProxyURL(&url.URL{Scheme: "socks5", Host: addr})
	socksCache[addr] = t
	return t
}

type chain struct{}

func (chain) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := direct.RoundTrip(req)
	if err == nil || req.Context().Err() != nil {
		return resp, err // got through, or the caller gave up: nothing to fall back to
	}
	errs := []error{fmt.Errorf("напрямую: %w", err)}
	type step struct {
		name string
		rt   http.RoundTripper
	}
	steps := []step{{"IPv4 + X25519", smallHello}}
	if TunnelSOCKS != nil {
		if addr := TunnelSOCKS(); addr != "" {
			steps = append(steps, step{"через туннель " + addr, viaSOCKS(addr)})
		}
	}
	for _, s := range steps {
		again, rerr := replay(req)
		if rerr != nil {
			errs = append(errs, rerr)
			break
		}
		resp, err := s.rt.RoundTrip(again)
		if err == nil {
			if Logf != nil {
				Logf("netfetch: %s: напрямую не вышло (%v) — получилось %s", req.URL.Host, errs[0], s.name)
			}
			return resp, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		if req.Context().Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

// replay makes a fresh copy of req for another attempt; a body that
// can't be re-read ends the chain.
func replay(req *http.Request) (*http.Request, error) {
	again := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return again, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("тело запроса не повторить")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	again.Body = body
	return again, nil
}
