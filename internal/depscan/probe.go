package depscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// Reach is the outcome of opening one host one way.
type Reach struct {
	Tried  bool   // false: this way was not attempted (not needed)
	OK     bool   // an HTTP response came back -- of any status
	Status int    // that response's status code
	Err    string // short Russian reason when !OK ("таймаут", "DNS", ...)
}

// Prober opens a host the two ways the scan compares. An interface so the
// tests can stand in a map of canned answers for the network.
type Prober interface {
	// Direct opens host from the router's own connection -- the path every
	// client's unrouted traffic takes.
	Direct(ctx context.Context, host string) Reach
	// Tunnel opens it through the router's tunnel.
	Tunnel(ctx context.Context, host string) Reach
}

// Per-attempt limits. Short on purpose: a blocked host either answers
// within a second or hangs until the limit, and 30 hosts share one
// budget.
const (
	directProbeTimeout = 4 * time.Second
	tunnelProbeTimeout = 6 * time.Second
)

// userAgent is what the scan presents: a current desktop browser, since a
// site that serves a bot-check page to anything else would hand us no
// markup to read.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

// netProber is Prober over two RoundTrippers.
type netProber struct {
	direct, tunnel http.RoundTripper
}

// NewProber builds the real Prober. direct==nil gets a plain transport
// that ignores proxy environment variables (a probe that quietly went
// through a proxy would call every blocked host reachable).
func NewProber(direct, tunnel http.RoundTripper) Prober {
	if direct == nil {
		direct = newDirectTransport()
	}
	return netProber{direct: direct, tunnel: tunnel}
}

func newDirectTransport() *http.Transport {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   directProbeTimeout,
		ResponseHeaderTimeout: directProbeTimeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
}

func (p netProber) Direct(ctx context.Context, host string) Reach {
	return probeOnce(ctx, p.direct, host, directProbeTimeout)
}

func (p netProber) Tunnel(ctx context.Context, host string) Reach {
	if p.tunnel == nil {
		return Reach{Tried: true, Err: "нет туннеля"}
	}
	return probeOnce(ctx, p.tunnel, host, tunnelProbeTimeout)
}

// probeOnce asks https://host/ for its first byte through rt and reports
// whether any HTTP answer came back. rt.RoundTrip is used directly so a
// redirect is not followed: the 3xx itself proves the host answers.
func probeOnce(ctx context.Context, rt http.RoundTripper, host string, limit time.Duration) Reach {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return Reach{Tried: true, Err: "ошибка"}
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", "bytes=0-0")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return Reach{Tried: true, Err: reason(err)}
	}
	// The status line is all we came for.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1))
	_ = resp.Body.Close()
	return Reach{Tried: true, OK: true, Status: resp.StatusCode}
}

// reason names a failed attempt in a word or two for the screen.
func reason(err error) string {
	var dns *net.DNSError
	var hostErr x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var rec tls.RecordHeaderError
	var redir *redirectError
	switch {
	case errors.As(err, &redir):
		return redir.msg
	case errors.Is(err, context.DeadlineExceeded):
		return "таймаут"
	case errors.As(err, &dns):
		if dns.IsTimeout {
			return "таймаут DNS"
		}
		return "DNS"
	case errors.As(err, &hostErr), errors.As(err, &unknown), errors.As(err, &invalid):
		return "сертификат"
	case errors.As(err, &rec):
		return "не TLS"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "отказ"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "сброс"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "нет маршрута"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "таймаут"
	}
	if strings.Contains(err.Error(), "tls:") {
		return "TLS"
	}
	return "ошибка"
}
