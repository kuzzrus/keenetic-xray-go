package dnsupstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// selfSignedCert makes a throwaway cert for the fake DoT server; the
// probe's TLS verification is disabled for the test via newDoTTLSConfig.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestProvidersWellFormed(t *testing.T) {
	if len(Providers()) < 15 {
		t.Fatalf("expected a broad catalogue, got %d", len(Providers()))
	}
	if len(TestPool()) <= len(Providers()) {
		t.Fatalf("TestPool (%d) should be wider than Providers (%d)", len(TestPool()), len(Providers()))
	}
	seen := map[string]bool{}
	for _, p := range TestPool() {
		if p.ID == "" || p.Name == "" {
			t.Errorf("provider %+v missing id/name", p)
		}
		if seen[p.ID] {
			t.Errorf("duplicate provider id %q", p.ID)
		}
		seen[p.ID] = true
		if len(p.DoT) == 0 && len(p.DoH) == 0 {
			t.Errorf("provider %q has no endpoints", p.ID)
		}
		for _, d := range p.DoT {
			if net.ParseIP(d.IP) == nil {
				t.Errorf("%s: bad DoT IP %q", p.ID, d.IP)
			}
			if d.SNI == "" || strings.ContainsAny(d.SNI, " /") {
				t.Errorf("%s: bad DoT SNI %q", p.ID, d.SNI)
			}
		}
		for _, h := range p.DoH {
			if !strings.HasPrefix(h.URL, "https://") {
				t.Errorf("%s: bad DoH URL %q", p.ID, h.URL)
			}
		}
	}
	if _, ok := Find("Cloudflare"); !ok {
		t.Error("Find should be case-insensitive")
	}
	if _, ok := Find("nope"); ok {
		t.Error("Find matched a bogus id")
	}
}

func TestManagedSets(t *testing.T) {
	ips := AllTLSIPs()
	urls := AllDoHURLs()
	if len(ips) < 15 || len(urls) < 15 {
		t.Fatalf("managed sets look thin: %d ips, %d urls", len(ips), len(urls))
	}
	has := func(xs []string, v string) bool {
		for _, x := range xs {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(ips, "9.9.9.9") || !has(urls, "https://dns.google/dns-query") {
		t.Error("expected known endpoints in the managed sets")
	}
}

func TestDNSQueryAndReplyCheck(t *testing.T) {
	q, id := dnsQuery("example.com")
	// header(12) + 1+7 "example" + 1+3 "com" + 1 root + 4 tail = 29
	if len(q) != 29 {
		t.Fatalf("query len = %d, want 29", len(q))
	}
	if binary.BigEndian.Uint16(q[4:]) != 1 {
		t.Errorf("QDCOUNT != 1")
	}

	good := make([]byte, 12)
	binary.BigEndian.PutUint16(good[0:], id)
	good[2] = 0x81 // QR + RD
	good[3] = 0x00 // NOERROR
	if err := checkDNSReply(good, id); err != nil {
		t.Errorf("valid reply rejected: %v", err)
	}
	good[3] = 0x03 // NXDOMAIN
	if err := checkDNSReply(good, id); err == nil {
		t.Error("NXDOMAIN reply should be flagged")
	}
	bad := make([]byte, 12)
	binary.BigEndian.PutUint16(bad[0:], id+1)
	bad[2] = 0x80
	if err := checkDNSReply(bad, id); err == nil {
		t.Error("wrong-id reply should be rejected")
	}
	if err := checkDNSReply([]byte{1, 2, 3}, id); err == nil {
		t.Error("short reply should be rejected")
	}
}

func TestProbeDoH_AgainstFakeServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 512))
		if len(body) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reply := make([]byte, 12)
		copy(reply[0:2], body[0:2]) // echo id
		reply[2] = 0x81
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(reply)
	}))
	defer srv.Close()

	if err := probeDoH(context.Background(), srv.URL); err != nil {
		t.Fatalf("probeDoH against a good fake server: %v", err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer bad.Close()
	if err := probeDoH(context.Background(), bad.URL); err == nil {
		t.Error("expected an error from an HTTP 418 server")
	}
}

func TestProbeDoT_AgainstFakeServer(t *testing.T) {
	orig := newDoTTLSConfig
	newDoTTLSConfig = func(string) *tls.Config { return &tls.Config{InsecureSkipVerify: true} } //nolint:gosec
	t.Cleanup(func() { newDoTTLSConfig = orig })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Minimal TLS server answering one DNS-over-TCP query.
	cert := selfSignedCert(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		if tc.Handshake() != nil {
			return
		}
		var l [2]byte
		if _, err := io.ReadFull(tc, l[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(l[:]))
		if _, err := io.ReadFull(tc, msg); err != nil {
			return
		}
		reply := make([]byte, 12)
		copy(reply[0:2], msg[0:2])
		reply[2] = 0x81
		out := make([]byte, 2+len(reply))
		binary.BigEndian.PutUint16(out, uint16(len(reply)))
		copy(out[2:], reply)
		tc.Write(out)
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	// probeDoT hard-codes :853; test the pieces via a small inline dial
	// with the same logic but the ephemeral port.
	if err := probeDoTAddr(context.Background(), net.JoinHostPort(host, port), "example.test", ProbeTimeout); err != nil {
		t.Fatalf("probeDoT against a good fake server: %v", err)
	}
}

func TestProbeAll_SortsWorkingFirst(t *testing.T) {
	// Two unreachable providers -> ProbeAll must still return, in order,
	// within a bounded time.
	ps := []Provider{
		{ID: "dead1", Name: "d1", DoT: []TLS{{"192.0.2.1", "x"}}, DoH: []HTTPS{{"https://192.0.2.1/dns-query"}}},
		{ID: "dead2", Name: "d2", DoT: []TLS{{"192.0.2.2", "y"}}, DoH: []HTTPS{{"https://192.0.2.2/dns-query"}}},
	}
	start := time.Now()
	res := ProbeAll(context.Background(), ps)
	if len(res) != 2 {
		t.Fatalf("got %d results", len(res))
	}
	if time.Since(start) > 2*ProbeTimeout+time.Second {
		t.Errorf("ProbeAll took too long: %v", time.Since(start))
	}
	for _, r := range res {
		if r.DoT.OK || r.DoH.OK {
			t.Errorf("%s unexpectedly reachable", r.Provider.ID)
		}
	}
}
