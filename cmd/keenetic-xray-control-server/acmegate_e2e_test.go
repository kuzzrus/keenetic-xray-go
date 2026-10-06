package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"golang.org/x/crypto/acme/autocert"
)

// These tests run the real autocert.Manager and acme client against a fake
// CA (fakeacme_test.go), wired together the way main.go does: they check
// that port 80 is bound when -- and only when -- the server is talking to
// the CA, that the CA's HTTP-01 check really reaches the challenge handler
// through it, and that it is shut again afterwards. A renewal that could
// not open the port would let the certificate expire without a sound
// (autocert logs nothing), cutting off every agent that trusts the CA.

const (
	e2eDomain = "vps.example.test"
	// e2eIdle is the gate's idle period here. The acme client polls the
	// authorization once a second, so it must comfortably exceed that.
	e2eIdle = 2500 * time.Millisecond
)

type e2eRig struct {
	ca    *fakeACME
	mgr   *autocert.Manager
	gate  *acmeGate
	probe *gateProbe
	cache autocert.Cache
}

func newE2ERig(t *testing.T) *e2eRig {
	t.Helper()
	dir := t.TempDir()
	probe := &gateProbe{}
	ca := newFakeACME(t, e2eDomain, 90*24*time.Hour)
	ca.httpAddr = probe.addr // the CA's check dials wherever the gate has bound
	mgr := newAutocertManager(e2eDomain, dir)
	gate := attachACMEGate(mgr, "127.0.0.1:0", probe.logf)
	gate.listen, gate.idle = probe.listen, e2eIdle
	mgr.Client.DirectoryURL = ca.srv.URL + "/directory"
	t.Cleanup(gate.Close)
	return &e2eRig{ca: ca, mgr: mgr, gate: gate, probe: probe, cache: autocert.DirCache(dir)}
}

// handshake is what a router's agent does: a TLS connection with the
// domain as SNI to a server set up like main.go's, which trusts the fake
// CA's root. It returns the certificate the server presented.
func (r *e2eRig) handshake(t *testing.T) *x509.Certificate {
	t.Helper()
	selfSigned, err := botcontrol.GenerateSelfSignedCert("self-signed")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: dualCertGetter(selfSigned, e2eDomain, r.mgr)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{ServerName: e2eDomain, RootCAs: r.ca.roots()}}
	conn, err := d.DialContext(ctx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("TLS handshake with the control server: %v (CA saw %d requests, HTTP-01 checks %v, log %q)",
			err, r.ca.requests(), r.ca.httpChecks(), r.probe.lines())
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitClosed(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, "port 80 to close after the idle period", e2eIdle+15*time.Second, func() bool { return !isOpen(addr) })
}

// The very first handshake for the domain issues the certificate: it blocks
// while the server asks Let's Encrypt, which checks port 80 -- bound just
// for that, and shut again afterwards.
func TestACMEGate_FirstIssuance(t *testing.T) {
	t.Parallel()
	rig := newE2ERig(t)
	if rig.probe.binds() != 0 {
		t.Fatal("port 80 bound before the CA was contacted")
	}

	leaf := rig.handshake(t)
	if leaf.Issuer.CommonName != "fake ACME root" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != e2eDomain {
		t.Errorf("served certificate: issuer %q, names %v", leaf.Issuer.CommonName, leaf.DNSNames)
	}
	if rig.ca.issuedCount() != 1 {
		t.Errorf("certificates issued = %d, want 1", rig.ca.issuedCount())
	}
	if c := rig.ca.httpChecks(); len(c) != 1 || c[0] != "ok" {
		t.Errorf("the CA's HTTP-01 checks = %v, want one that succeeded through the gate's port", c)
	}
	if rig.probe.binds() != 1 {
		t.Errorf("port 80 was bound %d times for one issuance, want 1 window", rig.probe.binds())
	}

	addr := rig.probe.addr()
	waitClosed(t, addr)
	if rig.probe.logged("opened") != 1 || rig.probe.logged("closed") != 1 {
		t.Errorf("log = %q: want one 'opened' and one 'closed'", rig.probe.lines())
	}

	// With a certificate in hand the CA is not contacted again, and the
	// port stays shut: this is the server's resting state.
	hits := rig.ca.requests()
	rig.handshake(t)
	if rig.ca.requests() != hits || isOpen(addr) || rig.probe.binds() != 1 {
		t.Errorf("a handshake served from the cache touched the CA (%d -> %d requests) or the port", hits, rig.ca.requests())
	}
}

// A certificate close to expiry is renewed in the background by autocert's
// own timer, with no handshake waiting for it: the port has to open for
// that just the same.
func TestACMEGate_Renewal(t *testing.T) {
	t.Parallel()
	rig := newE2ERig(t)
	rig.ca.seedCache(t, rig.cache, 5*24*time.Hour) // autocert renews 30 days before the end

	old := rig.handshake(t) // served from the cache at once
	if time.Until(old.NotAfter) > 6*24*time.Hour {
		t.Fatalf("expected the cached certificate (5 days left), got one valid until %v", old.NotAfter)
	}

	waitFor(t, "the renewal to issue a certificate", 30*time.Second, func() bool { return rig.ca.issuedCount() == 1 })
	if rig.probe.binds() != 1 {
		t.Errorf("port 80 was bound %d times for the renewal, want 1 window", rig.probe.binds())
	}
	if c := rig.ca.httpChecks(); len(c) != 1 || c[0] != "ok" {
		t.Errorf("the CA's HTTP-01 checks = %v, want one that succeeded", c)
	}
	waitClosed(t, rig.probe.addr())

	if fresh := rig.handshake(t); time.Until(fresh.NotAfter) < 80*24*time.Hour {
		t.Errorf("after the renewal the server still presents a certificate valid until %v", fresh.NotAfter)
	}
}

// Most of the time there is nothing to ask the CA for, and then port 80 is
// not touched at all.
func TestACMEGate_NothingDueNothingOpened(t *testing.T) {
	t.Parallel()
	rig := newE2ERig(t)
	rig.ca.seedCache(t, rig.cache, 80*24*time.Hour) // renewal is about 50 days away

	rig.handshake(t)
	time.Sleep(300 * time.Millisecond) // a renewal wrongly due now would have started by then
	if rig.probe.binds() != 0 || rig.ca.requests() != 0 {
		t.Errorf("a valid cached certificate led to %d binds of port 80 and %d requests to the CA", rig.probe.binds(), rig.ca.requests())
	}
}

// The failure the operator will actually meet: port 80 is taken by
// something else. Issuance fails at once with the reason in the log, rather
// than after a CA check that can only fail.
func TestACMEGate_PortTakenFailsTheIssuanceClearly(t *testing.T) {
	t.Parallel()
	rig := newE2ERig(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	rig.gate.addr = busy.Addr().String()
	rig.gate.listen = net.Listen // the real bind, which now collides

	selfSigned, err := botcontrol.GenerateSelfSignedCert("self-signed")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: dualCertGetter(selfSigned, e2eDomain, rig.mgr)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	d := tls.Dialer{Config: &tls.Config{ServerName: e2eDomain, RootCAs: rig.ca.roots()}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if conn, err := d.DialContext(ctx, "tcp", ln.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("a certificate was issued although the check could not be served")
	}
	// The reason is the OS's own words, which differ by platform; what the
	// log must carry is which port, and that it was the bind that failed.
	if rig.probe.logged("cannot open "+busy.Addr().String()) != 1 || rig.probe.logged("bind:") != 1 {
		t.Errorf("log = %q, want one line with the bind failure and its reason", rig.probe.lines())
	}
	if rig.ca.issuedCount() != 0 || len(rig.ca.httpChecks()) != 0 {
		t.Error("the CA was asked to validate a port that could not be opened")
	}
}
