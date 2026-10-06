package main

import (
	"crypto/tls"
	"net/http"
	"reflect"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
)

// fakeCertProvider stands in for *autocert.Manager without a real ACME
// round-trip: GetCertificate just records that it was called and hands
// back a marker certificate distinct from any self-signed one, so a test
// can tell whether dualCertGetter actually delegated to it.
type fakeCertProvider struct {
	called bool
	cert   *tls.Certificate
	err    error
}

func (f *fakeCertProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	f.called = true
	return f.cert, f.err
}

func TestDualCertGetter_MatchingSNIDelegatesToACME(t *testing.T) {
	selfSigned, err := botcontrol.GenerateSelfSignedCert("self-signed")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	acmeCert := &tls.Certificate{Certificate: [][]byte{[]byte("acme-marker")}}
	fake := &fakeCertProvider{cert: acmeCert}

	getter := dualCertGetter(selfSigned, "vps.example.com", fake)
	got, err := getter(&tls.ClientHelloInfo{ServerName: "vps.example.com"})
	if err != nil {
		t.Fatalf("getter: %v", err)
	}
	if !fake.called {
		t.Error("expected dualCertGetter to delegate to the ACME provider on a matching SNI")
	}
	if got != acmeCert {
		t.Error("expected the ACME-provided certificate back, not the self-signed one")
	}
}

func TestDualCertGetter_NonMatchingSNIFallsBackToSelfSigned(t *testing.T) {
	selfSigned, err := botcontrol.GenerateSelfSignedCert("self-signed")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	fake := &fakeCertProvider{cert: &tls.Certificate{Certificate: [][]byte{[]byte("should never be returned")}}}

	getter := dualCertGetter(selfSigned, "vps.example.com", fake)
	for _, sni := range []string{"", "not-the-domain.example.com", "203.0.113.1"} {
		t.Run(sni, func(t *testing.T) {
			fake.called = false
			got, err := getter(&tls.ClientHelloInfo{ServerName: sni})
			if err != nil {
				t.Fatalf("getter: %v", err)
			}
			if fake.called {
				t.Error("must not delegate to the ACME provider for a non-matching SNI -- already-pinned agents dial with no matching SNI at all")
			}
			// dualCertGetter closes over its own copy of selfSigned, so
			// this must compare by value, not by address.
			if !reflect.DeepEqual(*got, selfSigned) {
				t.Error("expected the self-signed certificate back")
			}
		})
	}
}

// TestDualCertGetter_SNIIgnoresCaseAndTrailingDot is R-2: DNS names are
// case-insensitive and may carry the root's trailing dot. Either used to
// get the self-signed certificate, which a CA-trusting agent rejects.
func TestDualCertGetter_SNIIgnoresCaseAndTrailingDot(t *testing.T) {
	selfSigned, err := botcontrol.GenerateSelfSignedCert("self-signed")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}
	acmeCert := &tls.Certificate{Certificate: [][]byte{[]byte("acme-marker")}}
	for _, configured := range []string{"vps.example.com", "VPS.Example.com."} {
		getter := dualCertGetter(selfSigned, configured, &fakeCertProvider{cert: acmeCert})
		for _, sni := range []string{"vps.example.com", "VPS.EXAMPLE.COM", "vps.example.com."} {
			got, err := getter(&tls.ClientHelloInfo{ServerName: sni})
			if err != nil {
				t.Fatalf("getter(%q): %v", sni, err)
			}
			if got != acmeCert {
				t.Errorf("domain %q, SNI %q: got the self-signed certificate, want the ACME one", configured, sni)
			}
		}
	}
}

// TestACMEChallengeServer_Bounded is R-1: the internet-facing :80 server
// has timeouts.
func TestACMEChallengeServer_Bounded(t *testing.T) {
	srv := acmeChallengeServer("127.0.0.1:0", http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("timeouts header=%v read=%v write=%v idle=%v, want all set", srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
