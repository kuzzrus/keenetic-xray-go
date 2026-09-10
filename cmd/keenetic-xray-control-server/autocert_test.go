package main

import (
	"crypto/tls"
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
