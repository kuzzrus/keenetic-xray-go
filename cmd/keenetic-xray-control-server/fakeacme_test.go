package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// fakeACME is just enough of an RFC 8555 CA for golang.org/x/crypto/acme's
// client to get a certificate from it. Where it matters for the on-demand
// port 80 it behaves like Let's Encrypt:
//
//   - every authorization offers tls-alpn-01 and http-01, and tls-alpn-01
//     fails (nobody answers on :443), so autocert opens a second order for
//     http-01 -- the sequence of every real issuance on this server;
//   - an HTTP-01 check does not happen while the client's request is being
//     answered: the CA fetches the key authorization over plain HTTP a
//     moment *after* the accept returned, while the client is only polling.
//     A port that closed with the request would fail it.
//
// It checks neither signatures nor nonces.
type fakeACME struct {
	srv      *httptest.Server
	domain   string
	validity time.Duration // how long the certificates it issues last
	httpAddr func() string // where the HTTP-01 check connects; stands in for <domain>:80

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	mu     sync.Mutex
	seq    int
	hits   int    // requests received
	thumb  string // thumbprint of the account key, from the registration
	orders map[string]*fakeOrder
	authzs map[string]*fakeAuthz
	checks []string // outcome of each HTTP-01 check
	issued int
}

type fakeOrder struct {
	id, status string
	authz      *fakeAuthz
	certPEM    []byte
}

type fakeAuthz struct {
	id, status string
	order      *fakeOrder
	tokens     map[string]string // challenge type -> token
	chosen     string            // the challenge the client accepted
}

func newFakeACME(t *testing.T, domain string, validity time.Duration) *fakeACME {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake ACME root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	ca := &fakeACME{
		domain: domain, validity: validity, caKey: key, caCert: root,
		orders: map[string]*fakeOrder{}, authzs: map[string]*fakeAuthz{},
		httpAddr: func() string { return "" },
	}
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeACME) roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.caCert)
	return p
}

func (ca *fakeACME) requests() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.hits
}

func (ca *fakeACME) issuedCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.issued
}

func (ca *fakeACME) httpChecks() []string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return append([]string(nil), ca.checks...)
}

// sign issues a certificate for the domain to pub, valid for validFor from now.
func (ca *fakeACME) sign(pub crypto.PublicKey, validFor time.Duration) []byte {
	ca.mu.Lock()
	ca.seq++
	serial := big.NewInt(time.Now().UnixNano() + int64(ca.seq))
	ca.mu.Unlock()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: ca.domain},
		DNSNames:     []string{ca.domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.caCert, pub, ca.caKey)
	if err != nil {
		panic(err)
	}
	return der
}

// seedCache leaves in cache what an earlier run of the server would have:
// a certificate for the domain from this CA, valid for validFor more.
func (ca *fakeACME) seedCache(t *testing.T, cache autocert.Cache, validFor time.Duration) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.sign(&key.PublicKey, validFor)})
	pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
	if err := cache.Put(context.Background(), ca.domain, buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func (ca *fakeACME) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	ca.hits++
	ca.seq++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", ca.seq))
	ca.mu.Unlock()

	base, path := ca.srv.URL, r.URL.Path
	switch path {
	case "/directory":
		writeJSON(w, http.StatusOK, map[string]any{
			"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/order",
			"revokeCert": base + "/revoke", "keyChange": base + "/key-change",
			"meta": map[string]any{"termsOfService": base + "/terms"},
		})
		return
	case "/nonce":
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	payload, jwk, err := readJWS(r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	switch {
	case path == "/account":
		ca.register(w, jwk)
	case path == "/order":
		ca.newOrder(w, payload)
	case strings.HasPrefix(path, "/order/"):
		ca.orderState(w, strings.TrimPrefix(path, "/order/"))
	case strings.HasPrefix(path, "/authz/"):
		ca.authzState(w, strings.TrimPrefix(path, "/authz/"), payload)
	case strings.HasPrefix(path, "/challenge/"):
		ca.accept(w, strings.TrimPrefix(path, "/challenge/"))
	case strings.HasPrefix(path, "/finalize/"):
		ca.finalize(w, strings.TrimPrefix(path, "/finalize/"), payload)
	case strings.HasPrefix(path, "/cert/"):
		ca.cert(w, strings.TrimPrefix(path, "/cert/"))
	default:
		writeProblem(w, http.StatusNotFound, "malformed", "no such resource: "+path)
	}
}

func (ca *fakeACME) register(w http.ResponseWriter, jwk json.RawMessage) {
	thumb, err := thumbprintOf(jwk)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "malformed", err.Error())
		return
	}
	ca.mu.Lock()
	status := http.StatusOK // an account for this key exists already
	if ca.thumb == "" {
		status = http.StatusCreated
	}
	ca.thumb = thumb
	ca.mu.Unlock()
	w.Header().Set("Location", ca.srv.URL+"/account/1")
	writeJSON(w, status, map[string]any{"status": "valid"})
}

func (ca *fakeACME) newOrder(w http.ResponseWriter, payload []byte) {
	var req struct {
		Identifiers []struct{ Type, Value string }
	}
	if err := json.Unmarshal(payload, &req); err != nil || len(req.Identifiers) != 1 || req.Identifiers[0].Value != ca.domain {
		writeProblem(w, http.StatusBadRequest, "rejectedIdentifier", "this CA only issues for "+ca.domain)
		return
	}
	ca.mu.Lock()
	ca.seq++
	n := ca.seq
	o := &fakeOrder{id: fmt.Sprintf("o%d", n), status: "pending"}
	az := &fakeAuthz{id: fmt.Sprintf("a%d", n), status: "pending", order: o, tokens: map[string]string{
		"tls-alpn-01": randomToken(), "http-01": randomToken(),
	}}
	o.authz = az
	ca.orders[o.id], ca.authzs[az.id] = o, az
	body := ca.orderJSON(o)
	ca.mu.Unlock()
	w.Header().Set("Location", ca.srv.URL+"/order/"+o.id)
	writeJSON(w, http.StatusCreated, body)
}

// orderJSON needs ca.mu.
func (ca *fakeACME) orderJSON(o *fakeOrder) map[string]any {
	v := map[string]any{
		"status":         o.status,
		"identifiers":    []map[string]string{{"type": "dns", "value": ca.domain}},
		"authorizations": []string{ca.srv.URL + "/authz/" + o.authz.id},
		"finalize":       ca.srv.URL + "/finalize/" + o.id,
	}
	if o.status == "valid" {
		v["certificate"] = ca.srv.URL + "/cert/" + o.id
	}
	return v
}

func (ca *fakeACME) orderState(w http.ResponseWriter, id string) {
	ca.mu.Lock()
	o := ca.orders[id]
	var body map[string]any
	if o != nil {
		body = ca.orderJSON(o)
	}
	ca.mu.Unlock()
	if o == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "no such order")
		return
	}
	w.Header().Set("Location", ca.srv.URL+"/order/"+id)
	writeJSON(w, http.StatusOK, body)
}

func (ca *fakeACME) authzState(w http.ResponseWriter, id string, payload []byte) {
	ca.mu.Lock()
	az := ca.authzs[id]
	var body map[string]any
	if az != nil {
		var req struct{ Status string }
		if json.Unmarshal(payload, &req) == nil && req.Status == "deactivated" {
			az.status = "deactivated"
		}
		body = ca.authzJSON(az)
	}
	ca.mu.Unlock()
	if az == nil {
		writeProblem(w, http.StatusNotFound, "malformed", "no such authorization")
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// authzJSON needs ca.mu.
func (ca *fakeACME) authzJSON(az *fakeAuthz) map[string]any {
	return map[string]any{
		"status":     az.status,
		"identifier": map[string]string{"type": "dns", "value": ca.domain},
		"challenges": []map[string]any{ca.challengeJSON(az, "tls-alpn-01"), ca.challengeJSON(az, "http-01")},
	}
}

// challengeJSON needs ca.mu.
func (ca *fakeACME) challengeJSON(az *fakeAuthz, typ string) map[string]any {
	status := "pending"
	if az.chosen == typ {
		status = az.status
	}
	return map[string]any{"type": typ, "url": ca.srv.URL + "/challenge/" + az.id + "/" + typ, "token": az.tokens[typ], "status": status}
}

// accept is the client saying "I am ready for this challenge".
func (ca *fakeACME) accept(w http.ResponseWriter, rest string) {
	id, typ, _ := strings.Cut(rest, "/")
	ca.mu.Lock()
	az := ca.authzs[id]
	if az == nil || az.tokens[typ] == "" {
		ca.mu.Unlock()
		writeProblem(w, http.StatusNotFound, "malformed", "no such challenge")
		return
	}
	az.chosen = typ
	switch typ {
	case "tls-alpn-01":
		az.status, az.order.status = "invalid", "invalid" // nothing answers on :443
	case "http-01":
		go ca.checkHTTP01(az)
	}
	body := ca.challengeJSON(az, typ)
	ca.mu.Unlock()
	writeJSON(w, http.StatusOK, body)
}

// checkHTTP01 is the CA's validation: fetch the key authorization from the
// domain over plain HTTP, a moment after the accept was answered.
func (ca *fakeACME) checkHTTP01(az *fakeAuthz) {
	time.Sleep(40 * time.Millisecond)
	err := ca.fetchKeyAuthorization(az.tokens["http-01"])
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if err != nil {
		az.status, az.order.status = "invalid", "invalid"
		ca.checks = append(ca.checks, "failed: "+err.Error())
		return
	}
	az.status, az.order.status = "valid", "ready"
	ca.checks = append(ca.checks, "ok")
}

func (ca *fakeACME) fetchKeyAuthorization(token string) error {
	addr := ca.httpAddr()
	if addr == "" {
		return errors.New("nothing is listening on port 80")
	}
	req, err := http.NewRequest("GET", "http://"+addr+"/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return err
	}
	req.Host = ca.domain // what the CA dials is <domain>:80
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	ca.mu.Lock()
	want := token + "." + ca.thumb
	ca.mu.Unlock()
	if res.StatusCode != http.StatusOK || string(body) != want {
		return fmt.Errorf("answered %d %q, want the key authorization %q", res.StatusCode, body, want)
	}
	return nil
}

func (ca *fakeACME) finalize(w http.ResponseWriter, id string, payload []byte) {
	ca.mu.Lock()
	o := ca.orders[id]
	ready := o != nil && o.status == "ready"
	ca.mu.Unlock()
	if !ready {
		writeProblem(w, http.StatusForbidden, "orderNotReady", "the order is not ready")
		return
	}
	csr, err := parseCSR(payload)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "badCSR", err.Error())
		return
	}
	leaf := ca.sign(csr.PublicKey, ca.validity)
	var chain bytes.Buffer
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})
	ca.mu.Lock()
	o.certPEM, o.status = chain.Bytes(), "valid"
	ca.issued++
	body := ca.orderJSON(o)
	ca.mu.Unlock()
	w.Header().Set("Location", ca.srv.URL+"/order/"+id)
	writeJSON(w, http.StatusOK, body)
}

func (ca *fakeACME) cert(w http.ResponseWriter, id string) {
	ca.mu.Lock()
	o := ca.orders[id]
	var chain []byte
	if o != nil {
		chain = o.certPEM
	}
	ca.mu.Unlock()
	if len(chain) == 0 {
		writeProblem(w, http.StatusNotFound, "malformed", "no certificate for this order")
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(chain)
}

func parseCSR(payload []byte) (*x509.CertificateRequest, error) {
	var req struct{ CSR string }
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, err
	}
	der, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	return csr, csr.CheckSignature()
}

// readJWS opens a flattened JWS request body. The signature is not checked.
func readJWS(r *http.Request) (payload []byte, jwk json.RawMessage, err error) {
	var env struct{ Protected, Payload, Signature string }
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		return nil, nil, err
	}
	if payload, err = base64.RawURLEncoding.DecodeString(env.Payload); err != nil {
		return nil, nil, err
	}
	prot, err := base64.RawURLEncoding.DecodeString(env.Protected)
	if err != nil {
		return nil, nil, err
	}
	var h struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(prot, &h); err != nil {
		return nil, nil, err
	}
	return payload, h.JWK, nil
}

// thumbprintOf is the RFC 7638 thumbprint of an EC P-256 JWK, which is what
// a key authorization is built from.
func thumbprintOf(jwk json.RawMessage) (string, error) {
	var k struct{ Crv, X, Y string }
	if err := json.Unmarshal(jwk, &k); err != nil || k.Crv != "P-256" {
		return "", fmt.Errorf("unsupported account key %s", jwk)
	}
	x, errX := base64.RawURLEncoding.DecodeString(k.X)
	y, errY := base64.RawURLEncoding.DecodeString(k.Y)
	if errX != nil || errY != nil {
		return "", errors.New("malformed account key")
	}
	return acme.JWKThumbprint(&ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)})
}

func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, status int, kind, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"type": "urn:ietf:params:acme:error:" + kind, "detail": detail})
}
