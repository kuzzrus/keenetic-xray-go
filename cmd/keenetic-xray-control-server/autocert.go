package main

// This file, not internal/botcontrol, is deliberately where the ACME
// dependency lives: golang.org/x/crypto/acme/autocert carries package
// init() functions, which the Go linker can never dead-code-eliminate --
// merely importing it anywhere in a package pulls that init cost into
// every binary that imports the package, whether or not anything in it
// actually calls into autocert. internal/botcontrol is imported by
// cmd/keenetic-xray too (the router binary), so an import there would
// have silently grown the router binary for a feature it never uses
// (confirmed while building this: ~300-400KB on the arm64/mipsel
// builds, entirely from unreachable autocert/acme init code). A `main`
// package is never imported by anything else, so keeping this here is a
// hard guarantee, not something that depends on linker DCE behaving a
// particular way.

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// newAutocertManager returns an ACME (Let's Encrypt) certificate manager
// scoped to exactly one domain -- HostWhitelist refuses to issue for
// anything else even if a client's SNI claims otherwise, so a stray
// ClientHello can't trick the manager into issuing for a domain the
// operator never configured. cacheDir persists the issued certificate,
// private key, and ACME account state across restarts, since Let's
// Encrypt rate-limits how often the same domain may be (re-)issued.
func newAutocertManager(domain, cacheDir string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}
}

// acmeCertProvider is satisfied by *autocert.Manager (GetCertificate has
// exactly this signature) -- the seam exists so dualCertGetter's
// dispatch logic is unit-testable without a real ACME round-trip.
type acmeCertProvider interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// dualCertGetter returns a tls.Config.GetCertificate function that keeps
// both trust schemes serving at once on the same listener: a client
// whose SNI matches domain (a router configured with `agent configure`
// in CA-trust mode) gets the ACME-issued certificate from mgr; anything
// else -- no SNI, an IP address, a stale domain -- gets selfSigned, the
// exact certificate every already-pinned agent (configured before the
// domain existed) already trusts by fingerprint. This is what lets
// adding a domain never require reconfiguring existing routers.
//
// The match ignores case and a trailing dot (2026-09-27 external review,
// R-2): DNS names are case-insensitive, and "VPS.example.com" or
// "vps.example.com." used to get the self-signed certificate -- which a
// CA-trusting agent rejects. autocert normalizes the name the same way
// on its side.
func dualCertGetter(selfSigned tls.Certificate, domain string, mgr acmeCertProvider) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain = normalizeDomain(domain)
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if domain != "" && strings.EqualFold(strings.TrimSuffix(hello.ServerName, "."), domain) {
			return mgr.GetCertificate(hello)
		}
		return &selfSigned, nil
	}
}

// normalizeDomain is how the configured domain is stored and compared:
// lower case, no surrounding space, no trailing dot.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// acmeChallengeServer is the plain-HTTP :80 server Let's Encrypt's HTTP-01
// challenge dials (opened on demand, see acmeGate). It faces the internet
// just like the TLS listener, so it gets the same bounded timeouts
// (botcontrol.ListenAndServeTLSDynamic). The bare http.ListenAndServe it
// replaces had none, so any client could hold a connection open for as
// long as it liked (2026-09-27 external review, R-1).
func acmeChallengeServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
