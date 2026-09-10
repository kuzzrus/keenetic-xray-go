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
func dualCertGetter(selfSigned tls.Certificate, domain string, mgr acmeCertProvider) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == domain {
			return mgr.GetCertificate(hello)
		}
		return &selfSigned, nil
	}
}
