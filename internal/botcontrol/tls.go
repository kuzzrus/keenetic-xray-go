package botcontrol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// certValidity is deliberately long: this certificate is never validated
// against a CA or checked for expiry by the agent (see newPinnedClient in
// agent.go) -- only its fingerprint is compared, SSH-host-key style -- so
// there's no rotation workflow to build here. A long validity just avoids
// ever needing one.
const certValidity = 10 * 365 * 24 * time.Hour

// GenerateSelfSignedCert creates a new ECDSA P-256 self-signed certificate
// and key. commonName is informational only (typically the VPS's hostname
// or IP) -- SNI/hostname checks are never performed on the client side,
// since the agent pins the fingerprint instead of validating a chain.
func GenerateSelfSignedCert(commonName string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour), // clock skew slack
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling key: %w", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("building tls.Certificate: %w", err)
	}
	return cert, nil
}

// FingerprintSHA256 returns the hex-encoded SHA256 of cert's leaf --
// the same value the agent pins against in newPinnedClient, and what
// /fingerprint serves.
func FingerprintSHA256(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("certificate has no leaf")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}

// LoadOrGenerateCert loads a PEM cert+key pair from certPath/keyPath if
// both exist, or generates a fresh self-signed pair and writes them there
// (key at 0600) if not. Reusing the same key/cert across restarts matters
// because the fingerprint is what every already-configured agent has
// pinned -- regenerating it on every start would lock out every router
// until each one is manually reconfigured with the new fingerprint.
func LoadOrGenerateCert(certPath, keyPath, commonName string) (tls.Certificate, error) {
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	switch {
	case certExists && keyExists:
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("loading existing cert/key: %w", err)
		}
		return cert, nil
	case certExists != keyExists:
		// Exactly one half of the pair is present. Regenerating now would
		// mint a fresh keypair with a new fingerprint and lock out every
		// agent that has pinned the old one -- so refuse and let the
		// operator decide (restore the missing file, or delete both).
		present, missing := certPath, keyPath
		if keyExists {
			present, missing = keyPath, certPath
		}
		return tls.Certificate{}, fmt.Errorf("%s exists but %s does not: refusing to regenerate (it would change the pinned fingerprint); restore the missing file or remove both to start fresh", present, missing)
	}

	cert, err := GenerateSelfSignedCert(commonName)
	if err != nil {
		return tls.Certificate{}, err
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return tls.Certificate{}, fmt.Errorf("creating cert directory: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("writing cert: %w", err)
	}

	ecKey, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("internal error: generated key is %T, not *ecdsa.PrivateKey", cert.PrivateKey)
	}
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshaling key for storage: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return tls.Certificate{}, fmt.Errorf("creating key directory: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("writing key: %w", err)
	}

	return cert, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
