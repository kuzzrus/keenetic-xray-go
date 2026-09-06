package config

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// WireGuard keys are Curve25519. crypto/ecdh's X25519 GenerateKey draws
// 32 random bytes for the scalar (unclamped, exactly like `wg genkey`)
// and PublicKey() applies the standard clamp+basepoint multiply, so the
// public key here is byte-identical to what `wg pubkey` would derive.

// GenerateWGKeypair returns a fresh WireGuard private/public keypair,
// both standard base64. Used for the xray side of the in-router WG
// transport -- the Keenetic side generates its own and we read the
// public key back off the interface.
func GenerateWGKeypair() (privB64, pubB64 string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating X25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// GenerateWGPSK returns a fresh 32-byte WireGuard pre-shared key, base64.
func GenerateWGPSK() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating pre-shared key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ValidWGKey reports whether s is a syntactically valid WireGuard key: 32
// bytes, standard base64 (44 chars ending "="). Not a cryptographic
// check -- just enough to reject a truncated paste before it reaches
// ndmc or the xray config.
func ValidWGKey(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
}
