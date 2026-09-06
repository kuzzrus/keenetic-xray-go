package config

import (
	"crypto/ecdh"
	"encoding/base64"
	"testing"
)

func TestGenerateWGKeypair(t *testing.T) {
	priv, pub, err := GenerateWGKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWGKey(priv) || !ValidWGKey(pub) {
		t.Fatalf("keys not valid 32-byte base64: priv=%q pub=%q", priv, pub)
	}
	if priv == pub {
		t.Error("private and public key are identical")
	}

	// pub must be the X25519 public key derived from priv.
	raw, _ := base64.StdEncoding.DecodeString(priv)
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("priv not a usable X25519 scalar: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()); got != pub {
		t.Errorf("derived public key %q != returned %q", got, pub)
	}

	priv2, _, _ := GenerateWGKeypair()
	if priv2 == priv {
		t.Error("two calls produced the same private key")
	}
}

func TestGenerateWGPSK(t *testing.T) {
	a, err := GenerateWGPSK()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidWGKey(a) {
		t.Errorf("PSK %q is not 32-byte base64", a)
	}
	if b, _ := GenerateWGPSK(); b == a {
		t.Error("two PSKs are identical")
	}
}

func TestValidWGKey(t *testing.T) {
	good, _, _ := GenerateWGKeypair()
	for _, s := range []string{good, base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		if !ValidWGKey(s) {
			t.Errorf("ValidWGKey(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "not base64!!", base64.StdEncoding.EncodeToString(make([]byte, 16)), "abc"} {
		if ValidWGKey(s) {
			t.Errorf("ValidWGKey(%q) = true, want false", s)
		}
	}
}
