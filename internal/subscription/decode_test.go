package subscription

import (
	"encoding/base64"
	"testing"
)

const samplePlaintext = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#a\n" +
	"vless://22222222-3333-4444-5555-666666666666@example.org:443?type=tcp&security=none#b"

func TestDecode_Base64Standard(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(samplePlaintext))
	got := Decode([]byte(encoded))
	if string(got) != samplePlaintext {
		t.Errorf("Decode(std-base64) = %q, want %q", got, samplePlaintext)
	}
}

func TestDecode_Base64RawStd(t *testing.T) {
	encoded := base64.RawStdEncoding.EncodeToString([]byte(samplePlaintext))
	got := Decode([]byte(encoded))
	if string(got) != samplePlaintext {
		t.Errorf("Decode(raw-std-base64) = %q, want %q", got, samplePlaintext)
	}
}

func TestDecode_Base64URL(t *testing.T) {
	encoded := base64.URLEncoding.EncodeToString([]byte(samplePlaintext))
	got := Decode([]byte(encoded))
	if string(got) != samplePlaintext {
		t.Errorf("Decode(url-base64) = %q, want %q", got, samplePlaintext)
	}
}

func TestDecode_Base64RawURL(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(samplePlaintext))
	got := Decode([]byte(encoded))
	if string(got) != samplePlaintext {
		t.Errorf("Decode(raw-url-base64) = %q, want %q", got, samplePlaintext)
	}
}

func TestDecode_PlaintextFallback(t *testing.T) {
	got := Decode([]byte(samplePlaintext))
	if string(got) != samplePlaintext {
		t.Errorf("Decode(plaintext) = %q, want unchanged passthrough %q", got, samplePlaintext)
	}
}

func TestDecode_TrimsWhitespaceBeforeDecoding(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte(samplePlaintext)) + "\n  "
	got := Decode([]byte(encoded))
	if string(got) != samplePlaintext {
		t.Errorf("Decode with trailing whitespace = %q, want %q", got, samplePlaintext)
	}
}
