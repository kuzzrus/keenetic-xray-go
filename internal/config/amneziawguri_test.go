package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// testAWGConf is a synthetic (not-a-real-server) AmneziaWG .conf, same
// shape as the real vpn:// links this was built against -- see
// docs/HANDOFF-amneziawg.md's debugging-arc section.
const testAWGConf = `[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Address = 10.8.1.2/32
DNS = 8.8.8.8, 8.8.4.4
Jc = 4
Jmin = 40
Jmax = 70
S1 = 30
S2 = 40
S3 = 15
S4 = 12
H1 = 1000000001-1000000010
H2 = 2000000001
H3 = 3000000001
H4 = 4000000001
I1 = <b 0xdeadbeef><r 16>
HeaderProtectionKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
ContentPaddingAddition = 5-60
RandomTrailers = on
DisableCookies = on

# a comment line, like the real links have before [Peer]
[Peer]
PublicKey = CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
PresharedKey = DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = awg.example.com:443
PersistentKeepalive = 25
`

func TestParseAmneziaWGURI(t *testing.T) {
	link := "vpn://" + base64.RawStdEncoding.EncodeToString([]byte(testAWGConf))
	p, err := ParseAmneziaWGURI(link)
	if err != nil {
		t.Fatalf("ParseAmneziaWGURI: %v", err)
	}
	if p.Protocol != "amneziawg" {
		t.Errorf("Protocol = %q, want amneziawg", p.Protocol)
	}
	if p.Address != "awg.example.com" || p.Port != 443 {
		t.Errorf("Address:Port = %s:%d, want awg.example.com:443 (from [Peer] Endpoint)", p.Address, p.Port)
	}
	a := p.AWG
	if a == nil {
		t.Fatal("AWG is nil")
	}
	switch {
	case a.PrivateKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=":
		t.Errorf("PrivateKey = %q", a.PrivateKey)
	case len(a.Address) != 1 || a.Address[0] != "10.8.1.2/32":
		t.Errorf("Address (tunnel) = %v, want [10.8.1.2/32]", a.Address)
	case len(a.DNS) != 2 || a.DNS[0] != "8.8.8.8" || a.DNS[1] != "8.8.4.4":
		t.Errorf("DNS = %v, want [8.8.8.8 8.8.4.4]", a.DNS)
	case a.Jc != "4" || a.Jmin != "40" || a.Jmax != "70":
		t.Errorf("Jc/Jmin/Jmax = %q/%q/%q", a.Jc, a.Jmin, a.Jmax)
	case a.H1 != "1000000001-1000000010":
		t.Errorf("H1 = %q, want the range verbatim", a.H1)
	case a.I1 != "<b 0xdeadbeef><r 16>":
		t.Errorf("I1 = %q, want the decoy notation verbatim", a.I1)
	case a.HeaderProtectionKey != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=":
		t.Errorf("HeaderProtectionKey = %q, want the base64 form verbatim (patched core converts it)", a.HeaderProtectionKey)
	case a.RandomTrailers != "on" || a.DisableCookies != "on":
		t.Errorf("RandomTrailers/DisableCookies = %q/%q, want the .conf's own on/on verbatim", a.RandomTrailers, a.DisableCookies)
	case a.PeerPublicKey != "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=":
		t.Errorf("PeerPublicKey = %q", a.PeerPublicKey)
	case a.PresharedKey != "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=":
		t.Errorf("PresharedKey = %q", a.PresharedKey)
	case len(a.AllowedIPs) != 2 || a.AllowedIPs[0] != "0.0.0.0/0" || a.AllowedIPs[1] != "::/0":
		t.Errorf("AllowedIPs = %v", a.AllowedIPs)
	case a.PersistentKeepalive != 25:
		t.Errorf("PersistentKeepalive = %d, want 25", a.PersistentKeepalive)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("parsed profile should validate: %v", err)
	}
}

// TestParseAmneziaWGURI_DualStackAddress is AWG-02's regression test:
// applyAmneziaWGInterfaceField's "address" case used to copy the .conf
// value verbatim (unlike the neighboring "dns" case, which already
// comma-splits) -- a dual-stack "10.8.1.2/32, fd00::2/128" became one
// slice element with a literal comma inside it instead of two.
func TestParseAmneziaWGURI_DualStackAddress(t *testing.T) {
	conf := strings.Replace(testAWGConf, "Address = 10.8.1.2/32", "Address = 10.8.1.2/32, fd00::2/128", 1)
	link := "vpn://" + base64.RawStdEncoding.EncodeToString([]byte(conf))
	p, err := ParseAmneziaWGURI(link)
	if err != nil {
		t.Fatalf("ParseAmneziaWGURI: %v", err)
	}
	if len(p.AWG.Address) != 2 || p.AWG.Address[0] != "10.8.1.2/32" || p.AWG.Address[1] != "fd00::2/128" {
		t.Errorf("Address = %v, want two separate entries [10.8.1.2/32 fd00::2/128]", p.AWG.Address)
	}
}

// TestParseAmneziaWGURI_URLSafeAlphabet confirms the fallback decode path:
// one real link this project was tested against used the URL-safe
// alphabet (RFC 4648 -_ instead of +/), the other the standard one --
// see docs/HANDOFF-amneziawg.md.
func TestParseAmneziaWGURI_URLSafeAlphabet(t *testing.T) {
	// Bytes chosen so the standard encoding is guaranteed to contain both
	// '+' and '/', making this a real test of the URL-safe fallback
	// rather than an accidental no-op (this project's own real links hit
	// exactly this: a payload whose standard-alphabet encoding used '+'/
	// '/' failed to decode until the URL-safe decoder was tried too).
	raw := []byte{0xfb, 0xff, 0xbf, 0x00, 0x01, 0x02, 0xfb, 0xff, 0xbf}
	std := base64.RawStdEncoding.EncodeToString(raw)
	urlSafe := base64.RawURLEncoding.EncodeToString(raw)
	if std == urlSafe {
		t.Fatal("test bytes don't actually exercise the alphabet difference -- fix the fixture")
	}
	got, err := decodeAmneziaWGPayload(urlSafe)
	if err != nil {
		t.Fatalf("decodeAmneziaWGPayload(url-safe): %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("decoded = %x, want %x", got, raw)
	}
}

func TestParseAmneziaWGURI_Rejections(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"not vpn at all", "vless://u@h:443"},
		{"garbage", "not a url at all"},
		{"not base64", "vpn://not valid base64!!"},
		{"missing PrivateKey", "vpn://" + base64.RawStdEncoding.EncodeToString(
			[]byte("[Interface]\nAddress = 10.8.1.2/32\n[Peer]\nPublicKey = X\nEndpoint = h:443\n"))},
		{"missing peer PublicKey", "vpn://" + base64.RawStdEncoding.EncodeToString(
			[]byte("[Interface]\nPrivateKey = X\n[Peer]\nEndpoint = h:443\n"))},
		{"missing Endpoint", "vpn://" + base64.RawStdEncoding.EncodeToString(
			[]byte("[Interface]\nPrivateKey = X\n[Peer]\nPublicKey = Y\n"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAmneziaWGURI(c.uri); err == nil {
				t.Errorf("ParseAmneziaWGURI(%q): expected an error, got nil", c.uri)
			}
		})
	}
}

func TestParseAmneziaWGURI_RemarkFallback(t *testing.T) {
	link := "vpn://" + base64.RawStdEncoding.EncodeToString([]byte(testAWGConf))
	p, err := ParseAmneziaWGURI(link)
	if err != nil {
		t.Fatalf("ParseAmneziaWGURI: %v", err)
	}
	if p.Remark == "" {
		t.Error("Remark should default to something non-empty when the link has no name")
	}
}
