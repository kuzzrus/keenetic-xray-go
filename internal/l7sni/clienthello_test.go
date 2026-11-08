package l7sni

import (
	"encoding/binary"
	"strings"
	"testing"
)

// recordOf wraps a handshake message in a TLS record, the way it travels
// over TCP.
func recordOf(hs []byte) []byte {
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestParseClientHello_NamesAndECHMarker(t *testing.T) {
	ech := encodeExt(extTypeEncryptedClientHello, make([]byte, 40))
	other := encodeExt(0x002b, []byte{0x02, 0x03, 0x04})

	cases := []struct {
		name     string
		hs       []byte
		wantHost string
		wantECH  bool
	}{
		{"plain", buildClientHelloMsg("example.com", other), "example.com", false},
		{"ECH extension after the name", buildClientHelloMsg("cloudflare-ech.com", other, ech), "cloudflare-ech.com", true},
		{"ECH extension before the name", func() []byte {
			// the helper writes server_name first; put ECH ahead of it by hand
			hs := buildClientHelloMsg("", ech)
			return withServerNameAfter(t, hs, "example.org")
		}(), "example.org", true},
		{"no name at all, ECH only", buildClientHelloMsg("", ech), "", true},
		{"no name, nothing else", buildClientHelloMsg(""), "", false},
		{"upper case is folded", buildClientHelloMsg("WWW.Example.COM"), "www.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := ParseClientHello(tc.hs)
			if !ok {
				t.Fatal("ParseClientHello: ok=false")
			}
			if info.Host != tc.wantHost || info.ECH != tc.wantECH {
				t.Errorf("got %+v, want host %q ECH %v", info, tc.wantHost, tc.wantECH)
			}
		})
	}
}

// withServerNameAfter appends a server_name extension to a ClientHello
// message's extension block (and fixes the lengths), so a test can place
// another extension ahead of it.
func withServerNameAfter(t *testing.T, hs []byte, host string) []byte {
	t.Helper()
	sn := []byte{0x00}
	sn = binary.BigEndian.AppendUint16(sn, uint16(len(host)))
	sn = append(sn, host...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(sn)))
	list = append(list, sn...)
	add := encodeExt(extTypeServerName, list)

	out := append(append([]byte(nil), hs...), add...)
	bodyLen := len(out) - 4
	out[1], out[2], out[3] = byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen)
	// the extensions length sits 2 bytes before the extensions: after
	// version(2) random(32) sid(1) ciphers(2+2) comp(1+1) = 41 bytes of body
	extLenAt := 4 + 41
	binary.BigEndian.PutUint16(out[extLenAt:], binary.BigEndian.Uint16(out[extLenAt:])+uint16(len(add)))
	return out
}

func TestParseClientHello_FirstServerNameWins(t *testing.T) {
	hs := withServerNameAfter(t, buildClientHelloMsg("first.example"), "second.example")
	info, ok := ParseClientHello(hs)
	if !ok || info.Host != "first.example" {
		t.Errorf("got %+v, %v, want the first server_name", info, ok)
	}
}

func TestParseClientHello_Rejects(t *testing.T) {
	good := buildClientHelloMsg("example.com")
	if _, ok := ParseClientHello(good[:len(good)-1]); ok {
		t.Error("an incomplete ClientHello parsed as ok")
	}
	notHello := append([]byte{0x02}, good[1:]...)
	if _, ok := ParseClientHello(notHello); ok {
		t.Error("a ServerHello-typed message parsed as a ClientHello")
	}
	if _, ok := ParseClientHello(nil); ok {
		t.Error("nil parsed as ok")
	}
}

// TestParseClientHello_UnusableNameIsDroppedNotRepaired: a server_name that
// is not a hostname gives an empty Host, while the ClientHello itself (and
// its ECH marker) still parse.
func TestParseClientHello_UnusableNameIsDroppedNotRepaired(t *testing.T) {
	for _, host := range []string{"ex ample.com", "exa\nmple.com", "\x1b[31mred.example", "пример.рф", strings.Repeat("a", 254)} {
		info, ok := ParseClientHello(buildClientHelloMsg(host, encodeExt(extTypeEncryptedClientHello, []byte{1})))
		if !ok || info.Host != "" || !info.ECH {
			t.Errorf("host %q: got %+v, %v, want an empty Host with the ClientHello still parsed", host, info, ok)
		}
	}
}

func TestExtractTLSInfo_OverTCPRecord(t *testing.T) {
	rec := recordOf(buildClientHelloMsg("cloudflare-ech.com", encodeExt(extTypeEncryptedClientHello, make([]byte, 30))))
	info, ok := ExtractTLSInfo(rec)
	if !ok || info.Host != "cloudflare-ech.com" || !info.ECH {
		t.Errorf("got %+v, %v", info, ok)
	}
	if host, ok := ExtractTLSSNI(rec); !ok || host != "cloudflare-ech.com" {
		t.Errorf("ExtractTLSSNI = %q, %v", host, ok)
	}
	// no usable name: Info parses, the SNI-only API reports nothing
	rec = recordOf(buildClientHelloMsg(""))
	if info, ok := ExtractTLSInfo(rec); !ok || info.Host != "" {
		t.Errorf("no-name ClientHello: got %+v, %v", info, ok)
	}
	if _, ok := ExtractTLSSNI(rec); ok {
		t.Error("ExtractTLSSNI reported a host for a ClientHello without one")
	}
}
