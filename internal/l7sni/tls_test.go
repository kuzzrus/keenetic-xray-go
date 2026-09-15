package l7sni

import (
	"encoding/binary"
	"testing"
)

// buildTLSClientHello constructs a minimal, valid TLS ClientHello record.
// If host != "", it carries a server_name extension for that hostname
// (and, if extraExt, a second throwaway extension before it, to exercise
// the "walk past unrelated extensions" path); if host == "", it carries
// no extensions at all (a client connecting straight to an IP).
func buildTLSClientHello(host string, extraExt bool) []byte {
	var ext []byte
	if extraExt {
		// A bogus extension type with 4 bytes of don't-care data --
		// findServerName must skip straight over it.
		ext = append(ext, 0x00, 0x0d) // extension_type: signature_algorithms (unused, just needs a type != 0)
		ext = binary.BigEndian.AppendUint16(ext, 4)
		ext = append(ext, 0xde, 0xad, 0xbe, 0xef)
	}
	if host != "" {
		sn := []byte{0x00} // name_type: host_name
		sn = binary.BigEndian.AppendUint16(sn, uint16(len(host)))
		sn = append(sn, host...)
		snList := binary.BigEndian.AppendUint16(nil, uint16(len(sn)))
		snList = append(snList, sn...)

		ext = append(ext, 0x00, 0x00) // extension_type: server_name
		ext = binary.BigEndian.AppendUint16(ext, uint16(len(snList)))
		ext = append(ext, snList...)
	}

	body := []byte{0x03, 0x03}                  // legacy_version: TLS 1.2 (compat value)
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // legacy_session_id: empty
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: one entry
	body = append(body, 0x01, 0x00)             // legacy_compression_methods: [null]
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{0x01} // Handshake.msg_type: client_hello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01} // ContentType: handshake, legacy_record_version
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestExtractTLSSNI_Basic(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	host, ok := ExtractTLSSNI(rec)
	if !ok || host != "example.com" {
		t.Fatalf("ExtractTLSSNI = %q, %v, want example.com, true", host, ok)
	}
}

func TestExtractTLSSNI_LowercasesHost(t *testing.T) {
	rec := buildTLSClientHello("Example.COM", false)
	host, ok := ExtractTLSSNI(rec)
	if !ok || host != "example.com" {
		t.Fatalf("ExtractTLSSNI = %q, %v, want example.com, true", host, ok)
	}
}

func TestExtractTLSSNI_SkipsOtherExtensions(t *testing.T) {
	rec := buildTLSClientHello("youtube.com", true)
	host, ok := ExtractTLSSNI(rec)
	if !ok || host != "youtube.com" {
		t.Fatalf("ExtractTLSSNI = %q, %v, want youtube.com, true", host, ok)
	}
}

func TestExtractTLSSNI_NoServerNameExtension(t *testing.T) {
	rec := buildTLSClientHello("", false)
	if _, ok := ExtractTLSSNI(rec); ok {
		t.Error("ExtractTLSSNI on a ClientHello with no server_name extension: want ok=false")
	}
}

func TestExtractTLSSNI_NotTLS(t *testing.T) {
	if _, ok := ExtractTLSSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Error("ExtractTLSSNI on plain HTTP bytes: want ok=false")
	}
}

func TestExtractTLSSNI_IncompleteRecord(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	if _, ok := ExtractTLSSNI(rec[:len(rec)-10]); ok {
		t.Error("ExtractTLSSNI on a truncated record: want ok=false, not a partial/wrong host")
	}
}

func TestIsTLSClientHello(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	if !IsTLSClientHello(rec) {
		t.Error("IsTLSClientHello on a real ClientHello: want true")
	}
	if !IsTLSClientHello(rec[:11]) {
		t.Error("IsTLSClientHello on just the first 11 bytes: want true (enough to recognize it)")
	}
	if IsTLSClientHello([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("IsTLSClientHello on plain HTTP: want false")
	}
	if IsTLSClientHello(nil) {
		t.Error("IsTLSClientHello on nil: want false")
	}
}

func TestTLSRecordLen(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	if got := TLSRecordLen(rec); got != len(rec) {
		t.Errorf("TLSRecordLen = %d, want %d (the full record built)", got, len(rec))
	}
}

func TestExtractTLSSNI_IgnoresTrailingBytes(t *testing.T) {
	rec := buildTLSClientHello("example.com", false)
	rec = append(rec, []byte("trailing junk from a coalesced next record")...)
	host, ok := ExtractTLSSNI(rec)
	if !ok || host != "example.com" {
		t.Fatalf("ExtractTLSSNI with trailing bytes past the record = %q, %v, want example.com, true", host, ok)
	}
}
