package l7sni

import "testing"

func TestExtractHTTPHost_Basic(t *testing.T) {
	req := "GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
	host, ok := ExtractHTTPHost([]byte(req))
	if !ok || host != "example.com" {
		t.Fatalf("ExtractHTTPHost = %q, %v, want example.com, true", host, ok)
	}
}

func TestExtractHTTPHost_LowercasesAndStripsPort(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n"
	host, ok := ExtractHTTPHost([]byte(req))
	if !ok || host != "example.com" {
		t.Fatalf("ExtractHTTPHost = %q, %v, want example.com, true", host, ok)
	}
}

func TestExtractHTTPHost_HeaderCaseInsensitive(t *testing.T) {
	req := "GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n"
	host, ok := ExtractHTTPHost([]byte(req))
	if !ok || host != "example.com" {
		t.Fatalf("ExtractHTTPHost = %q, %v, want example.com, true", host, ok)
	}
}

func TestExtractHTTPHost_NoHostHeader(t *testing.T) {
	req := "GET / HTTP/1.0\r\nUser-Agent: test\r\n\r\n"
	if _, ok := ExtractHTTPHost([]byte(req)); ok {
		t.Error("ExtractHTTPHost with no Host header: want ok=false")
	}
}

func TestExtractHTTPHost_TruncatedHeaders(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: example.co"
	if _, ok := ExtractHTTPHost([]byte(req)); ok {
		t.Error("ExtractHTTPHost on a request cut off mid-header: want ok=false")
	}
}

func TestExtractHTTPHost_LFOnlyLineEndings(t *testing.T) {
	req := "GET / HTTP/1.1\nHost: example.com\n\n"
	host, ok := ExtractHTTPHost([]byte(req))
	if !ok || host != "example.com" {
		t.Fatalf("ExtractHTTPHost with bare LF line endings = %q, %v, want example.com, true", host, ok)
	}
}

func TestIsHTTPRequest(t *testing.T) {
	cases := []struct {
		data []byte
		want bool
	}{
		{[]byte("GET / HTTP/1.1\r\n"), true},
		{[]byte("POST /api HTTP/1.1\r\n"), true},
		{[]byte("HEAD / HTTP/1.0\r\n"), true},
		{[]byte("CONNECT example.com:443 HTTP/1.1\r\n"), false}, // deliberately out of scope
		{[]byte("\x16\x03\x01\x00\x05"), false},                 // TLS record, not HTTP
		{[]byte("GETX / HTTP/1.1\r\n"), false},                  // no space right after the method
		{nil, false},
	}
	for _, c := range cases {
		if got := IsHTTPRequest(c.data); got != c.want {
			t.Errorf("IsHTTPRequest(%q) = %v, want %v", c.data, got, c.want)
		}
	}
}
