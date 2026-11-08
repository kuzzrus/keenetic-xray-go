package l7sni

import (
	"strings"
	"testing"
)

func TestNormalizeHostname(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) // 253
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"example.com", "example.com", true},
		{"Example.COM", "example.com", true},
		{"example.com.", "example.com", true}, // one trailing dot
		{"a_b.example-1.com", "a_b.example-1.com", true},
		{"localhost", "localhost", true},
		{"1.2.3.4", "1.2.3.4", true}, // an address literal is a valid name here; it will just match nothing
		{long, long, true},
		{long + "x", "", false}, // 254
		{"", "", false},
		{".", "", false},
		{"ex ample.com", "", false},
		{"exa\nmple.com", "", false},
		{"exa\x00mple.com", "", false},
		{"[::1]", "", false},
		{"пример.рф", "", false},
		{"exam*ple.com", "", false},
		{"user@example.com", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeHostname(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("normalizeHostname(%q) = %q, %v, want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestExtractHTTPHost_InvalidHostIsRejected: an IPv6 literal or a name with
// stray bytes is "no host", not something to pass on to the log and the
// matcher.
func TestExtractHTTPHost_InvalidHostIsRejected(t *testing.T) {
	for _, host := range []string{"[::1]:8080", "exa mple.com", "\x1b[2Jevil.example"} {
		req := "GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
		if h, ok := ExtractHTTPHost([]byte(req)); ok {
			t.Errorf("Host %q accepted as %q", host, h)
		}
	}
	if h, ok := ExtractHTTPHost([]byte("GET / HTTP/1.1\r\nHost: Example.COM.:8080\r\n\r\n")); !ok || h != "example.com" {
		t.Errorf("trailing dot and port: got %q, %v, want example.com", h, ok)
	}
}
