package l7sni

import (
	"bytes"
	"strings"
)

// httpMethods are the request methods a real client actually sends over
// plain HTTP/1.x -- enough to recognize the start of a request without
// validating the whole request line. CONNECT is deliberately excluded:
// it's how an explicit HTTP proxy is asked to open a tunnel (the target
// host lives in the request line, not a Host header), a different
// traffic shape than the transparent-redirect capture this package is
// built for (same scope as HydraRoute's own dport-based capture, which
// doesn't special-case it either).
var httpMethods = [][]byte{
	[]byte("GET"), []byte("POST"), []byte("HEAD"),
	[]byte("PUT"), []byte("DELETE"), []byte("OPTIONS"), []byte("PATCH"),
}

// IsHTTPRequest is a cheap check for "looks like the start of an
// HTTP/1.x request line" -- doesn't validate the rest of the line or
// require a trailing CRLF, so it works on a still-arriving, possibly
// truncated buffer.
func IsHTTPRequest(data []byte) bool {
	for _, m := range httpMethods {
		if len(data) > len(m) && data[len(m)] == ' ' && bytes.HasPrefix(data, m) {
			return true
		}
	}
	return false
}

// ExtractHTTPHost parses a plaintext HTTP/1.x request's Host header,
// lowercased with any ":port" suffix stripped. ok is false if data
// doesn't contain a complete header line naming Host.
//
// No reassembly path the way ExtractTLSSNI has one: the request line
// plus a Host header are small enough to land in whatever single packet
// NFLOG's own connbytes-filtered capture already grabs, and plain HTTP
// is rare enough on the modern web that a fuller multi-segment
// reassembly path isn't worth the added complexity here.
func ExtractHTTPHost(data []byte) (host string, ok bool) {
	for {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			return "", false
		}
		line := bytes.TrimSuffix(data[:nl], []byte("\r"))
		data = data[nl+1:]
		if len(line) == 0 {
			return "", false // end of headers, no Host seen
		}
		name, value, found := bytes.Cut(line, []byte(":"))
		if !found || !bytes.EqualFold(bytes.TrimSpace(name), []byte("host")) {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(string(value)))
		if i := strings.LastIndexByte(h, ':'); i > 0 && isAllDigits(h[i+1:]) {
			h = h[:i]
		}
		if h == "" {
			return "", false
		}
		return h, true
	}
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
