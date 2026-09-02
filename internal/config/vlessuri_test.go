package config

import (
	"reflect"
	"testing"
)

func TestParseVLESSURI(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		want Profile
	}{
		{
			name: "tcp none minimal",
			uri:  "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#My%20Server",
			want: Profile{
				Remark:     "My Server",
				UUID:       "11111111-2222-3333-4444-555555555555",
				Address:    "example.com",
				Port:       443,
				Encryption: "none",
				Network:    "tcp",
				Security:   "none",
			},
		},
		{
			name: "ws tls with sni and fingerprint",
			uri:  "vless://uuid-1@1.2.3.4:8443?type=ws&security=tls&sni=cdn.example.com&fp=chrome&path=%2Fws&host=cdn.example.com#ws-tls",
			want: Profile{
				Remark:      "ws-tls",
				UUID:        "uuid-1",
				Address:     "1.2.3.4",
				Port:        8443,
				Encryption:  "none",
				Network:     "ws",
				Security:    "tls",
				SNI:         "cdn.example.com",
				Fingerprint: "chrome",
				Path:        "/ws",
				Host:        "cdn.example.com",
			},
		},
		{
			name: "grpc reality with flow",
			uri:  "vless://uuid-2@10.0.0.1:443?type=grpc&security=reality&pbk=PUBKEY&sid=SHORTID&spx=%2F&flow=xtls-rprx-vision&serviceName=grpcsvc#reality-grpc",
			want: Profile{
				Remark:      "reality-grpc",
				UUID:        "uuid-2",
				Address:     "10.0.0.1",
				Port:        443,
				Encryption:  "none",
				Flow:        "xtls-rprx-vision",
				Network:     "grpc",
				Security:    "reality",
				PublicKey:   "PUBKEY",
				ShortID:     "SHORTID",
				SpiderX:     "/",
				Path:        "grpcsvc",
				ServiceName: "grpcsvc",
			},
		},
		{
			name: "xhttp tls with mode and host",
			uri:  "vless://uuid-6@cdn.example.net:443?type=xhttp&security=tls&sni=cdn.example.net&fp=chrome&path=%2Fxhttp&host=cdn.example.net&mode=stream-up#xhttp-tls",
			want: Profile{
				Remark:      "xhttp-tls",
				UUID:        "uuid-6",
				Address:     "cdn.example.net",
				Port:        443,
				Encryption:  "none",
				Network:     "xhttp",
				Security:    "tls",
				SNI:         "cdn.example.net",
				Fingerprint: "chrome",
				Path:        "/xhttp",
				Host:        "cdn.example.net",
				Mode:        "stream-up",
			},
		},
		{
			name: "http transport, type=http",
			uri:  "vless://uuid-7@h2.example:443?type=http&security=tls&sni=h2.example&path=%2Fh2#h2",
			want: Profile{
				Remark:     "h2",
				UUID:       "uuid-7",
				Address:    "h2.example",
				Port:       443,
				Encryption: "none",
				Network:    "http",
				Security:   "tls",
				SNI:        "h2.example",
				Path:       "/h2",
			},
		},
		{
			name: "http transport, legacy type=h2 alias normalises to http",
			uri:  "vless://uuid-8@h2.example:443?type=h2&security=tls&sni=h2.example&path=%2Fh2#h2",
			want: Profile{
				Remark:     "h2",
				UUID:       "uuid-8",
				Address:    "h2.example",
				Port:       443,
				Encryption: "none",
				Network:    "http",
				Security:   "tls",
				SNI:        "h2.example",
				Path:       "/h2",
			},
		},
		{
			name: "no fragment falls back to address as remark",
			uri:  "vless://uuid-3@host.example:443?type=tcp&security=none",
			want: Profile{
				Remark:     "host.example",
				UUID:       "uuid-3",
				Address:    "host.example",
				Port:       443,
				Encryption: "none",
				Network:    "tcp",
				Security:   "none",
			},
		},
		{
			name: "no port defaults to 443",
			uri:  "vless://uuid-4@host.example?type=tcp&security=none#no-port",
			want: Profile{
				Remark:     "no-port",
				UUID:       "uuid-4",
				Address:    "host.example",
				Port:       443,
				Encryption: "none",
				Network:    "tcp",
				Security:   "none",
			},
		},
		{
			name: "alpn list",
			uri:  "vless://uuid-5@host.example:443?type=tcp&security=tls&alpn=h2,http%2F1.1#alpn",
			want: Profile{
				Remark:     "alpn",
				UUID:       "uuid-5",
				Address:    "host.example",
				Port:       443,
				Encryption: "none",
				Network:    "tcp",
				Security:   "tls",
				ALPN:       []string{"h2", "http/1.1"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVLESSURI(tc.uri)
			if err != nil {
				t.Fatalf("ParseVLESSURI(%q) error: %v", tc.uri, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseVLESSURI(%q) =\n  %#v\nwant\n  %#v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestParseVLESSURI_Errors(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"wrong scheme", "vmess://uuid@host:443"},
		{"missing uuid", "vless://@host:443"},
		{"missing host", "vless://uuid@:443"},
		{"not a URI at all", "not a uri"},
		{"bad port", "vless://uuid@host:notaport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseVLESSURI(tc.uri); err == nil {
				t.Errorf("ParseVLESSURI(%q) expected error, got nil", tc.uri)
			}
		})
	}
}

func TestProfileURI_RoundTrip(t *testing.T) {
	uris := []string{
		"vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#My%20Server",
		"vless://uuid-1@1.2.3.4:8443?type=ws&security=tls&sni=cdn.example.com&fp=chrome&path=%2Fws&host=cdn.example.com#ws-tls",
		"vless://uuid-2@10.0.0.1:443?type=grpc&security=reality&pbk=PUBKEY&sid=SHORTID&spx=%2F&flow=xtls-rprx-vision&serviceName=grpcsvc#reality-grpc",
		"vless://uuid-6@cdn.example.net:443?type=xhttp&security=tls&sni=cdn.example.net&fp=chrome&path=%2Fxhttp&host=cdn.example.net&mode=stream-up#xhttp-tls",
		"vless://uuid-7@h2.example:443?type=http&security=tls&sni=h2.example&path=%2Fh2#h2",
	}

	for _, uri := range uris {
		t.Run(uri, func(t *testing.T) {
			p1, err := ParseVLESSURI(uri)
			if err != nil {
				t.Fatalf("first parse: %v", err)
			}
			roundTripped := p1.URI()
			p2, err := ParseVLESSURI(roundTripped)
			if err != nil {
				t.Fatalf("second parse of round-tripped URI %q: %v", roundTripped, err)
			}
			if !reflect.DeepEqual(p1, p2) {
				t.Errorf("round trip mismatch:\n  original   %#v\n  round-trip %#v", p1, p2)
			}
		})
	}
}
