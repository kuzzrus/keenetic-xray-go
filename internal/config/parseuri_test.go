package config

import "testing"

func TestParseProfileURI(t *testing.T) {
	t.Run("vless dispatches to ParseVLESSURI", func(t *testing.T) {
		p, err := ParseProfileURI("vless://11111111-2222-3333-4444-555555555555@a.example.com:443?type=tcp&security=none#x")
		if err != nil {
			t.Fatalf("ParseProfileURI: %v", err)
		}
		if p.Protocol != "" || p.UUID == "" || p.Address != "a.example.com" {
			t.Errorf("not a vless profile: %+v", p)
		}
	})

	t.Run("naive dispatches to ParseNaiveURI", func(t *testing.T) {
		p, err := ParseProfileURI("naive+https://u:p@n.example.com:443#y")
		if err != nil {
			t.Fatalf("ParseProfileURI: %v", err)
		}
		if p.Protocol != "naive" || p.User != "u" || p.Password != "p" {
			t.Errorf("not a naive profile: %+v", p)
		}
	})

	t.Run("malformed vless propagates the real error", func(t *testing.T) {
		_, err := ParseProfileURI("vless://@bad:443?type=tcp&security=none")
		if err == nil {
			t.Error("expected an error for a vless link with no UUID")
		}
	})

	t.Run("malformed naive propagates the real error", func(t *testing.T) {
		_, err := ParseProfileURI("naive+quic://u:p@h:443")
		if err == nil {
			t.Error("expected an error for naive+quic:// (unsupported)")
		}
	})

	t.Run("unrecognized scheme", func(t *testing.T) {
		for _, uri := range []string{"vmess://x", "ss://x", "not-a-uri-at-all", ""} {
			if _, err := ParseProfileURI(uri); err == nil {
				t.Errorf("ParseProfileURI(%q): expected an error", uri)
			}
		}
	})

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		p, err := ParseProfileURI("  naive+https://u:p@n.example.com  \n")
		if err != nil {
			t.Fatalf("ParseProfileURI: %v", err)
		}
		if p.Address != "n.example.com" {
			t.Errorf("Address = %q", p.Address)
		}
	})
}
