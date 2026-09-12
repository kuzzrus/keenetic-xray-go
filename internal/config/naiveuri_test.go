package config

import "testing"

func TestParseNaiveURI(t *testing.T) {
	p, err := ParseNaiveURI("naive+https://alice:s3cret@naive.example.com:8443#My%20Naive")
	if err != nil {
		t.Fatalf("ParseNaiveURI: %v", err)
	}
	switch {
	case p.Remark != "My Naive":
		t.Errorf("Remark = %q, want %q", p.Remark, "My Naive")
	case p.Protocol != "naive":
		t.Errorf("Protocol = %q, want naive", p.Protocol)
	case p.Address != "naive.example.com":
		t.Errorf("Address = %q, want naive.example.com", p.Address)
	case p.Port != 8443:
		t.Errorf("Port = %d, want 8443", p.Port)
	case p.SNI != "naive.example.com":
		t.Errorf("SNI = %q, want naive.example.com", p.SNI)
	case p.User != "alice":
		t.Errorf("User = %q, want alice", p.User)
	case p.Password != "s3cret":
		t.Errorf("Password = %q, want s3cret", p.Password)
	case p.UUID != "":
		t.Errorf("UUID = %q, want empty (naive has none)", p.UUID)
	}
	if err := p.Validate(); err != nil {
		t.Errorf("parsed profile should validate: %v", err)
	}
}

func TestParseNaiveURI_DefaultPortAndRemark(t *testing.T) {
	// No explicit port -> 443 (naive's proxy is always TLS). No fragment
	// -> Remark falls back to the host, same convention as ParseVLESSURI.
	p, err := ParseNaiveURI("naive+https://u:p@bare.example.com")
	if err != nil {
		t.Fatalf("ParseNaiveURI: %v", err)
	}
	if p.Port != 443 {
		t.Errorf("Port = %d, want 443 (default)", p.Port)
	}
	if p.Remark != "bare.example.com" {
		t.Errorf("Remark = %q, want the host", p.Remark)
	}
}

func TestParseNaiveURI_Rejections(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"not naive at all", "vless://u@h:443"},
		{"bare naive, no inner scheme", "naive://u:p@h:443"},
		{"quic not supported yet", "naive+quic://u:p@h:443"},
		{"plaintext http rejected", "naive+http://u:p@h:443"},
		{"unknown inner scheme", "naive+ftp://u:p@h:443"},
		{"missing user", "naive+https://h:443"},
		{"missing password", "naive+https://onlyuser@h:443"},
		{"missing host", "naive+https://u:p@:443"},
		{"garbage", "not a url at all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseNaiveURI(c.uri); err == nil {
				t.Errorf("ParseNaiveURI(%q): expected an error, got nil", c.uri)
			}
		})
	}
}
