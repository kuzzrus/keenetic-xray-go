package subscription

import (
	"context"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestPick(t *testing.T) {
	ps := []config.Profile{
		{Remark: "🇷🇺 RU-1"}, {Remark: "🇳🇱 NL-1"}, {Remark: "🇩🇪 DE-1"},
	}
	cases := []struct {
		sel     string
		want    string
		wantErr bool
	}{
		{"", "🇷🇺 RU-1", false},
		{"first", "🇷🇺 RU-1", false},
		{"1", "🇳🇱 NL-1", false},
		{"9", "", true},
		{"nl", "🇳🇱 NL-1", false},
		{"de-1", "🇩🇪 DE-1", false},
		{"xx", "", true},
	}
	for _, c := range cases {
		got, err := Pick(ps, c.sel)
		if c.wantErr {
			if err == nil {
				t.Errorf("Pick(%q): want error", c.sel)
			}
			continue
		}
		if err != nil || got.Remark != c.want {
			t.Errorf("Pick(%q) = %q, %v; want %q", c.sel, got.Remark, err, c.want)
		}
	}

	if _, err := Pick(nil, ""); err == nil {
		t.Error("Pick on an empty list should error")
	}
}

func TestResolveSource_RawLinkKeepsExtra(t *testing.T) {
	uri := "vless://u@h:443?type=xhttp&security=none&mode=auto" +
		"&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D#x"
	p, err := ResolveSource(context.TODO(), uri, "")
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if len(p.XHTTPExtra) == 0 {
		t.Error("ResolveSource dropped the xhttp extra blob from a raw link")
	}
}

func TestResolveSource_BadScheme(t *testing.T) {
	if _, err := ResolveSource(context.TODO(), "ss://whatever", ""); err == nil {
		t.Error("ResolveSource should reject a non-vless / non-http source")
	}
}
