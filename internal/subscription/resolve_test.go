package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// nodeA / nodeB are two distinct servers; nodeArenamed is nodeA with a
// new display name and a rotated UUID -- same endpoint, so same
// ImportKey.
const (
	nodeA        = "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?type=tcp&security=none#Alpha"
	nodeB        = "vless://22222222-2222-2222-2222-222222222222@b.example.com:8443?type=ws&security=tls&sni=cdn.example.com#Bravo"
	nodeArenamed = "vless://99999999-9999-9999-9999-999999999999@a.example.com:443?type=tcp&security=none#Alpha-NEW-NAME"
)

// mutableSubServer serves whatever body is currently stored; swap it with
// set() to simulate a provider reordering / renaming its nodes.
func mutableSubServer(t *testing.T, initial string) (url string, set func(string)) {
	t.Helper()
	var body atomic.Value
	body.Store(initial)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func(s string) { body.Store(s) }
}

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

func TestResolveSource_NaiveLink(t *testing.T) {
	p, err := ResolveSource(context.TODO(), "naive+https://alice:s3cret@n.example.com:8443#Naive", "")
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if p.Protocol != "naive" || p.User != "alice" || p.Password != "s3cret" || p.Address != "n.example.com" {
		t.Errorf("ResolveSource(naive link) = %+v", p)
	}
}

func TestResolveSourcePinned_AnchorSurvivesReorderAndRename(t *testing.T) {
	url, set := mutableSubServer(t, nodeA+"\n"+nodeB)

	// First resolve: selector "0" -> Alpha, and we learn its ImportKey.
	p, key, err := ResolveSourcePinned(context.Background(), url, "0", "")
	if err != nil || p.Address != "a.example.com" {
		t.Fatalf("first resolve = %q %v, want a.example.com", p.Address, err)
	}
	if key == "" {
		t.Fatal("first resolve returned an empty ImportKey to anchor on")
	}

	// Provider now lists Bravo first AND renames Alpha + rotates its UUID.
	set(nodeB + "\n" + nodeArenamed)

	// Positional selector "0" would now hand back Bravo -- the anchor must win.
	p2, key2, err := ResolveSourcePinned(context.Background(), url, "0", key)
	if err != nil {
		t.Fatalf("anchored resolve: %v", err)
	}
	if p2.Address != "a.example.com" {
		t.Errorf("anchored resolve = %q, want a.example.com (anchor should beat selector 0)", p2.Address)
	}
	if key2 != key {
		t.Errorf("anchor key changed after rename/UUID rotation: %q -> %q", key, key2)
	}
	if p2.Remark != "Alpha-NEW-NAME" {
		t.Errorf("resolved profile should carry the fresh name, got %q", p2.Remark)
	}
}

func TestResolveSourcePinned_FallsBackToSelectorWhenAnchorGone(t *testing.T) {
	url, _ := mutableSubServer(t, nodeA+"\n"+nodeB)

	// Anchor at a server that isn't in this subscription at all.
	p, key, err := ResolveSourcePinned(context.Background(), url, "1", "deadbeefdeadbeef")
	if err != nil {
		t.Fatalf("resolve with a stale anchor should fall back, got: %v", err)
	}
	if p.Address != "b.example.com" {
		t.Errorf("fallback = %q, want b.example.com (selector 1)", p.Address)
	}
	if key == "" || key == "deadbeefdeadbeef" {
		t.Errorf("fallback should return the freshly-picked profile's real key, got %q", key)
	}
}

func TestResolveSourcePinned_BackfillsKeyFromSelector(t *testing.T) {
	url, _ := mutableSubServer(t, nodeA+"\n"+nodeB)
	p, key, err := ResolveSourcePinned(context.Background(), url, "1", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := p.ImportKey(); key != want {
		t.Errorf("backfilled key = %q, want the resolved profile's ImportKey %q", key, want)
	}
}
