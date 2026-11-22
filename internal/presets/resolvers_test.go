package presets

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const (
	googleDNS  = "Google Public DNS (8.8.8.8, 8.8.4.4)"
	cloudflare = "Cloudflare (1.1.1.1)"
	quad9      = "Quad9 (9.9.9.9)"
	opendns    = "OpenDNS (208.67.222.222)"
)

func TestResolversIn(t *testing.T) {
	cases := []struct {
		name    string
		entries []string
		want    []string
	}{
		{"exact range", []string{"8.8.8.0/24"}, []string{googleDNS}},
		{"the other Google range", []string{"8.8.4.0/24"}, []string{googleDNS}},
		{"both Google ranges are one service", []string{"8.8.4.0/24", "8.8.8.0/24"}, []string{googleDNS}},
		{"a single address inside", []string{"8.8.8.8"}, []string{googleDNS}},
		{"a narrower block inside", []string{"8.8.8.0/28"}, []string{googleDNS}},
		{"a wider block that contains it", []string{"8.8.0.0/16"}, []string{googleDNS}},
		{"a much wider block", []string{"8.0.0.0/8"}, []string{googleDNS}},
		{"several services, table order", []string{"208.67.220.0/24", "1.1.1.1", "8.8.8.0/24", "9.9.9.0/24"}, []string{googleDNS, cloudflare, quad9, opendns}},
		{"next door is not inside", []string{"8.8.9.0/24", "8.8.3.0/24", "1.1.2.0/24"}, nil},
		{"unrelated ranges", []string{"142.250.0.0/15", "172.217.0.0/16"}, nil},
		{"junk and IPv6 are ignored", []string{"", "not an address", "2001:4860:4860::8888", "8.8.8.0/99"}, nil},
		{"whitespace is tolerated", []string{" 8.8.8.0/24 "}, []string{googleDNS}},
		{"nothing at all", nil, nil},
	}
	for _, c := range cases {
		if got := ResolversIn(c.entries); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ResolversIn(%v) = %v, want %v", c.name, c.entries, got, c.want)
		}
	}
}

// A subnet preset reports what its own list file covers; a domain preset, a
// list without a resolver and a preset with no file report nothing. Overlay data,
// not the embedded presets: those change with every daily refresh.
func TestPresetResolvers_FromTheListFile(t *testing.T) {
	dir := t.TempDir()
	withOverlay(t, dir)
	pIP, bIP := list("acme-ip", "cidr", "Acme", "8.8.8.0/24", "1.1.1.1", "203.0.113.0/24")
	pPlain, bPlain := list("plain-ip", "cidr", "Plain", "203.0.113.0/24")
	pDom, bDom := list("acme", "domains", "Acme", "alpha.example")
	for name, body := range map[string]string{
		"manifest.json": manifestJSON(pDom, pIP, pPlain),
		"acme-ip.lst":   bIP, "plain-ip.lst": bPlain, "acme.lst": bDom,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if got := pIP.Resolvers(); !reflect.DeepEqual(got, []string{googleDNS, cloudflare}) {
		t.Errorf("acme-ip: Resolvers() = %v, want Google then Cloudflare", got)
	}
	if got := pPlain.Resolvers(); got != nil {
		t.Errorf("plain-ip: Resolvers() = %v, want none", got)
	}
	if got := pDom.Resolvers(); got != nil {
		t.Errorf("a domain preset has no resolvers to report, got %v", got)
	}
	if got := (Preset{Name: "no-such-list", Kind: "cidr"}).Resolvers(); got != nil {
		t.Errorf("a preset without a file: %v", got)
	}
}

func TestResolverNote_NamesTheServicesAndSaysNothingWasChanged(t *testing.T) {
	note := ResolverNote([]string{googleDNS, cloudflare})
	for _, want := range []string{googleDNS, cloudflare, "UDP/53", "Список не менялся"} {
		if !strings.Contains(note, want) {
			t.Errorf("%q not in %q", want, note)
		}
	}
}
