package keenetic

import "testing"

func TestParseObjectGroupCounts(t *testing.T) {
	got := parseObjectGroupCounts(realShowObjectGroupFQDN)
	want := map[string]ObjectGroupCount{
		"akamai":              {IPv4: 340, IPv6: 749, FQDN: 231},
		"keenetic-xray-media": {IPv4: 1, FQDN: 1},
		"keenetic-xray-lan":   {},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d groups %v, want %d", len(got), got, len(want))
	}
	for g, w := range want {
		if got[g] != w {
			t.Errorf("%s = %+v, want %+v", g, got[g], w)
		}
	}
}
