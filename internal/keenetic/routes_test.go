package keenetic

import (
	"context"
	"strings"
	"testing"
)

const ver51 = "          release: 5.01.C.3.0-1\n            title: 5.1.3\n             arch: aarch64\n"
const ver43 = "            title: 4.3.7\n"

// runningConfig with the operator's own hand-made lists plus one of ours,
// modeled on the real `buba` output.
const rcFixture = `interface Proxy0
    description keenetic-xray
    up
!
object-group fqdn youtube
    include youtube.com
    include googlevideo.com
!
object-group fqdn domain-list0
    include example.org
!
object-group fqdn keenetic-xray-media
    include netflix.com
    include 1.2.3.0/24
!
service dns-proxy
dns-proxy
    route object-group youtube Proxy0 auto
    route object-group domain-list0 Wireguard1 auto
    route object-group keenetic-xray-media Proxy0 auto
    tls upstream router.example.xyz
    https upstream https://dns.example/query
!
`

func TestOSVersion(t *testing.T) {
	fakeNdmc(t, map[string]string{"show version": ver51})
	maj, min, patch, err := OSVersion(context.Background())
	if err != nil || maj != 5 || min != 1 || patch != 3 {
		t.Fatalf("OSVersion = (%d,%d,%d,%v), want (5,1,3,nil)", maj, min, patch, err)
	}
	if ok, _ := OSAtLeast(context.Background(), 5, 0); !ok {
		t.Error("OSAtLeast(5,0) = false for 5.1.3")
	}
	if ok, _ := OSAtLeast(context.Background(), 6, 0); ok {
		t.Error("OSAtLeast(6,0) = true for 5.1.3")
	}
}

func TestReadOurRoutes_OnlyPrefixed(t *testing.T) {
	fakeNdmc(t, map[string]string{"show running-config": rcFixture})
	groups, routes, err := readOurRoutes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %v, want just keenetic-xray-media", groups)
	}
	if got := groups["keenetic-xray-media"]; strings.Join(got, ",") != "netflix.com,1.2.3.0/24" {
		t.Errorf("entries = %v", got)
	}
	if len(routes) != 1 || routes["keenetic-xray-media"].iface != "Proxy0" {
		t.Errorf("routes = %v, want just keenetic-xray-media -> Proxy0", routes)
	}
}

func TestApplyRoutes_ReconcilesAndNeverTouchesForeignLists(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show version":        ver51,
		"show running-config": rcFixture,
	})

	want := []DesiredRoute{
		// media: drop the /24, add a domain, keep netflix.com
		{Group: "keenetic-xray-media", Iface: "Proxy0", Entries: []string{"netflix.com", "disneyplus.com"}},
		// a brand-new list, exclusive
		{Group: "keenetic-xray-work", Iface: "Proxy1", Entries: []string{"corp.example"}, Reject: true},
	}
	rep, err := ApplyRoutes(context.Background(), want)
	if err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}

	all := strings.Join(*sent, "\n")
	for _, foreign := range []string{"youtube", "domain-list0", "wireguard1", "tls upstream", "https upstream"} {
		if strings.Contains(strings.ToLower(all), foreign) {
			t.Errorf("ApplyRoutes issued a command touching a foreign name %q:\n%s", foreign, all)
		}
	}

	assertSent(t, *sent, "object-group fqdn keenetic-xray-media include disneyplus.com")
	assertSent(t, *sent, "no object-group fqdn keenetic-xray-media include 1.2.3.0/24")
	assertSent(t, *sent, "object-group fqdn keenetic-xray-work")
	assertSent(t, *sent, "object-group fqdn keenetic-xray-work include corp.example")
	assertSent(t, *sent, "dns-proxy route object-group keenetic-xray-work Proxy1 auto reject")
	assertSent(t, *sent, "system configuration save")
	notSent(t, *sent, "dns-proxy route object-group keenetic-xray-media") // unchanged route, not rewritten

	if rep.EntriesAdded != 2 || rep.EntriesRemoved != 1 {
		t.Errorf("report entries add/remove = %d/%d, want 2/1", rep.EntriesAdded, rep.EntriesRemoved)
	}
}

func TestApplyRoutes_RemovesDeletedList(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show version":        ver51,
		"show running-config": rcFixture,
	})
	if _, err := ApplyRoutes(context.Background(), nil); err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}
	assertSent(t, *sent, "no dns-proxy route object-group keenetic-xray-media Proxy0")
	assertSent(t, *sent, "no object-group fqdn keenetic-xray-media")
	// the operator's own youtube route/group are left alone
	notSent(t, *sent, "no dns-proxy route object-group youtube")
	notSent(t, *sent, "no object-group fqdn youtube")
}

func TestApplyRoutes_DisabledDropsRouteKeepsGroup(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show version":        ver51,
		"show running-config": rcFixture,
	})
	want := []DesiredRoute{
		{Group: "keenetic-xray-media", Iface: "Proxy0", Entries: []string{"netflix.com", "1.2.3.0/24"}, Disabled: true},
	}
	if _, err := ApplyRoutes(context.Background(), want); err != nil {
		t.Fatalf("ApplyRoutes: %v", err)
	}
	assertSent(t, *sent, "no dns-proxy route object-group keenetic-xray-media Proxy0")
	notSent(t, *sent, "no object-group fqdn keenetic-xray-media")
	notSent(t, *sent, "no object-group fqdn keenetic-xray-media include")
}

func TestApplyRoutes_OldOSRejected(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show version":        ver43,
		"show running-config": rcFixture,
	})
	_, err := ApplyRoutes(context.Background(), []DesiredRoute{
		{Group: "keenetic-xray-x", Iface: "Proxy0", Entries: []string{"a.io"}},
	})
	if err == nil {
		t.Fatal("expected an error on KeeneticOS 4.3")
	}
	for _, c := range *sent {
		if strings.HasPrefix(c, "object-group") || strings.HasPrefix(c, "dns-proxy") || c == "system configuration save" {
			t.Errorf("mutating command %q issued on an unsupported OS", c)
		}
	}
}

func TestApplyRoutes_NoChangeNoSave(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show version":        ver51,
		"show running-config": rcFixture,
	})
	want := []DesiredRoute{
		{Group: "keenetic-xray-media", Iface: "Proxy0", Entries: []string{"netflix.com", "1.2.3.0/24"}},
	}
	rep, err := ApplyRoutes(context.Background(), want)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Saved {
		t.Error("Saved = true with nothing to change")
	}
	notSent(t, *sent, "system configuration save")
}

func TestClearRoutes_OnlyOurs(t *testing.T) {
	rc := rcFixture + "object-group fqdn keenetic-xray-extra\n    include a.io\n!\ndns-proxy\n    route object-group keenetic-xray-extra Proxy0 auto\n!\n"
	sent := fakeNdmc(t, map[string]string{"show running-config": rc})
	if err := ClearRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSent(t, *sent, "no object-group fqdn keenetic-xray-media")
	assertSent(t, *sent, "no object-group fqdn keenetic-xray-extra")
	assertSent(t, *sent, "system configuration save")
	all := strings.ToLower(strings.Join(*sent, "\n"))
	if strings.Contains(all, "youtube") || strings.Contains(all, "domain-list0") {
		t.Errorf("ClearRoutes touched a foreign list:\n%s", all)
	}
}

func assertSent(t *testing.T, sent []string, want string) {
	t.Helper()
	for _, c := range sent {
		if c == want {
			return
		}
	}
	t.Errorf("command not issued: %q\ngot:\n%s", want, strings.Join(sent, "\n"))
}

func notSent(t *testing.T, sent []string, unwantedPrefix string) {
	t.Helper()
	for _, c := range sent {
		if strings.HasPrefix(c, unwantedPrefix) {
			t.Errorf("unexpected command issued: %q (prefix %q)", c, unwantedPrefix)
		}
	}
}
