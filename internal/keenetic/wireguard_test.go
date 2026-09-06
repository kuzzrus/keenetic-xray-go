package keenetic

import (
	"context"
	"strings"
	"testing"
)

// A running-config modeled on the real `buba` output: four hand-made WG
// interfaces (0..3), none of them ours.
const wgRC = `interface Wireguard0
    description "\xd0\x9a\xd0\xbe\xd0\xbc\xd0\xbf_awg"
    security-level public
    ip address 10.8.10.2 255.255.255.255
    wireguard peer w+P9JKLsp/aZWZcAkO0HhgbEIkyDt1nTHZqRbK6KdUA=
        endpoint ccl.852654.xyz:443
        connect
    !
    down
!
interface Wireguard1
    description "Wireguard VPN Server"
    security-level private
    ip address 172.16.6.1 255.255.255.0
    wireguard listen-port 41495
    up
!
interface Wireguard2
    description Bubadom
    ip address 10.8.0.67 255.255.255.0
!
interface Wireguard3
    description "\xd0\xa0..."
    ip address 10.8.1.3 255.255.255.255
    up
!
`

// wgIfaceShow is a `show interface Wireguard4` for a freshly created
// interface: KeeneticOS has generated its keypair, no working peer yet.
const wgIfaceShow = `               id: Wireguard4
             type: Wireguard
              mtu: 1280
   security-level: public
        wireguard:
           public-key: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
          listen-port: 40000
               status: down
                 peer:
                      public-key:
                                  BAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
`

const testXrayPub = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
const testPSK = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="

func TestFreeWireguardIface(t *testing.T) {
	fakeNdmc(t, map[string]string{"show running-config": wgRC})
	got, err := FreeWireguardIface(context.Background())
	if err != nil || got != "Wireguard4" {
		t.Fatalf("FreeWireguardIface = (%q, %v), want Wireguard4", got, err)
	}
}

func TestFreeWireguardIface_ReusesOurs(t *testing.T) {
	rc := wgRC + "interface Wireguard9\n    description " + WGIfaceMarker + "\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc})
	got, err := FreeWireguardIface(context.Background())
	if err != nil || got != "Wireguard9" {
		t.Fatalf("FreeWireguardIface = (%q, %v), want the marked Wireguard9", got, err)
	}
}

func TestWGInterfacePublicKey(t *testing.T) {
	fakeNdmc(t, map[string]string{"show interface Wireguard4": wgIfaceShow})
	got, err := WGInterfacePublicKey(context.Background(), "Wireguard4")
	if err != nil {
		t.Fatal(err)
	}
	if got != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Errorf("public key = %q, want the interface key (not the peer key)", got)
	}
}

func TestApplyWGTransport(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{
		"show running-config":       wgRC,
		"show interface Wireguard4": wgIfaceShow,
	})
	spec := WGTransportSpec{
		Iface: "Wireguard4", Address: "172.31.209.2", MTU: 1280,
		PeerPubKey: testXrayPub, PeerPSK: testPSK,
		Endpoint: "192.168.1.1:41199", Keepalive: 25,
	}
	pub, err := ApplyWGTransport(context.Background(), spec)
	if err != nil {
		t.Fatalf("ApplyWGTransport: %v", err)
	}
	if pub != "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" {
		t.Errorf("returned key = %q, want the Wireguard4 interface key", pub)
	}

	joined := strings.Join(*sent, "\n")
	for _, want := range []string{
		"interface Wireguard4 description " + WGIfaceMarker,
		"interface Wireguard4 security-level public",
		"interface Wireguard4 ip address 172.31.209.2 255.255.255.255",
		"interface Wireguard4 ip mtu 1280",
		"interface Wireguard4 ip tcp adjust-mss pmtu",
		"interface Wireguard4 wireguard peer " + testXrayPub,
		"interface Wireguard4 wireguard peer " + testXrayPub + " endpoint 192.168.1.1:41199",
		"interface Wireguard4 wireguard peer " + testXrayPub + " keepalive-interval 25",
		"interface Wireguard4 wireguard peer " + testXrayPub + " preshared-key " + testPSK,
		"interface Wireguard4 wireguard peer " + testXrayPub + " allow-ips 0.0.0.0 0.0.0.0",
		"interface Wireguard4 wireguard peer " + testXrayPub + " connect",
		"interface Wireguard4 up",
		"system configuration save",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing ndmc command: %q", want)
		}
	}
	// Never touches a hand-made interface.
	for _, s := range *sent {
		for _, foreign := range []string{"Wireguard0", "Wireguard1", "Wireguard2", "Wireguard3"} {
			if strings.Contains(s, "interface "+foreign) {
				t.Errorf("touched a foreign interface: %q", s)
			}
		}
	}
}

func TestApplyWGTransport_DropsStalePeer(t *testing.T) {
	rc := wgRC + "interface Wireguard4\n    description " + WGIfaceMarker +
		"\n    wireguard peer OLDXRAYKEYbase64AAAAAAAAAAAAAAAAAAAAAAAA=\n        connect\n    !\n    up\n!\n"
	sent := fakeNdmc(t, map[string]string{
		"show running-config":       rc,
		"show interface Wireguard4": wgIfaceShow,
	})
	_, err := ApplyWGTransport(context.Background(), WGTransportSpec{
		Iface: "Wireguard4", Address: "172.31.209.2", MTU: 1280,
		PeerPubKey: testXrayPub, Endpoint: "192.168.1.1:41199",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*sent, "\n"),
		"interface Wireguard4 no wireguard peer OLDXRAYKEYbase64AAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Errorf("stale peer not removed; sent:\n%s", strings.Join(*sent, "\n"))
	}
}

func TestClearWGTransport(t *testing.T) {
	// Nothing of ours -> no-op.
	sent := fakeNdmc(t, map[string]string{"show running-config": wgRC})
	if err := ClearWGTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range *sent {
		if strings.HasPrefix(s, "no interface") {
			t.Errorf("removed an interface when none was ours: %q", s)
		}
	}

	// Our marked interface -> removed.
	rc := wgRC + "interface Wireguard5\n    description " + WGIfaceMarker + "\n    up\n!\n"
	sent = fakeNdmc(t, map[string]string{"show running-config": rc})
	if err := ClearWGTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*sent, "\n"), "no interface Wireguard5") {
		t.Errorf("our interface not removed; sent: %v", *sent)
	}
}
