package keenetic

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fakeNdmc installs a stub for ndmcRun/lookNdmc for the duration of a
// test. respond maps a `show ...` command to its output; every other
// command is recorded and returns "".
func fakeNdmc(t *testing.T, respond map[string]string) *[]string {
	t.Helper()
	var sent []string
	origRun, origLook := ndmcRun, lookNdmc
	ndmcRun = func(_ context.Context, cmd string) (string, error) {
		sent = append(sent, cmd)
		if out, ok := respond[cmd]; ok {
			return out, nil
		}
		if strings.HasPrefix(cmd, "show ") {
			return "", nil
		}
		return "", nil
	}
	lookNdmc = func() error { return nil }
	t.Cleanup(func() { ndmcRun, lookNdmc = origRun, origLook })
	return &sent
}

func TestValidPrivateIPv4(t *testing.T) {
	good := []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.254", "10.255.255.255"}
	bad := []string{"", "127.0.0.1", "8.8.8.8", "192.168.1.1/24", "172.15.0.1", "172.32.0.1", "10.0.0.256", "10.0.0", "1.2.3.4.5", "0.0.0.0"}
	for _, s := range good {
		if !validPrivateIPv4(s) {
			t.Errorf("validPrivateIPv4(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if validPrivateIPv4(s) {
			t.Errorf("validPrivateIPv4(%q) = true, want false", s)
		}
	}
}

func TestLANIP_OverrideWins(t *testing.T) {
	got, err := LANIP(context.Background(), "192.168.50.1")
	if err != nil || got != "192.168.50.1" {
		t.Fatalf("LANIP(override) = (%q, %v)", got, err)
	}
	if _, err := LANIP(context.Background(), "127.0.0.1"); err == nil {
		t.Error("LANIP should reject a loopback override")
	}
}

func TestLANIP_FromShowInterface(t *testing.T) {
	fakeNdmc(t, map[string]string{
		"show running-config":    "interface Bridge0\n    description Home\n", // no ip address line
		"show interface Bridge0": "               id: Bridge0\n          address: 192.168.1.1\n             mask: 255.255.255.0\n",
	})
	got, err := LANIP(context.Background(), "")
	if err != nil || got != "192.168.1.1" {
		t.Fatalf("LANIP = (%q, %v), want 192.168.1.1", got, err)
	}
}

func TestLANIP_FromRunningConfig_IgnoresWANLikeAddresses(t *testing.T) {
	// A 10.x address on a mobile WAN interface must not be picked up --
	// only Bridge0/Home/br0 are consulted.
	rc := strings.Join([]string{
		"interface UsbLte0",
		"    ip address 10.64.1.23/30",
		"interface Bridge0",
		"    ip address 192.168.88.1/24",
	}, "\n")
	fakeNdmc(t, map[string]string{"show running-config": rc})
	got, err := LANIP(context.Background(), "")
	if err != nil || got != "192.168.88.1" {
		t.Fatalf("LANIP = (%q, %v), want 192.168.88.1", got, err)
	}
}

func TestConfigureProxy0_SendsSequenceAndVerifies(t *testing.T) {
	// running-config reports the upstream we're about to set, so the
	// read-back check passes.
	rc := "interface Proxy0\n    proxy protocol socks5\n    proxy upstream 192.168.1.1 10808\n"
	sent := fakeNdmc(t, map[string]string{"show running-config": rc})

	err := ConfigureProxy0(context.Background(), Proxy0Options{
		UpstreamHost: "192.168.1.1",
		UpstreamPort: 10808,
	})
	if err != nil {
		t.Fatalf("ConfigureProxy0: %v", err)
	}

	joined := strings.Join(*sent, "\n")
	for _, want := range []string{
		"interface Proxy0",
		"interface Proxy0 proxy protocol socks5",
		"interface Proxy0 proxy socks5-udp",
		"interface Proxy0 proxy upstream 192.168.1.1 10808",
		"interface Proxy0 no ip global",
		"interface Proxy0 up",
		"system configuration save",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("ndmc sequence missing %q\n---\n%s", want, joined)
		}
	}
}

func TestConfigureProxy0_ReadBackMismatchFails(t *testing.T) {
	rc := "interface Proxy0\n    proxy upstream 192.168.1.1 9999\n" // wrong port
	fakeNdmc(t, map[string]string{"show running-config": rc})

	err := ConfigureProxy0(context.Background(), Proxy0Options{UpstreamHost: "192.168.1.1", UpstreamPort: 10808})
	if err == nil || !strings.Contains(err.Error(), "reads back as") {
		t.Fatalf("ConfigureProxy0 err = %v, want a read-back mismatch", err)
	}
}

func TestConfigureProxy0_RejectsBadUpstream(t *testing.T) {
	fakeNdmc(t, nil)
	for _, o := range []Proxy0Options{
		{UpstreamHost: "127.0.0.1", UpstreamPort: 10808},
		{UpstreamHost: "192.168.1.1", UpstreamPort: 0},
		{UpstreamHost: "8.8.8.8", UpstreamPort: 10808},
	} {
		if err := ConfigureProxy0(context.Background(), o); err == nil {
			t.Errorf("ConfigureProxy0(%+v) = nil, want an error", o)
		}
	}
}

func TestProxy0Upstream(t *testing.T) {
	fakeNdmc(t, map[string]string{
		"show running-config": "interface GuestWiFi\n    ip address 192.168.2.1/24\ninterface Proxy0\n    proxy upstream 192.168.1.1 10808\n    proxy protocol socks5\n",
	})
	host, port, ok, err := Proxy0Upstream(context.Background(), "")
	if err != nil || !ok || host != "192.168.1.1" || port != 10808 {
		t.Fatalf("Proxy0Upstream = (%q, %d, %v, %v)", host, port, ok, err)
	}
}

func TestProxy0Upstream_NoneSet(t *testing.T) {
	fakeNdmc(t, map[string]string{"show running-config": "interface Proxy0\n    proxy protocol socks5\n"})
	if _, _, ok, err := Proxy0Upstream(context.Background(), "Proxy0"); ok || err != nil {
		t.Fatalf("Proxy0Upstream ok=%v err=%v, want (false, nil)", ok, err)
	}
}

func TestDisableProxy0(t *testing.T) {
	sent := fakeNdmc(t, nil)
	if err := DisableProxy0(context.Background(), ""); err != nil {
		t.Fatalf("DisableProxy0: %v", err)
	}
	if got := strings.Join(*sent, "|"); got != "interface Proxy0 down|system configuration save" {
		t.Errorf("sent = %q", got)
	}
}

// ensure the exec-backed defaults at least compile / don't panic when
// ndmc is absent
func TestAvailable_NoNdmc(t *testing.T) {
	orig := lookNdmc
	lookNdmc = func() error { return fmt.Errorf("nope") }
	t.Cleanup(func() { lookNdmc = orig })
	if Available() {
		t.Error("Available() = true with no ndmc")
	}
}
