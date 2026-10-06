package keenetic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A running-config with one OpkgTun interface that is NOT ours -- the
// AmneziaWG-go guide's OpkgTun0 -- next to an unrelated WireGuard one.
const tunRC = `interface Wireguard0
    description Home
    security-level public
    up
!
interface OpkgTun0
    description "awg-go"
    security-level public
    ip address 10.8.0.2 255.255.255.255
    ip mtu 1376
    up
!
`

// tunIfaceShow is `show interface OpkgTun1` with xray holding the device.
const tunIfaceShow = `               id: OpkgTun1
             type: OpkgTun
            state: up
             link: up
        connected: yes
          address: 172.31.254.2
              mtu: 1280
`

// tunDevices points sysClassNet at a temp dir holding the named devices
// and makes waiting for a device that never comes cheap.
func tunDevices(t *testing.T, devs ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range devs {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	origDir, origWait, origPoll := sysClassNet, tunDeviceWait, tunDevicePoll
	sysClassNet, tunDeviceWait, tunDevicePoll = dir, 60*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { sysClassNet, tunDeviceWait, tunDevicePoll = origDir, origWait, origPoll })
	return dir
}

func TestTunDeviceName(t *testing.T) {
	for in, want := range map[string]string{
		"OpkgTun0": "opkgtun0", "OpkgTun12": "opkgtun12",
		"": "", "Wireguard0": "", "OpkgTun": "", "opkgtun0": "", "OpkgTun0 ": "", "OpkgTunX": "", "Proxy0": "",
	} {
		if got := TunDeviceName(in); got != want {
			t.Errorf("TunDeviceName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTunDevicePresent(t *testing.T) {
	tunDevices(t, "opkgtun0")
	if !TunDevicePresent("opkgtun0") {
		t.Error("TunDevicePresent(opkgtun0) = false, the device exists")
	}
	for _, bad := range []string{"", "opkgtun1", "../opkgtun0", "a/b", `a\b`} {
		if TunDevicePresent(bad) {
			t.Errorf("TunDevicePresent(%q) = true", bad)
		}
	}
}

func TestFreeOpkgTunIface(t *testing.T) {
	tunDevices(t)
	fakeNdmc(t, map[string]string{"show running-config": tunRC})
	got, err := FreeOpkgTunIface(context.Background())
	if err != nil || got != "OpkgTun1" {
		t.Fatalf("FreeOpkgTunIface = (%q, %v), want OpkgTun1 -- OpkgTun0 is somebody else's", got, err)
	}
}

func TestFreeOpkgTunIface_SkipsLeftoverDevice(t *testing.T) {
	tunDevices(t, "opkgtun1")
	fakeNdmc(t, map[string]string{"show running-config": tunRC})
	got, err := FreeOpkgTunIface(context.Background())
	if err != nil || got != "OpkgTun2" {
		t.Fatalf("FreeOpkgTunIface = (%q, %v), want OpkgTun2 -- a device named opkgtun1 already exists", got, err)
	}
}

func TestFreeOpkgTunIface_ReusesOurs(t *testing.T) {
	tunDevices(t)
	rc := tunRC + "interface OpkgTun3\n    description " + TunIfaceMarker + "\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc})
	got, err := FreeOpkgTunIface(context.Background())
	if err != nil || got != "OpkgTun3" {
		t.Fatalf("FreeOpkgTunIface = (%q, %v), want the marked OpkgTun3", got, err)
	}
}

func TestActiveTunIface(t *testing.T) {
	fakeNdmc(t, map[string]string{"show running-config": tunRC})
	if got, err := ActiveTunIface(context.Background()); err != nil || got != "" {
		t.Fatalf("ActiveTunIface = (%q, %v), want (\"\", nil) -- no marked interface exists yet", got, err)
	}
	rc := tunRC + "interface OpkgTun3\n    description \"" + TunIfaceMarker + "\"\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc})
	if got, err := ActiveTunIface(context.Background()); err != nil || got != "OpkgTun3" {
		t.Fatalf("ActiveTunIface = (%q, %v), want the marked OpkgTun3", got, err)
	}
}

func TestApplyTunTransport(t *testing.T) {
	tunDevices(t, "opkgtun1")
	sent := fakeNdmc(t, map[string]string{"show running-config": tunRC})
	err := ApplyTunTransport(context.Background(), TunTransportSpec{Iface: "OpkgTun1", Address: "172.31.254.2", MTU: 1280})
	if err != nil {
		t.Fatalf("ApplyTunTransport: %v", err)
	}
	want := []string{
		"show running-config",
		"interface OpkgTun1", // the object first: it is what makes ndm create the kernel device
		"interface OpkgTun1 description " + TunIfaceMarker,
		"interface OpkgTun1 security-level public",
		"interface OpkgTun1 ip address 172.31.254.2 255.255.255.255",
		"interface OpkgTun1 ip mtu 1280",
		"interface OpkgTun1 ip tcp adjust-mss pmtu",
		"interface OpkgTun1 up",
		"system configuration save",
	}
	if strings.Join(*sent, "\n") != strings.Join(want, "\n") {
		t.Errorf("ndmc commands:\n%s\nwant:\n%s", strings.Join(*sent, "\n"), strings.Join(want, "\n"))
	}
	for _, s := range *sent {
		if strings.Contains(s, "OpkgTun0") || strings.Contains(s, "Wireguard0") {
			t.Errorf("touched a foreign interface: %q", s)
		}
		if strings.Contains(s, "ip global") {
			t.Errorf("made the interface a default-route candidate: %q", s)
		}
	}
}

func TestApplyTunTransport_ClampsMTU(t *testing.T) {
	tunDevices(t, "opkgtun1")
	sent := fakeNdmc(t, map[string]string{"show running-config": tunRC})
	if err := ApplyTunTransport(context.Background(), TunTransportSpec{Iface: "OpkgTun1", Address: "172.31.254.2", MTU: 600}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(*sent, "\n"), "interface OpkgTun1 ip mtu 1280") {
		t.Errorf("MTU below 1280 not raised; sent: %v", *sent)
	}
}

func TestApplyTunTransport_RefusesForeignInterface(t *testing.T) {
	tunDevices(t, "opkgtun0")
	sent := fakeNdmc(t, map[string]string{"show running-config": tunRC})
	err := ApplyTunTransport(context.Background(), TunTransportSpec{Iface: "OpkgTun0", Address: "172.31.254.2", MTU: 1280})
	if err == nil || !strings.Contains(err.Error(), "somebody else's") {
		t.Fatalf("err = %v, want a refusal to touch OpkgTun0", err)
	}
	if len(*sent) != 1 || (*sent)[0] != "show running-config" {
		t.Errorf("wrote to a foreign interface before refusing; sent: %v", *sent)
	}
}

func TestApplyTunTransport_AdoptsOursAndBare(t *testing.T) {
	for name, block := range map[string]string{
		"ours": "interface OpkgTun1\n    description " + TunIfaceMarker + "\n    down\n!\n",
		"bare": "interface OpkgTun1\n!\n", // a crash between `interface` and `description`
	} {
		t.Run(name, func(t *testing.T) {
			tunDevices(t, "opkgtun1")
			sent := fakeNdmc(t, map[string]string{"show running-config": tunRC + block})
			if err := ApplyTunTransport(context.Background(), TunTransportSpec{Iface: "OpkgTun1", Address: "172.31.254.2"}); err != nil {
				t.Fatalf("ApplyTunTransport: %v", err)
			}
			if !strings.Contains(strings.Join(*sent, "\n"), "interface OpkgTun1 up") {
				t.Errorf("did not bring the interface up; sent: %v", *sent)
			}
		})
	}
}

func TestApplyTunTransport_DeviceNeverAppears(t *testing.T) {
	tunDevices(t) // no opkgtun1
	fakeNdmc(t, map[string]string{"show running-config": tunRC})
	err := ApplyTunTransport(context.Background(), TunTransportSpec{Iface: "OpkgTun1", Address: "172.31.254.2"})
	if err == nil || !strings.Contains(err.Error(), "opkgtun1") {
		t.Fatalf("err = %v, want one naming the missing kernel device", err)
	}
}

func TestApplyTunTransport_BadInput(t *testing.T) {
	tunDevices(t)
	sent := fakeNdmc(t, map[string]string{})
	for _, spec := range []TunTransportSpec{
		{Iface: "", Address: "172.31.254.2"},
		{Iface: "Wireguard4", Address: "172.31.254.2"},
		{Iface: "opkgtun0", Address: "172.31.254.2"},
		{Iface: "OpkgTun1", Address: ""},
	} {
		if err := ApplyTunTransport(context.Background(), spec); err == nil {
			t.Errorf("ApplyTunTransport(%+v) = nil, want an error", spec)
		}
	}
	if len(*sent) != 0 {
		t.Errorf("sent ndmc commands for invalid input: %v", *sent)
	}
}

func TestTunLinkState(t *testing.T) {
	fakeNdmc(t, map[string]string{"show interface OpkgTun1": tunIfaceShow})
	l, err := TunLinkState(context.Background(), "OpkgTun1")
	if err != nil {
		t.Fatal(err)
	}
	if l.State != "up" || l.Link != "up" || !l.Connected || !l.CarrierUp() || l.Address != "172.31.254.2" || l.MTU != "1280" {
		t.Errorf("TunLinkState = %+v", l)
	}

	// Nobody attached: administratively up, but no carrier.
	noCarrier := strings.NewReplacer("link: up", "link: down", "connected: yes", "connected: no").Replace(tunIfaceShow)
	fakeNdmc(t, map[string]string{"show interface OpkgTun1": noCarrier})
	if l, _ = TunLinkState(context.Background(), "OpkgTun1"); l.CarrierUp() || l.State != "up" {
		t.Errorf("no-carrier interface read as %+v", l)
	}
}

func TestWaitTunCarrierGone(t *testing.T) {
	orig := tunCarrierPoll
	tunCarrierPoll = 5 * time.Millisecond
	t.Cleanup(func() { tunCarrierPoll = orig })

	noCarrier := strings.NewReplacer("link: up", "link: down", "connected: yes", "connected: no").Replace(tunIfaceShow)

	// Already gone: returns at once.
	fakeNdmc(t, map[string]string{"show interface OpkgTun1": noCarrier})
	if !WaitTunCarrierGone(context.Background(), "OpkgTun1", time.Second) {
		t.Error("WaitTunCarrierGone = false with no carrier")
	}

	// Still held: gives up after the limit and says so.
	fakeNdmc(t, map[string]string{"show interface OpkgTun1": tunIfaceShow})
	start := time.Now()
	if WaitTunCarrierGone(context.Background(), "OpkgTun1", 40*time.Millisecond) {
		t.Error("WaitTunCarrierGone = true while xray still holds the device")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("waited %v for a 40ms limit", time.Since(start))
	}

	// A cancelled context stops the wait.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if WaitTunCarrierGone(ctx, "OpkgTun1", time.Hour) {
		t.Error("WaitTunCarrierGone = true on a cancelled context with the device held")
	}
}

func TestTunTransportIntact(t *testing.T) {
	ours := tunRC + "interface OpkgTun1\n    description " + TunIfaceMarker + "\n    up\n!\n"
	down := strings.Replace(tunIfaceShow, "state: up", "state: down", 1)
	cases := []struct {
		name    string
		rc      string
		show    string
		devices []string
		wantOK  bool
		wantWhy string
	}{
		{"healthy", ours, tunIfaceShow, []string{"opkgtun1"}, true, ""},
		{"missing from the config", tunRC, tunIfaceShow, []string{"opkgtun1"}, false, "not in the running config"},
		{"description lost", tunRC + "interface OpkgTun1\n    up\n!\n", tunIfaceShow, []string{"opkgtun1"}, false, "lost our description"},
		{"administratively down", ours, down, []string{"opkgtun1"}, false, "administratively down"},
		{"kernel device gone", ours, tunIfaceShow, nil, false, "opkgtun1 is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tunDevices(t, tc.devices...)
			fakeNdmc(t, map[string]string{"show running-config": tc.rc, "show interface OpkgTun1": tc.show})
			ok, why, err := TunTransportIntact(context.Background(), "OpkgTun1", 0)
			if err != nil || ok != tc.wantOK || !strings.Contains(why, tc.wantWhy) {
				t.Errorf("TunTransportIntact = (%v, %q, %v), want ok=%v why~%q", ok, why, err, tc.wantOK, tc.wantWhy)
			}
		})
	}
}

// The MTU the config wants is compared with the `ip mtu` the interface block
// prints: an interface made by an older version keeps `ip mtu 1280` after the
// default moved to 1500, and that must be noticed. But a block that prints no
// `ip mtu` (a firmware may leave a default out) is NOT drift -- it would
// otherwise be re-applied, and flash-saved, on every tick for ever.
func TestTunTransportIntact_MTU(t *testing.T) {
	tunDevices(t, "opkgtun1")
	block := func(extra string) string {
		return tunRC + "interface OpkgTun1\n    description " + TunIfaceMarker + "\n" + extra + "    up\n!\n"
	}
	cases := []struct {
		name    string
		extra   string
		want    int
		wantOK  bool
		wantWhy string
	}{
		{"matches", "    ip mtu 1500\n", 1500, true, ""},
		{"left at the old default", "    ip mtu 1280\n", 1500, false, "configured MTU is 1280, the config says 1500"},
		{"the other way round", "    ip mtu 1500\n", 1280, false, "configured MTU is 1500, the config says 1280"},
		{"printed none: nothing to compare", "", 1500, true, ""},
		{"not asked to compare", "    ip mtu 1280\n", 0, true, ""},
		{"garbage in the line is no verdict", "    ip mtu abc\n", 1500, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeNdmc(t, map[string]string{"show running-config": block(tc.extra), "show interface OpkgTun1": tunIfaceShow})
			ok, why, err := TunTransportIntact(context.Background(), "OpkgTun1", tc.want)
			if err != nil || ok != tc.wantOK || !strings.Contains(why, tc.wantWhy) {
				t.Errorf("TunTransportIntact(want %d) = (%v, %q, %v), want ok=%v why~%q", tc.want, ok, why, err, tc.wantOK, tc.wantWhy)
			}
			// Present looks at the same thing.
			okP, whyP, _ := TunTransportPresent(context.Background(), "OpkgTun1", tc.want)
			if okP != tc.wantOK || !strings.Contains(whyP, tc.wantWhy) {
				t.Errorf("TunTransportPresent(want %d) = (%v, %q)", tc.want, okP, whyP)
			}
		})
	}
}

func TestBlockMTU(t *testing.T) {
	for in, want := range map[string]int{"ip mtu 1500": 1500, "ip mtu  1280 ": 1280, "ip mtu x": 0, "ip tcp adjust-mss pmtu": 0, "": 0} {
		if got := blockMTU([]string{"description a", in, "up"}); got != want {
			t.Errorf("blockMTU(%q) = %d, want %d", in, got, want)
		}
	}
	if got := blockMTU(nil); got != 0 {
		t.Errorf("blockMTU(nil) = %d", got)
	}
}

// While the gate holds the interface down on purpose, "administratively
// down" is not drift: Present ignores it, Intact does not.
func TestTunTransportPresent_IgnoresAdminState(t *testing.T) {
	tunDevices(t, "opkgtun1")
	down := strings.Replace(tunIfaceShow, "state: up", "state: down", 1)
	rc := tunRC + "interface OpkgTun1\n    description " + TunIfaceMarker + "\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc, "show interface OpkgTun1": down})
	if ok, why, err := TunTransportIntact(context.Background(), "OpkgTun1", 0); err != nil || ok || !strings.Contains(why, "administratively down") {
		t.Errorf("Intact on a down interface = (%v, %q, %v)", ok, why, err)
	}
	if ok, why, err := TunTransportPresent(context.Background(), "OpkgTun1", 0); err != nil || !ok {
		t.Errorf("Present on a down interface = (%v, %q, %v), want present", ok, why, err)
	}
	// Everything else still counts for Present.
	tunDevices(t) // no device
	if ok, why, _ := TunTransportPresent(context.Background(), "OpkgTun1", 0); ok || !strings.Contains(why, "opkgtun1 is missing") {
		t.Errorf("Present without a device = (%v, %q)", ok, why)
	}
}

func TestSetTunAdmin(t *testing.T) {
	sent := fakeNdmc(t, map[string]string{})
	if err := SetTunAdmin(context.Background(), "OpkgTun1", false); err != nil {
		t.Fatal(err)
	}
	if err := SetTunAdmin(context.Background(), "OpkgTun1", true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*sent, "|"); got != "interface OpkgTun1 down|interface OpkgTun1 up" {
		t.Errorf("sent %q", got)
	}
	// Not saved: a runtime state.
	for _, s := range *sent {
		if strings.Contains(s, "save") {
			t.Errorf("the gate's lever saved the configuration: %q", s)
		}
	}
	for _, bad := range []string{"", "Wireguard0", "opkgtun1", "OpkgTun"} {
		if err := SetTunAdmin(context.Background(), bad, true); err == nil {
			t.Errorf("SetTunAdmin(%q) = nil, want an error", bad)
		}
	}
	if len(*sent) != 2 {
		t.Errorf("a bad name reached ndmc: %v", *sent)
	}
}

// Carrier is not part of "intact": it comes and goes with xray, and the
// reconcile loop must not rebuild the interface every time xray restarts.
func TestTunTransportIntact_IgnoresCarrier(t *testing.T) {
	tunDevices(t, "opkgtun1")
	noCarrier := strings.NewReplacer("link: up", "link: down", "connected: yes", "connected: no").Replace(tunIfaceShow)
	rc := tunRC + "interface OpkgTun1\n    description " + TunIfaceMarker + "\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc, "show interface OpkgTun1": noCarrier})
	if ok, why, err := TunTransportIntact(context.Background(), "OpkgTun1", 0); err != nil || !ok {
		t.Errorf("TunTransportIntact without carrier = (%v, %q, %v), want intact", ok, why, err)
	}
}

func TestReadTunCounts(t *testing.T) {
	dir := tunDevices(t, "opkgtun1")
	stats := filepath.Join(dir, "opkgtun1", "statistics")
	if err := os.Mkdir(stats, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"tx_packets": "1500\n", "rx_packets": "1200\n", "tx_bytes": "2097152\n", "rx_bytes": "512\n"} {
		if err := os.WriteFile(filepath.Join(stats, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	c, ok := ReadTunCounts("opkgtun1")
	if !ok || c.TxPackets != 1500 || c.RxPackets != 1200 || c.TxBytes != 2097152 || c.RxBytes != 512 {
		t.Fatalf("ReadTunCounts = %+v, %v", c, ok)
	}
	want := "в туннель 2.0 МБ (1500 пакетов), из туннеля 512 Б (1200)"
	if got := c.Summary(); got != want {
		t.Errorf("Summary = %q, want %q", got, want)
	}

	// A device without counters, or a missing one, is not an error -- just no card.
	if _, ok := ReadTunCounts("opkgtun9"); ok {
		t.Error("ReadTunCounts of a missing device = ok")
	}
	if err := os.Remove(filepath.Join(stats, "rx_bytes")); err != nil {
		t.Fatal(err)
	}
	if _, ok := ReadTunCounts("opkgtun1"); ok {
		t.Error("ReadTunCounts with a counter missing = ok")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[uint64]string{
		0: "0 Б", 1023: "1023 Б", 1024: "1.0 КБ", 1536: "1.5 КБ", 1 << 20: "1.0 МБ", 5 << 30: "5.0 ГБ", 3 << 40: "3.0 ТБ", 3000 << 40: "3000.0 ТБ",
	} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestShowTunTransport(t *testing.T) {
	tunDevices(t, "opkgtun1")
	fakeNdmc(t, map[string]string{"show running-config": tunRC})
	got, err := ShowTunTransport(context.Background(), "")
	if err != nil || !strings.Contains(got, "интерфейс не создан") {
		t.Fatalf("ShowTunTransport with nothing set up = (%q, %v)", got, err)
	}

	rc := tunRC + "interface OpkgTun1\n    description " + TunIfaceMarker + "\n    up\n!\n"
	fakeNdmc(t, map[string]string{"show running-config": rc, "show interface OpkgTun1": tunIfaceShow})
	stats := filepath.Join(sysClassNet, "opkgtun1", "statistics")
	if err := os.Mkdir(stats, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"tx_packets", "rx_packets", "tx_bytes", "rx_bytes"} {
		if err := os.WriteFile(filepath.Join(stats, n), []byte("2048\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err = ShowTunTransport(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"OpkgTun1", "opkgtun1: есть", "состояние: up", "несущая (xray держит устройство): есть", "172.31.254.2", "mtu: 1280", "трафик устройства: в туннель 2.0 КБ (2048 пакетов)"} {
		if !strings.Contains(got, want) {
			t.Errorf("ShowTunTransport output lacks %q:\n%s", want, got)
		}
	}
}

func TestClearTunTransport(t *testing.T) {
	// Nothing of ours -> no-op, and the foreign OpkgTun0 stays.
	sent := fakeNdmc(t, map[string]string{"show running-config": tunRC})
	if err := ClearTunTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, s := range *sent {
		if strings.HasPrefix(s, "no interface") {
			t.Errorf("removed an interface when none was ours: %q", s)
		}
	}

	// Our marked interface -> removed, then saved.
	rc := tunRC + "interface OpkgTun5\n    description " + TunIfaceMarker + "\n    up\n!\n"
	sent = fakeNdmc(t, map[string]string{"show running-config": rc})
	if err := ClearTunTransport(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(*sent, "\n")
	if !strings.Contains(joined, "no interface OpkgTun5\nsystem configuration save") {
		t.Errorf("our interface not removed and saved; sent: %v", *sent)
	}
	if strings.Contains(joined, "no interface OpkgTun0") {
		t.Errorf("removed the foreign OpkgTun0; sent: %v", *sent)
	}
}
