package keenetic

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// realShowPingCheck is `show ping-check` verbatim from a real router
// (2026-09-26), trimmed of repeated ipcache entries: a default profile on
// the LTE modem, the web UI's own WAN profile, and ours in connect mode.
const realShowPingCheck = `
        pingcheck:
              profile: default

            interface:
                     name: UsbLte0
              ignore-fail: no
             successcount: 1358
                failcount: 0
                   status: pass

                  ipcache:
                         host: dzen.ru

                    addresses: 95.163.218.220

        pingcheck:
              profile: _WEBADMIN_GigabitEthernet0/Vlan4

                 host: ozon.ru

      update-interval: 5
            max-fails: 2
                 mode: icmp

            interface:
                     name: GigabitEthernet0/Vlan4
              ignore-fail: no
             successcount: 2702
                failcount: 0
                   status: pass

                  ipcache:
                         host: ozon.ru

                    addresses: 185.73.193.68

        pingcheck:
              profile: kxray

                 host: 1.1.1.1

                 port: 443
      update-interval: 5
            max-fails: 3
                 mode: connect

            interface:
                     name: Proxy0
              ignore-fail: no
             successcount: 6
                failcount: 0
                   status: pass

                  ipcache:
                         host: 1.1.1.1

                    addresses: 1.1.1.1
`

func tlsProfileOutput(status string, fails int) string {
	return strings.Replace(strings.Replace(realShowPingCheck, "mode: connect", "mode: tls", 1),
		"failcount: 0\n                   status: pass\n\n                  ipcache: \n                         host: 1.1.1.1",
		"failcount: "+itoa(fails)+"\n                   status: "+status+"\n\n                  ipcache: \n                         host: 1.1.1.1", 1)
}

func itoa(n int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n))) }

func TestParsePingCheck_RealRouterOutput(t *testing.T) {
	ps := parsePingCheck(realShowPingCheck)
	if len(ps) != 3 {
		t.Fatalf("got %d profiles, want 3: %+v", len(ps), ps)
	}
	wan := ps[1]
	if wan.Name != "_WEBADMIN_GigabitEthernet0/Vlan4" || wan.Host != "ozon.ru" || wan.Mode != "icmp" || wan.MaxFails != 2 {
		t.Errorf("WAN profile = %+v", wan)
	}
	k := ps[2]
	if k.Name != "kxray" || k.Host != "1.1.1.1" || k.Port != 443 || k.Mode != "connect" || k.UpdateInterval != 5 || k.MaxFails != 3 {
		t.Errorf("kxray profile = %+v", k)
	}
	b := k.BoundTo("Proxy0")
	if b == nil || b.Status != "pass" || b.SuccessCount != 6 || b.FailCount != 0 {
		t.Errorf("kxray binding = %+v", b)
	}
	// ipcache's host lines must not overwrite the profile's own host.
	if ps[0].Host != "" {
		t.Errorf("default profile host = %q, want empty (dzen.ru is an ipcache entry)", ps[0].Host)
	}
}

type fakeRouter struct {
	pingCheck string
	fail      map[string]error
	sent      []string
}

func (f *fakeRouter) install(t *testing.T) {
	t.Helper()
	origRun, origLook := ndmcRun, lookNdmc
	ndmcRun = func(_ context.Context, cmd string) (string, error) {
		f.sent = append(f.sent, cmd)
		if err := f.fail[cmd]; err != nil {
			return "", err
		}
		if cmd == "show ping-check" {
			return f.pingCheck, nil
		}
		return "", nil
	}
	lookNdmc = func() error { return nil }
	t.Cleanup(func() { ndmcRun, lookNdmc = origRun, origLook })
}

func TestEnsureHealthCheck_NoOpWhenAlreadyRight(t *testing.T) {
	f := &fakeRouter{pingCheck: tlsProfileOutput("pass", 0)}
	f.install(t)
	changed, err := EnsureProxy0HealthCheck(context.Background(), "Proxy0")
	if err != nil || changed {
		t.Fatalf("changed=%v err=%v, want a silent no-op", changed, err)
	}
	if len(f.sent) != 1 {
		t.Errorf("sent %q, want only the one read -- this runs every reconcile tick", f.sent)
	}
}

// TestEnsureHealthCheck_FixesConnectMode is the exact state the manual
// recon left behind: a connect-mode profile, which passes with xray dead.
func TestEnsureHealthCheck_FixesConnectMode(t *testing.T) {
	f := &fakeRouter{pingCheck: realShowPingCheck}
	f.install(t)
	// The read-back after writing sees the fixed profile.
	origRun := ndmcRun
	reads := 0
	ndmcRun = func(ctx context.Context, cmd string) (string, error) {
		if cmd == "show ping-check" {
			reads++
			if reads > 1 {
				f.sent = append(f.sent, cmd)
				return tlsProfileOutput("pass", 0), nil
			}
		}
		return origRun(ctx, cmd)
	}
	changed, err := EnsureProxy0HealthCheck(context.Background(), "Proxy0")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	joined := strings.Join(f.sent, "\n")
	iMode := strings.Index(joined, "ping-check profile kxray mode tls")
	iBind := strings.Index(joined, "interface Proxy0 ping-check profile kxray")
	if iMode < 0 || iBind < 0 || iMode > iBind {
		t.Errorf("mode tls must be set before the bind:\n%s", joined)
	}
	if !strings.Contains(joined, "system configuration save") {
		t.Error("changes were not saved")
	}
}

// TestEnsureHealthCheck_TLSRejectedLeavesNothingBound: on firmware
// without tls mode the profile must be deleted, never bound in its
// default mode -- an ICMP check through the proxy would drop Proxy0 for
// good.
func TestEnsureHealthCheck_TLSRejectedLeavesNothingBound(t *testing.T) {
	f := &fakeRouter{fail: map[string]error{"ping-check profile kxray mode tls": errors.New("unknown mode")}}
	f.install(t)
	if _, err := EnsureProxy0HealthCheck(context.Background(), "Proxy0"); err == nil {
		t.Fatal("want an error when tls is rejected")
	}
	joined := strings.Join(f.sent, "\n")
	if strings.Contains(joined, "interface Proxy0 ping-check profile kxray") {
		t.Errorf("profile was bound despite tls being rejected:\n%s", joined)
	}
	if !strings.Contains(joined, "no ping-check profile kxray") {
		t.Errorf("half-built profile was not deleted:\n%s", joined)
	}
}

func TestRemoveHealthCheck_UnbindsThenDeletes(t *testing.T) {
	f := &fakeRouter{pingCheck: realShowPingCheck}
	f.install(t)
	if err := RemoveHealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(f.sent, "\n")
	iUnbind := strings.Index(joined, "interface Proxy0 no ping-check profile kxray")
	iDelete := strings.Index(joined, "\nno ping-check profile kxray")
	if iUnbind < 0 || iDelete < 0 || iUnbind > iDelete {
		t.Errorf("want unbind before delete:\n%s", joined)
	}
}

func TestProxyIPLayer_RealRouterOutput(t *testing.T) {
	out := `
          summary:
                layer:
                     conf: running
                     link: running
                     ipv4: pending
                     ipv6: pending
                     ctrl: running
`
	fakeNdmc(t, map[string]string{"show interface Proxy0": out})
	got, err := ProxyIPLayer(context.Background(), "Proxy0")
	if err != nil || got != "pending" {
		t.Errorf("ProxyIPLayer = %q, %v; want pending", got, err)
	}
}
