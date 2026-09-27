package keenetic

import (
	"context"
	"errors"
	"strconv"
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
		"failcount: "+strconv.Itoa(fails)+"\n                   status: "+status+"\n\n                  ipcache: \n                         host: 1.1.1.1", 1)
}

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
	removed, err := RemoveHealthCheck(context.Background())
	if err != nil || !removed {
		t.Fatalf("removed=%v err=%v", removed, err)
	}
	iUnbind, iDelete := indexOf(f.sent, "interface Proxy0 no ping-check profile"), indexOf(f.sent, "no ping-check profile kxray")
	if iUnbind < 0 || iDelete < 0 || iUnbind > iDelete {
		t.Errorf("want unbind before delete: %q", f.sent)
	}
	// The router rejects the profile name in the unbind ("argument parse
	// error", confirmed 2026-09-27) -- it must never come back.
	if indexOf(f.sent, "interface Proxy0 no ping-check profile kxray") >= 0 {
		t.Errorf("unbind carries the profile name, which the router rejects: %q", f.sent)
	}
}

// TestRemoveHealthCheck_DeletesEvenIfUnbindFails: the delete works on a
// still-bound profile (confirmed on a real router), so a failed unbind
// must not stop it.
func TestRemoveHealthCheck_DeletesEvenIfUnbindFails(t *testing.T) {
	f := &fakeRouter{
		pingCheck: realShowPingCheck,
		fail:      map[string]error{"interface Proxy0 no ping-check profile": errors.New("argument parse error")},
	}
	f.install(t)
	if _, err := RemoveHealthCheck(context.Background()); err != nil {
		t.Fatalf("a failed unbind aborted the removal: %v", err)
	}
	if indexOf(f.sent, "no ping-check profile kxray") < 0 {
		t.Errorf("profile never deleted: %q", f.sent)
	}
}

// TestEnsureHealthCheck_LeftoverBindingIsNotChurn: a stale binding on a
// former interface that can't be removed must not make every reconcile
// tick rewrite the profile and save the config to flash.
func TestEnsureHealthCheck_LeftoverBindingIsNotChurn(t *testing.T) {
	two := strings.Replace(tlsProfileOutput("pass", 0), "name: Proxy0",
		"name: Proxy1\n\n            interface:\n                     name: Proxy0", 1)
	if ps := parsePingCheck(two); len(ps) != 3 || len(ps[2].Bindings) != 2 {
		t.Fatalf("fixture should bind kxray to two interfaces, parsed %+v", ps)
	}
	f := &fakeRouter{pingCheck: two}
	f.install(t)
	changed, err := EnsureProxy0HealthCheck(context.Background(), "Proxy0")
	if err != nil || changed || len(f.sent) != 1 {
		t.Errorf("changed=%v err=%v sent=%q, want a read-only no-op", changed, err, f.sent)
	}
}

func indexOf(cmds []string, want string) int {
	for i, c := range cmds {
		if c == want {
			return i
		}
	}
	return -1
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

// TestEnsureHealthCheck_MovesBindingToNewInterface: after `proxy0 set
// --interface=Proxy1` the check must follow the interface, not stay on the
// old one as well.
func TestEnsureHealthCheck_MovesBindingToNewInterface(t *testing.T) {
	onProxy0 := tlsProfileOutput("pass", 0)
	onProxy1 := strings.Replace(onProxy0, "name: Proxy0", "name: Proxy1", 1)
	f := &fakeRouter{pingCheck: onProxy0}
	f.install(t)
	origRun := ndmcRun
	reads := 0
	ndmcRun = func(ctx context.Context, cmd string) (string, error) {
		if cmd == "show ping-check" {
			reads++
			if reads > 1 {
				f.sent = append(f.sent, cmd)
				return onProxy1, nil
			}
		}
		return origRun(ctx, cmd)
	}

	changed, err := EnsureProxy0HealthCheck(context.Background(), "Proxy1")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	joined := strings.Join(f.sent, "\n")
	for _, want := range []string{
		"interface Proxy0 no ping-check profile",
		"interface Proxy1 ping-check profile kxray",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q:\n%s", want, joined)
		}
	}
}

// TestEnsureHealthCheck_BadReadBackRemovesIt: if the router does not show
// the settings just written, the check must not be left bound in whatever
// state it is actually in.
func TestEnsureHealthCheck_BadReadBackRemovesIt(t *testing.T) {
	f := &fakeRouter{pingCheck: ""} // no profile yet, and the read-back never shows one either
	f.install(t)
	if _, err := EnsureProxy0HealthCheck(context.Background(), "Proxy0"); err == nil {
		t.Fatal("want an error when the read-back does not show the profile")
	}
	if !strings.Contains(strings.Join(f.sent, "\n"), "no ping-check profile kxray") {
		t.Errorf("profile not removed after a failed read-back:\n%s", strings.Join(f.sent, "\n"))
	}
}
