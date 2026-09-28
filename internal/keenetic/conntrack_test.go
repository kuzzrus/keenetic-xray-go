package keenetic

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// realShowObjectGroupFQDN starts with `show object-group fqdn` verbatim
// from a real router (2026-09-28, KeeneticOS 5.x) -- the akamai group,
// cut after its first entry. The ipv6 block and the other two groups are
// built on the same pattern; their exact firmware format is unseen.
const realShowObjectGroupFQDN = `
            group: 
               group-name: akamai
                  enabled: yes
     ipv4-addresses-count: 340
     ipv6-addresses-count: 749
               fqdn-count: 231

                    entry: 
                      fqdn: a132.dscb.akamai.net
                      type: runtime
                 deadline4: 165
                 deadline6: 10
             fail-counter4: 0
             fail-counter6: 0
             last-external: 52
         last-list-changed: 52
                    parent: akamai.net

                      ipv4: 
                      address: 23.73.4.217
                          ttl: 20
                 last-updated: 568

                      ipv4: 
                      address: 23.73.4.225
                          ttl: 20
                 last-updated: 568

                      ipv4: 
                      address: 23.201.43.136
                          ttl: 20
                 last-updated: 1392

                      ipv4: 
                      address: 23.201.43.171
                          ttl: 20
                 last-updated: 1392

                      ipv6: 
                      address: 2a02:26f0:3500:14::17d0:9e45
                          ttl: 20
                 last-updated: 568

                    entry: 
                      fqdn: a133.dscb.akamai.net
                      type: runtime
                    parent: akamai.net

                      ipv4: 
                      address: 23.73.4.217
                          ttl: 20
                 last-updated: 568

            group: 
               group-name: keenetic-xray-media
                  enabled: yes
     ipv4-addresses-count: 1
               fqdn-count: 1

                    entry: 
                      fqdn: netflix.com
                      type: config

                      ipv4: 
                      address: 54.155.178.5
                          ttl: 60
                 last-updated: 12

            group: 
               group-name: keenetic-xray-lan
                  enabled: yes

                    entry: 
                      fqdn: 10.20.0.0/16
                      type: config
`

func TestParseObjectGroupAddrs(t *testing.T) {
	cases := []struct {
		name   string
		want   map[string]bool
		addrs  []string
		subnet bool
	}{
		{"one group, v4+v6, duplicate once", map[string]bool{"akamai": true},
			[]string{"23.73.4.217", "23.73.4.225", "23.201.43.136", "23.201.43.171", "2a02:26f0:3500:14::17d0:9e45"}, false},
		{"scoped to its own group", map[string]bool{"keenetic-xray-media": true}, []string{"54.155.178.5"}, false},
		{"subnet entry", map[string]bool{"keenetic-xray-lan": true}, nil, true},
		{"group not on the router", map[string]bool{"keenetic-xray-gone": true}, nil, false},
	}
	for _, tc := range cases {
		addrs, subnet := parseObjectGroupAddrs(realShowObjectGroupFQDN, tc.want)
		if strings.Join(addrs, ",") != strings.Join(tc.addrs, ",") || subnet != tc.subnet {
			t.Errorf("%s: got %v subnet=%v, want %v subnet=%v", tc.name, addrs, subnet, tc.addrs, tc.subnet)
		}
	}
}

// TestFlushConntrackForGroups: one `show object-group fqdn` for all
// groups -- the per-group form doesn't exist on the firmware -- then a
// targeted delete per address (IPv6 with -f ipv6), or one full flush when
// the set can't be used.
func TestFlushConntrackForGroups(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })
	conntrackPresent = func() bool { return true }
	var ran []string
	conntrackRun = func(_ context.Context, args ...string) error { ran = append(ran, strings.Join(args, " ")); return nil }

	sent := fakeNdmc(t, map[string]string{"show object-group fqdn": realShowObjectGroupFQDN})
	mode, err := FlushConntrackForGroups(context.Background(), []string{"akamai", "keenetic-xray-media"})
	if err != nil || mode != "точечно (6 IP)" {
		t.Fatalf("targeted: mode=%q err=%v ran=%v", mode, err, ran)
	}
	if strings.Join(*sent, "|") != "show object-group fqdn" {
		t.Errorf("ndmc calls = %q, want the one no-argument read", *sent)
	}
	for _, want := range []string{"-D -d 23.73.4.217", "-D -d 54.155.178.5", "-D -f ipv6 -d 2a02:26f0:3500:14::17d0:9e45"} {
		if !contains(ran, want) {
			t.Errorf("missing %q in %v", want, ran)
		}
	}

	for _, tc := range []struct {
		name   string
		groups []string
	}{
		{"nothing resolved", []string{"keenetic-xray-gone"}},
		{"subnet among the entries", []string{"keenetic-xray-media", "keenetic-xray-lan"}},
	} {
		ran = nil
		mode, _ = FlushConntrackForGroups(context.Background(), tc.groups)
		if mode != "весь conntrack" || strings.Join(ran, "|") != "-F" {
			t.Errorf("%s: mode=%q ran=%v, want one full flush", tc.name, mode, ran)
		}
	}

	ran = nil
	ndmcRun = func(context.Context, string) (string, error) { return "", fmt.Errorf("exit status 1") }
	mode, _ = FlushConntrackForGroups(context.Background(), []string{"akamai"})
	if mode != "весь conntrack" || strings.Join(ran, "|") != "-F" {
		t.Errorf("unreadable groups: mode=%q ran=%v, want one full flush", mode, ran)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestFlushConntrack(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })

	// Absent -> no-op, no error, no exec.
	conntrackPresent = func() bool { return false }
	var ran [][]string
	conntrackRun = func(_ context.Context, args ...string) error { ran = append(ran, args); return nil }
	if err := FlushConntrack(context.Background()); err != nil {
		t.Fatalf("FlushConntrack (absent) = %v, want nil", err)
	}
	if len(ran) != 0 {
		t.Errorf("ran %v with conntrack absent, want nothing", ran)
	}

	// Present -> runs `conntrack -F`.
	conntrackPresent = func() bool { return true }
	if err := FlushConntrack(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || len(ran[0]) != 1 || ran[0][0] != "-F" {
		t.Errorf("ran %v, want a single [-F]", ran)
	}
}

func TestDeleteConntrackFlow(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })
	conntrackPresent = func() bool { return true }
	var ran []string
	conntrackRun = func(_ context.Context, args ...string) error {
		ran = args
		return nil
	}

	DeleteConntrackFlow(context.Background(), "tcp", "192.168.1.5", "1.2.3.4", 40000, 443)
	want := []string{"-D", "-p", "tcp", "-s", "192.168.1.5", "-d", "1.2.3.4",
		"--sport", "40000", "--dport", "443"}
	if strings.Join(ran, " ") != strings.Join(want, " ") {
		t.Errorf("ran = %v, want %v", ran, want)
	}
}

func TestDeleteConntrackFlow_NotInstalledIsNoop(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })
	conntrackPresent = func() bool { return false }
	called := false
	conntrackRun = func(_ context.Context, args ...string) error { called = true; return nil }

	DeleteConntrackFlow(context.Background(), "tcp", "192.168.1.5", "1.2.3.4", 40000, 443)
	if called {
		t.Error("should not shell out when conntrack isn't installed")
	}
}

func TestEnsureConntrackTool_AlreadyPresentSkipsOpkg(t *testing.T) {
	origPresent, origOpkg := conntrackPresent, opkgInstallConntrack
	t.Cleanup(func() { conntrackPresent, opkgInstallConntrack = origPresent, origOpkg })
	conntrackPresent = func() bool { return true }
	called := false
	opkgInstallConntrack = func(context.Context) error { called = true; return nil }

	if err := EnsureConntrackTool(context.Background()); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("opkg install should not run when conntrack is already present")
	}
}

func TestEnsureConntrackTool_InstallsWhenAbsent(t *testing.T) {
	origPresent, origOpkg := conntrackPresent, opkgInstallConntrack
	t.Cleanup(func() { conntrackPresent, opkgInstallConntrack = origPresent, origOpkg })
	present := false
	conntrackPresent = func() bool { return present }
	opkgInstallConntrack = func(context.Context) error { present = true; return nil }

	if err := EnsureConntrackTool(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Error("expected conntrack to be installed")
	}
}

func TestEnsureConntrackTool_OpkgFailure(t *testing.T) {
	origPresent, origOpkg := conntrackPresent, opkgInstallConntrack
	t.Cleanup(func() { conntrackPresent, opkgInstallConntrack = origPresent, origOpkg })
	conntrackPresent = func() bool { return false }
	opkgInstallConntrack = func(context.Context) error { return fmt.Errorf("opkg: no feed") }

	if err := EnsureConntrackTool(context.Background()); err == nil {
		t.Fatal("want an error when opkg install fails")
	}
}
