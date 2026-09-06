package keenetic

import (
	"context"
	"strings"
	"testing"
)

func TestObjectGroupIPs(t *testing.T) {
	// Modeled loosely on `show object-group fqdn` output; the parser is
	// format-tolerant (any bare dotted-quad that isn't excluded/*-count).
	fakeNdmc(t, map[string]string{
		"show object-group fqdn keenetic-xray-media": "" +
			"            group: \n" +
			"       group-name: keenetic-xray-media\n" +
			"     ipv4-addresses-count: 3\n" +
			"            entry: \n" +
			"                   142.250.185.78\n" +
			"                   142.250.185.110/32\n" +
			"    excluded-ipv4: 10.0.0.1\n",
	})
	got := objectGroupIPs(context.Background(), "keenetic-xray-media")
	want := map[string]bool{"142.250.185.78": true, "142.250.185.110": true}
	if len(got) != 2 {
		t.Fatalf("objectGroupIPs = %v, want the two entry IPs (not the excluded / count)", got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Errorf("unexpected IP %q", ip)
		}
	}
}

func TestFlushConntrackForGroups(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })
	conntrackPresent = func() bool { return true }
	var ran [][]string
	conntrackRun = func(_ context.Context, args ...string) error { ran = append(ran, args); return nil }

	// Group has resolved IPs -> targeted -D per IP.
	fakeNdmc(t, map[string]string{
		"show object-group fqdn g1": "            entry: \n   1.1.1.1\n   2.2.2.2\n",
	})
	mode, err := FlushConntrackForGroups(context.Background(), []string{"g1"})
	if err != nil || !strings.Contains(mode, "точечно") {
		t.Fatalf("targeted: mode=%q err=%v", mode, err)
	}
	dels := 0
	for _, a := range ran {
		if len(a) == 3 && a[0] == "-D" && a[1] == "-d" {
			dels++
		}
	}
	if dels != 2 {
		t.Errorf("targeted -D count = %d, want 2; calls=%v", dels, ran)
	}

	// Nothing resolved -> full flush.
	ran = nil
	fakeNdmc(t, map[string]string{"show object-group fqdn g2": "            entry: \n"})
	mode, _ = FlushConntrackForGroups(context.Background(), []string{"g2"})
	if mode != "весь conntrack" || len(ran) != 1 || ran[0][0] != "-F" {
		t.Errorf("fallback: mode=%q ran=%v", mode, ran)
	}
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
