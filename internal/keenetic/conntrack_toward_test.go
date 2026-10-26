package keenetic

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real-shaped /proc/net/nf_conntrack lines (KeeneticOS), trimmed.
const towardTable = `ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.50 dst=31.13.72.9 sport=51234 dport=443 packets=12 bytes=3100 src=31.13.72.9 dst=192.168.1.50 sport=443 dport=51234 packets=10 bytes=9000 [ASSURED] mark=0 use=2
ipv4     2 tcp      6 118 SYN_SENT src=192.168.1.51 dst=31.13.73.4 sport=40000 dport=80 packets=3 bytes=180 [UNREPLIED] src=31.13.73.4 dst=192.168.1.51 sport=80 dport=40000 packets=0 bytes=0 mark=0 use=2
ipv4     2 udp      17 20 src=192.168.1.50 dst=31.13.72.200 sport=50000 dport=443 packets=5 bytes=6000 [UNREPLIED] src=31.13.72.200 dst=192.168.1.50 sport=443 dport=50000 packets=0 bytes=0 mark=0 use=2
ipv4     2 tcp      6 431000 ESTABLISHED src=192.168.1.50 dst=8.8.8.8 sport=51235 dport=443 packets=9 bytes=2000 src=8.8.8.8 dst=192.168.1.50 sport=443 dport=51235 packets=8 bytes=4000 [ASSURED] mark=0 use=2
ipv4     2 icmp     1 29 src=192.168.1.50 dst=31.13.72.9 type=8 code=0 id=1 packets=1 bytes=84 src=31.13.72.9 dst=192.168.1.50 type=0 code=0 id=1 packets=1 bytes=84 mark=0 use=1
garbage line
`

func stubConntrack(t *testing.T, table string) *[]string {
	t.Helper()
	origRun, origPresent, origPath := conntrackRun, conntrackPresent, conntrackProcPath
	t.Cleanup(func() { conntrackRun, conntrackPresent, conntrackProcPath = origRun, origPresent, origPath })
	conntrackPresent = func() bool { return true }
	var ran []string
	conntrackRun = func(_ context.Context, args ...string) error {
		ran = append(ran, strings.Join(args, " "))
		return nil
	}
	conntrackProcPath = filepath.Join(t.TempDir(), "nf_conntrack")
	if err := os.WriteFile(conntrackProcPath, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	return &ran
}

func TestDeleteConntrackToward_Address(t *testing.T) {
	ran := stubConntrack(t, towardTable)
	DeleteConntrackToward(context.Background(), "31.13.72.9")
	DeleteConntrackToward(context.Background(), "31.13.72.200/32")
	want := []string{"-D -d 31.13.72.9", "-D -d 31.13.72.200"}
	if strings.Join(*ran, "|") != strings.Join(want, "|") {
		t.Errorf("conntrack calls = %q, want %q", *ran, want)
	}
}

func TestDeleteConntrackToward_SubnetDeletesEachFlowIntoIt(t *testing.T) {
	ran := stubConntrack(t, towardTable)
	DeleteConntrackToward(context.Background(), "31.13.72.0/24")
	want := []string{
		"-D -p tcp -s 192.168.1.50 -d 31.13.72.9 --sport 51234 --dport 443",
		"-D -p udp -s 192.168.1.50 -d 31.13.72.200 --sport 50000 --dport 443",
	}
	if strings.Join(*ran, "|") != strings.Join(want, "|") {
		t.Errorf("conntrack calls =\n%q\nwant\n%q\n(the /24 holds two flows; 31.13.73.4, 8.8.8.8 and the icmp entry are outside or not tcp/udp)", *ran, want)
	}
}

func TestDeleteConntrackToward_SubnetWithoutATableIsQuiet(t *testing.T) {
	ran := stubConntrack(t, "")
	conntrackProcPath = filepath.Join(t.TempDir(), "absent")
	DeleteConntrackToward(context.Background(), "10.0.0.0/8")
	if len(*ran) != 0 {
		t.Errorf("conntrack calls = %q, want none", *ran)
	}
}

func TestDeleteConntrackToward_IgnoresJunkTargets(t *testing.T) {
	ran := stubConntrack(t, towardTable)
	for _, target := range []string{"", "garbage", "2001:db8::1", "1.2.3.4/99", "::/0"} {
		DeleteConntrackToward(context.Background(), target)
	}
	if len(*ran) != 0 {
		t.Errorf("conntrack calls = %q, want none for unusable targets", *ran)
	}
}

func TestDeleteConntrackToward_NotInstalledIsNoop(t *testing.T) {
	ran := stubConntrack(t, towardTable)
	conntrackPresent = func() bool { return false }
	DeleteConntrackToward(context.Background(), "31.13.72.9")
	DeleteConntrackToward(context.Background(), "31.13.72.0/24")
	if len(*ran) != 0 {
		t.Errorf("conntrack calls = %q, want none without the tool", *ran)
	}
}

func TestDeleteConntrackToward_SubnetCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxTowardDeletes+50; i++ {
		b.WriteString("ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.5 dst=44.0.0.1 sport=")
		b.WriteString(strings.Repeat("1", 1+i%4))
		b.WriteString(" dport=443 packets=1 bytes=1\n")
	}
	ran := stubConntrack(t, b.String())
	DeleteConntrackToward(context.Background(), "44.0.0.0/8")
	if len(*ran) != maxTowardDeletes {
		t.Errorf("conntrack calls = %d, want the cap of %d", len(*ran), maxTowardDeletes)
	}
}

func TestDeleteConntrackToward_StopsOnCancelledContext(t *testing.T) {
	ran := stubConntrack(t, towardTable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	DeleteConntrackToward(ctx, "31.13.72.0/24")
	if len(*ran) != 0 {
		t.Errorf("conntrack calls = %q, want none once the context is done", *ran)
	}
}

func TestConntrackOriginalTuple(t *testing.T) {
	line := strings.Split(towardTable, "\n")[0]
	proto, src, dst, sport, dport, ok := conntrackOriginalTuple(line)
	if !ok || proto != "tcp" || src != "192.168.1.50" || dst != "31.13.72.9" || sport != "51234" || dport != "443" {
		t.Errorf("tuple = %s %s %s %s %s %v; want the ORIGINAL direction, not the reply's repeated fields", proto, src, dst, sport, dport, ok)
	}
	if _, _, _, _, _, ok := conntrackOriginalTuple("ipv4 2 icmp 1 29 src=1.1.1.1 dst=2.2.2.2 type=8"); ok {
		t.Error("an icmp line must not yield a tcp/udp tuple")
	}
}
