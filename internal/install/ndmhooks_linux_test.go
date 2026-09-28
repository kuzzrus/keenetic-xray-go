//go:build linux

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestNetfilterHook_SignalsOnOurTables runs the real
// packaging/ndm/netfilter.d hook the way ndm does -- $type and $table in
// the environment -- against a stand-in daemon that records SIGUSR1. nat
// is where adaptive routing's REDIRECT lives; the hook used to skip it,
// so a nat rebuild (a DHCP renew, a policy edit) left that traffic going
// direct until the daemon's 2-minute poll.
func TestNetfilterHook_SignalsOnOurTables(t *testing.T) {
	hook, err := filepath.Abs(filepath.Join("..", "..", "packaging", "ndm", "netfilter.d", "50-keenetic-xray.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		typ, table string
		signalled  bool
	}{
		{"iptables", "nat", true},
		{"iptables", "mangle", true},
		{"iptables", "filter", true},
		{"iptables", "raw", false},
		{"ip6tables", "nat", false}, // our rules are IPv4 only
	}
	for _, tc := range cases {
		t.Run(tc.typ+"/"+tc.table, func(t *testing.T) {
			dir := t.TempDir()
			got := filepath.Join(dir, "usr1")
			daemon := exec.Command("sh", "-c", `trap 'echo usr1 >> "$0"' USR1; while :; do sleep 1; done`, got)
			if err := daemon.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = daemon.Process.Kill(); _ = daemon.Wait() })
			pidFile := filepath.Join(dir, "keenetic-xray.pid")
			if err := os.WriteFile(pidFile, []byte(strconv.Itoa(daemon.Process.Pid)+"\n12345\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond) // let the trap be installed

			sh := shell()
			cmd := exec.Command(sh[0], append(sh[1:], hook)...)
			cmd.Env = append(os.Environ(), "type="+tc.typ, "table="+tc.table, "KEENETIC_XRAY_PID_FILE="+pidFile)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("hook: %v\n%s", err, out)
			}

			deadline := time.Now().Add(3 * time.Second)
			for {
				_, statErr := os.Stat(got)
				signalled := statErr == nil
				if signalled == tc.signalled && (signalled || time.Now().After(deadline)) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("daemon signalled = %v, want %v", signalled, tc.signalled)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}
