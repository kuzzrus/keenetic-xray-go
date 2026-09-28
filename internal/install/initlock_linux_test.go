//go:build linux

package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// procStart is /proc/<pid>/stat field 22 -- what the init script's lock
// records next to the PID.
func procStart(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ") ")+2:])
	return f[19]
}

// bystander is a live process that has nothing to do with the lock.
func bystander(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd.Process.Pid
}

// holdLock leaves a lock behind the way a start/stop that died mid-way
// would: pidLine is what its pid file says ("" for none written yet).
func holdLock(t *testing.T, e initEnv, pidLine string) {
	t.Helper()
	dir := filepath.Join(e.dir, "init.lock")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if pidLine != "" {
		if err := os.WriteFile(filepath.Join(dir, "pid"), []byte(pidLine+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func timedStart(t *testing.T, e initEnv) (string, int, time.Duration) {
	t.Helper()
	begin := time.Now()
	out, rc := e.run(t, "start")
	return out, rc, time.Since(begin)
}

// TestInitLock_StaleHolders: each way a lock outlives its holder is
// taken over well inside LOCK_WAIT, and the daemon starts.
func TestInitLock_StaleHolders(t *testing.T) {
	cases := []struct {
		name    string
		pidLine func(t *testing.T) string
		within  time.Duration
	}{
		{"holder's PID now another process", func(t *testing.T) string {
			return strconv.Itoa(bystander(t)) + " 1" // live PID, wrong start time
		}, 5 * time.Second},
		{"holder died before writing its PID", func(*testing.T) string { return "" }, 12 * time.Second},
		{"old-format lock, holder gone", func(t *testing.T) string {
			cmd := exec.Command("true")
			if err := cmd.Run(); err != nil {
				t.Fatal(err)
			}
			return strconv.Itoa(cmd.Process.Pid) // exited, no start time recorded
		}, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInitEnv(t, fakeDaemon)
			e.env = append(e.env, "KEENETIC_XRAY_LOCK_WAIT=30")
			holdLock(t, e, tc.pidLine(t))
			out, rc, took := timedStart(t, e)
			if rc != 0 {
				t.Fatalf("start = %d:\n%s", rc, out)
			}
			if took > tc.within {
				t.Errorf("start took %v, want the stale lock taken over within %v", took, tc.within)
			}
			if _, rc := e.run(t, "status"); rc != 0 {
				t.Error("daemon not running after the lock was taken over")
			}
		})
	}
}

// TestInitLock_LiveHolderBlocks: a lock whose holder is alive -- the
// very process that wrote it -- is waited on, and given up on after
// LOCK_WAIT, not taken over.
func TestInitLock_LiveHolderBlocks(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	e.env = append(e.env, "KEENETIC_XRAY_LOCK_WAIT=3")
	pid := bystander(t)
	holdLock(t, e, strconv.Itoa(pid)+" "+procStart(t, pid))
	out, rc, took := timedStart(t, e)
	if rc == 0 {
		t.Fatalf("start went ahead under a live holder's lock:\n%s", out)
	}
	if !strings.Contains(out, "giving up") || took < 2*time.Second {
		t.Errorf("rc %d after %v:\n%s", rc, took, out)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "init.lock", "pid")); err != nil {
		t.Error("the live holder's lock was removed")
	}
}

// lockSpyDaemon is fakeDaemon that first copies the init lock's pid file
// -- start holds the lock while it launches the daemon -- to
// $KX_LOCK_SEEN.
const lockSpyDaemon = `#!/bin/sh
if [ "$1" = daemon ]; then
	cp "$KEENETIC_XRAY_INIT_LOCK/pid" "$KX_LOCK_SEEN" 2>/dev/null
	read -r stat < /proc/$$/stat
	set -- ${stat##*) }
	shift 19
	printf '%s\n%s\n' "$$" "$1" > "$KEENETIC_XRAY_PID_FILE"
	trap 'rm -f "$KEENETIC_XRAY_PID_FILE"; exit 0' TERM
	while :; do sleep 1; done
fi
sleep 30
`

// TestInitLock_RecordsPIDAndStart: the lock a start holds carries the
// holder's start time next to its PID -- what makes a reused PID
// detectable at all.
func TestInitLock_RecordsPIDAndStart(t *testing.T) {
	e := newInitEnv(t, lockSpyDaemon)
	seen := filepath.Join(e.dir, "lock-seen")
	e.env = append(e.env, "KX_LOCK_SEEN="+seen)
	if out, rc := e.run(t, "start"); rc != 0 {
		t.Fatalf("start = %d:\n%s", rc, out)
	}
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("the daemon saw no lock: %v", err)
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		t.Fatalf("lock pid file = %q, want \"<pid> <start time>\"", b)
	}
	for _, v := range f {
		if _, err := strconv.Atoi(v); err != nil {
			t.Errorf("lock pid file = %q: %q is not a number", b, v)
		}
	}
}
