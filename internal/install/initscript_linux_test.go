//go:build linux

package install

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These run the real packaging/init.d/S99keenetic-xray against a
// stand-in daemon, reproducing the 2026-09-27 external review's bench:
// the script used to be built on Entware's rc.func, which finds "the
// daemon" with `pidof keenetic-xray` and stops it with `killall
// keenetic-xray` -- both matching any process of that name.

// fakeDaemon stands in for the real binary. Its file name is what makes
// the kernel report it as `keenetic-xray` in /proc/<pid>/comm, exactly
// like the real one. `daemon` writes the pidfile the way
// cmd/keenetic-xray's writeDaemonPIDFile does (PID, then /proc stat
// field 22) and lingers until SIGTERM; any other invocation is a CLI
// command that just lingers.
const fakeDaemon = `#!/bin/sh
if [ "$1" = daemon ]; then
	read -r stat < /proc/$$/stat
	set -- ${stat##*) }
	shift 19
	printf '%s\n%s\n' "$$" "$1" > "$KEENETIC_XRAY_PID_FILE"
	trap 'rm -f "$KEENETIC_XRAY_PID_FILE"; exit 0' TERM
	while :; do sleep 1; done
fi
sleep 30
`

type initEnv struct {
	dir, bin, pidFile, logDir string
	env                       []string
}

func newInitEnv(t *testing.T, daemonBody string) initEnv {
	t.Helper()
	dir := t.TempDir()
	e := initEnv{
		dir:     dir,
		bin:     filepath.Join(dir, "keenetic-xray"),
		pidFile: filepath.Join(dir, "run", "keenetic-xray.pid"),
		logDir:  filepath.Join(dir, "log"),
	}
	if err := os.WriteFile(e.bin, []byte(daemonBody), 0o755); err != nil {
		t.Fatal(err)
	}
	e.env = append(os.Environ(),
		"KEENETIC_XRAY_BIN="+e.bin,
		"KEENETIC_XRAY_PID_FILE="+e.pidFile,
		"KEENETIC_XRAY_LOG_DIR="+e.logDir,
		"KEENETIC_XRAY_INIT_LOCK="+filepath.Join(dir, "init.lock"),
		"KEENETIC_XRAY_START_WAIT=5",
	)
	t.Cleanup(func() { e.run(t, "kill") })
	return e
}

// shell is the interpreter the script runs under: the system sh by
// default, or e.g. `busybox sh` -- the router's own -- via KX_TEST_SHELL.
func shell() []string {
	if s := os.Getenv("KX_TEST_SHELL"); s != "" {
		return strings.Fields(s)
	}
	return []string{"sh"}
}

func (e initEnv) run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	sh := shell()
	argv := append(append(sh[1:], filepath.Join("..", "..", "packaging", "init.d", "S99keenetic-xray")), args...)
	cmd := exec.Command(sh[0], argv...)
	cmd.Env = e.env
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exitErr):
		return string(out), exitErr.ExitCode()
	default:
		t.Fatalf("running the init script: %v", err)
		return "", -1
	}
}

// cli starts a stand-in CLI command: a live process named
// keenetic-xray that is not the daemon -- the watchdog hook, a
// self-rollback, `keenetic-xray logs`.
func (e initEnv) cli(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(e.bin)
	cmd.Env = e.env
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func (e initEnv) daemonPID(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(e.pidFile)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0])
	return pid
}

// TestInitScript_Status is BOOT-02: rc.func has no `status`, so the
// watchdog's check failed on every tick, healthy daemon or not.
func TestInitScript_Status(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	if out, code := e.run(t, "status"); code != 1 {
		t.Fatalf("status with no daemon: exit %d (%s), want 1", code, out)
	}
	if out, code := e.run(t, "start"); code != 0 {
		t.Fatalf("start: exit %d: %s", code, out)
	}
	for _, action := range []string{"status", "check"} {
		if out, code := e.run(t, action); code != 0 {
			t.Errorf("%s with the daemon running: exit %d (%s), want 0", action, code, out)
		}
	}
	if out, code := e.run(t, "stop"); code != 0 {
		t.Fatalf("stop: exit %d: %s", code, out)
	}
	if out, code := e.run(t, "status"); code != 1 {
		t.Errorf("status after stop: exit %d (%s), want 1", code, out)
	}
	if _, err := os.Stat(e.pidFile); !os.IsNotExist(err) {
		t.Error("the daemon's pidfile outlived it")
	}
}

// TestInitScript_StartsDespiteAnotherKeeneticXrayProcess is BOOT-01:
// the watchdog hook is itself a process named keenetic-xray, and rc.func
// took it for the daemon -- "already running", nothing started, ever.
func TestInitScript_StartsDespiteAnotherKeeneticXrayProcess(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	e.cli(t)
	if out, code := e.run(t, "start"); code != 0 || strings.Contains(out, "already running") {
		t.Fatalf("start next to a keenetic-xray CLI process: exit %d: %s", code, out)
	}
	if pid := e.daemonPID(t); pid == 0 || !alive(pid) {
		t.Fatal("no daemon is running after start")
	}
}

// TestInitScript_StopLeavesOtherKeeneticXrayProcessesAlone is N2:
// rc.func's `killall keenetic-xray` also killed whatever CLI process
// happened to be alive -- a rollback halfway through opkg included.
func TestInitScript_StopLeavesOtherKeeneticXrayProcessesAlone(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	if out, code := e.run(t, "start"); code != 0 {
		t.Fatalf("start: exit %d: %s", code, out)
	}
	daemon := e.daemonPID(t)
	cli := e.cli(t)
	if out, code := e.run(t, "stop"); code != 0 {
		t.Fatalf("stop: exit %d: %s", code, out)
	}
	if alive(daemon) {
		t.Error("the daemon survived stop")
	}
	if !alive(cli.Process.Pid) {
		t.Error("stop killed a keenetic-xray process that was not the daemon")
	}
}

func TestInitScript_SecondStartDoesNotLaunchAnotherDaemon(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	e.run(t, "start")
	first := e.daemonPID(t)
	out, code := e.run(t, "start")
	if code != 0 || !strings.Contains(out, "already running") {
		t.Fatalf("second start: exit %d: %s", code, out)
	}
	if got := e.daemonPID(t); got != first || !alive(first) {
		t.Errorf("second start replaced the daemon: pid %d -> %d", first, got)
	}
}

// TestInitScript_StalePidfileIsNotADaemon: a pidfile left by a crash,
// its PID now reused -- by an unrelated process, or by a keenetic-xray
// CLI command without the `daemon` argument -- must read as stopped.
func TestInitScript_StalePidfileIsNotADaemon(t *testing.T) {
	e := newInitEnv(t, fakeDaemon)
	if err := os.MkdirAll(filepath.Dir(e.pidFile), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, pid := range map[string]int{
		"unrelated process":             os.Getpid(),
		"keenetic-xray CLI, not daemon": e.cli(t).Process.Pid,
		"no such process":               1 << 22,
	} {
		if err := os.WriteFile(e.pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, code := e.run(t, "status"); code != 1 {
			t.Errorf("%s: status exit %d (%s), want 1", name, code, out)
		}
	}
}

// TestInitScript_FailedStartSaysWhy is BOOT-04: rc.func sent the
// daemon's stderr to /dev/null, so a fatal startup error -- raised before
// daemon.log even exists -- vanished without a trace.
func TestInitScript_FailedStartSaysWhy(t *testing.T) {
	e := newInitEnv(t, "#!/bin/sh\necho 'keenetic-xray: loading config: unexpected end of JSON input' >&2\nexit 1\n")
	start := time.Now()
	out, code := e.run(t, "start")
	if code == 0 {
		t.Fatalf("start of a daemon that exits at once reported success: %s", out)
	}
	if !strings.Contains(out, "unexpected end of JSON input") {
		t.Errorf("start output does not carry the daemon's own error:\n%s", out)
	}
	boot, _ := os.ReadFile(filepath.Join(e.logDir, "boot.log"))
	if !strings.Contains(string(boot), "unexpected end of JSON input") {
		t.Errorf("boot.log does not carry the daemon's own error:\n%s", boot)
	}
	if time.Since(start) > 20*time.Second {
		t.Errorf("start took %s to give up", time.Since(start))
	}
}

// withHook is fakeDaemon plus the restart hook, doing what
// cmdWatchdogRestartHook does on an ordinary restart: become the init
// script's `start`.
var withHook = strings.Replace(fakeDaemon, "sleep 30\n",
	`if [ "$1 $2" = "internal watchdog-restart-hook" ]; then exec sh "$KX_INIT" start watchdog; fi
sleep 30
`, 1)

// watchdogBench writes the script writeWatchdogScript generates for e,
// pointed at the real init script, and returns a func running one cron
// tick of it plus the log it writes.
func watchdogBench(t *testing.T, e *initEnv) (tick func(), logFile string) {
	t.Helper()
	initPath, err := filepath.Abs(filepath.Join("..", "..", "packaging", "init.d", "S99keenetic-xray"))
	if err != nil {
		t.Fatal(err)
	}
	e.env = append(e.env, "KX_INIT="+initPath)
	sh := shell()
	// The generated script calls $INIT directly, so give it an executable
	// that runs the real init script under the shell being tested.
	wrapper := filepath.Join(e.dir, "S99keenetic-xray")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexec "+strings.Join(sh, " ")+" "+initPath+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(e.dir, "watchdog.sh")
	logFile = filepath.Join(e.logDir, "watchdog.log")
	if err := writeWatchdogScript(script, wrapper, logFile, e.bin); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.logDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		cmd := exec.Command(sh[0], append(sh[1:], script)...)
		cmd.Env = e.env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("watchdog tick: %v: %s", err, out)
		}
	}, logFile
}

// TestWatchdogScript_EndToEnd: a healthy tick must stay silent; a tick
// that finds the daemon down must bring it back and say so.
func TestWatchdogScript_EndToEnd(t *testing.T) {
	e := newInitEnv(t, withHook)
	tick, logFile := watchdogBench(t, &e)

	tick() // daemon down: the tick must bring it back
	if pid := e.daemonPID(t); pid == 0 || !alive(pid) {
		log, _ := os.ReadFile(logFile)
		t.Fatalf("the watchdog tick did not bring the daemon up; log:\n%s", log)
	}
	log, _ := os.ReadFile(logFile)
	if !strings.Contains(string(log), "daemon running again") {
		t.Errorf("log does not record the outcome:\n%s", log)
	}

	before := len(log)
	tick() // daemon up: nothing to do, nothing to write
	if log, _ = os.ReadFile(logFile); len(log) != before {
		t.Errorf("a healthy tick wrote to the log:\n%s", log[before:])
	}
}

// TestWatchdogScript_ShellRollbackWhenTheBinaryCannotRun is UPD-02's
// remainder: an update whose binary can't run at all can't roll itself
// back -- the hook *is* that binary. The script must do it from shell
// using the update marker, exactly once.
func TestWatchdogScript_ShellRollbackWhenTheBinaryCannotRun(t *testing.T) {
	e := newInitEnv(t, withHook)
	tick, logFile := watchdogBench(t, &e)
	if err := os.Chmod(e.bin, 0o644); err != nil { // the "new version": can't execute
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("old-ipk")) }))
	defer srv.Close()
	marker := filepath.Join(e.logDir, "self-update.json")
	if err := os.WriteFile(marker, []byte(`{"prev_version":"0.32.82","ipk_url":"`+srv.URL+`/old.ipk","arch":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// opkg "installing the old version" puts a runnable binary back.
	fakeBin := filepath.Join(e.dir, "fakebin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "opkg"), []byte("#!/bin/sh\necho \"opkg $*\"\nchmod +x \"$KEENETIC_XRAY_BIN\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i, kv := range e.env {
		if strings.HasPrefix(kv, "PATH=") {
			e.env[i] = "PATH=" + fakeBin + ":" + strings.TrimPrefix(kv, "PATH=")
		}
	}

	tick()
	log, _ := os.ReadFile(logFile)
	for _, want := range []string{"rolling back to " + srv.URL, "opkg install --force-downgrade --force-reinstall", "rollback installed"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
	if pid := e.daemonPID(t); pid == 0 || !alive(pid) {
		t.Errorf("no daemon after the shell rollback; log:\n%s", log)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("the marker survived: a still-broken build would be reinstalled on every tick")
	}
	if _, err := os.Stat(filepath.Join(e.logDir, "rollback.ipk")); !os.IsNotExist(err) {
		t.Error("the downloaded .ipk was left behind")
	}
}
