package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const initScript = "/opt/etc/init.d/S99keenetic-xray"

// writeDaemonPIDFile records this process's PID at pidFilePath, so a
// later CLI command can find it (see runningDaemonPID). The returned
// func removes it; call it on shutdown. The caller decides how to treat
// a failure -- cmdDaemon logs a warning and carries on, since this only
// affects the live-reload convenience, not the daemon's actual job.
func writeDaemonPIDFile() (cleanup func(), err error) {
	path := pidFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return func() { _ = os.Remove(path) }, nil
}

// applyDaemonChange makes a config change just saved to disk take
// effect on a daemon that may already be running. It first tries
// signalDaemonReload (SIGHUP -- the running daemon reloads config.json
// and re-applies it live, restarting only the supervised xray-core
// child via failover.Daemon.ReloadConfig, not itself), and only falls
// back to offering a full restart if that's not possible: no daemon
// running yet, no pidfile, or a stale one. Every command that changes
// config.json (setup, proxy0 set/off, subscription refresh/set-*,
// failover set) calls this instead of unconditionally restarting, so a
// live router only ever drops the xray-core connection for as long as
// that one child process takes to relaunch -- not a full daemon+agent
// restart, which used to also cost the control-server polling
// connection a reconnect.
func applyDaemonChange(in *bufio.Reader, interactive bool) {
	if signalDaemonReload() {
		fmt.Println("applied live (no restart needed)")
		return
	}
	if interactive {
		offerDaemonRestart(in)
		return
	}
	fmt.Printf("apply with: %s restart\n", initScript)
}

// signalDaemonReload sends SIGHUP to the running daemon (found via its
// own pidfile, see pidFilePath) so it reloads config.json live -- see
// failover.Daemon.ReloadConfig. Best-effort: reports false, not an
// error, whenever there's nothing to signal (no pidfile, unreadable,
// pid no longer running, or now some other process -- a pidfile can go
// stale if the daemon crashed or was killed -9), so callers fall back
// to the older "restart the whole daemon" guidance instead of failing
// the command that actually made the config change.
func signalDaemonReload() bool {
	pid, err := runningDaemonPID()
	if err != nil {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.SIGHUP) == nil
}

// processName reads /proc/<pid>/comm, the running executable's name --
// a test hook (overridden in daemonctl_test.go, since /proc doesn't
// exist on the Windows box this is developed on, only the Linux routers
// and servers it actually runs on). Returns "" if it can't be read
// (process gone, no /proc at all).
var processName = func(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// runningDaemonPID reads pidFilePath and cross-checks processName
// actually names this binary before trusting it -- SIGHUP terminates a
// process that hasn't installed its own handler for it, by POSIX
// default, so signaling a reused PID on a stale pidfile would be a real
// (if unlikely) way to kill an unrelated process rather than a
// merely-ineffective no-op.
func runningDaemonPID() (int, error) {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("pidfile %s: %w", pidFilePath(), err)
	}
	name := processName(pid)
	if name == "" {
		return 0, fmt.Errorf("pid %d from %s is not running", pid, pidFilePath())
	}
	if name != "keenetic-xray" {
		return 0, fmt.Errorf("pid %d from %s is now %q, not keenetic-xray -- stale pidfile", pid, pidFilePath(), name)
	}
	return pid, nil
}

// offerDaemonRestart restarts the failover daemon through its init
// script, after a Y/n prompt. Called by applyDaemonChange only once a
// live reload wasn't possible. Where the init script isn't present (dev
// box, foreground use) it just prints how to start the daemon.
func offerDaemonRestart(in *bufio.Reader) {
	if fi, err := os.Stat(initScript); err != nil || fi.IsDir() {
		fmt.Println("Start the failover daemon with: keenetic-xray daemon")
		return
	}
	fmt.Print("\nRestart the failover daemon now to apply? [Y/n]: ")
	line, _ := in.ReadString('\n')
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "n") {
		fmt.Printf("not restarted -- apply later with: %s restart\n", initScript)
		return
	}
	cmd := exec.Command(initScript, "restart")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("restart failed (%v) -- run it yourself: %s restart\n", err, initScript)
	}
}
