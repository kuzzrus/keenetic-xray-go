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
//
// Format: line 1 is the PID, line 2 (when it can be read) is a
// start-time token for that PID -- /proc/<pid>/stat field 22, ticks
// since boot. /opt lives on persistent flash, so after a reboot the
// kernel readily hands our old PID to an unrelated process;
// runningDaemonPID compares this token to reject that case before
// signalling. An old single-line pidfile still works (the token check is
// simply skipped), and off Linux the token is empty so only the PID
// line is written -- same lenient convention as processName.
func writeDaemonPIDFile() (cleanup func(), err error) {
	path := pidFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	body := strconv.Itoa(os.Getpid())
	if tok := procStartToken(os.Getpid()); tok != "" {
		body += "\n" + tok
	}
	if err := os.WriteFile(path, []byte(body+"\n"), 0o644); err != nil {
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
		fmt.Println("применено на лету (рестарт не нужен)")
		return
	}
	// Fresh install: postinst runs `S99keenetic-xray start` right after
	// the wizard, so there's nothing to restart -- and restarting here
	// would be actively harmful, since rc.func's stop matches by process
	// name and kills the running `keenetic-xray setup` process itself.
	if os.Getenv("KEENETIC_XRAY_POSTINST") == "1" {
		fmt.Println("демон запустится сразу после установки — рестарт не нужен")
		return
	}
	if interactive {
		offerDaemonRestart(in)
		return
	}
	fmt.Printf("применить:  %s restart\n", initScript)
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

// procStartToken returns a value that is stable for the lifetime of one
// process but differs across a PID reuse: /proc/<pid>/stat field 22,
// the process start time in clock ticks since boot. Test hook, same
// lenient convention as processName -- "" when it can't be read (no
// /proc, process gone, unparseable). Field 2 is "(comm)" and comm may
// itself contain spaces or ')', so parsing starts after the final ')'.
var procStartToken = func(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	return parseProcStatStartTime(string(data))
}

// parseProcStatStartTime pulls field 22 (starttime) out of a
// /proc/<pid>/stat line. Field 2 is "(comm)" and comm can contain
// spaces and ')', so parsing resumes after the final ')'. Returns ""
// if the line is too short or malformed.
func parseProcStatStartTime(stat string) string {
	rparen := strings.LastIndexByte(stat, ')')
	if rparen < 0 || rparen+2 >= len(stat) {
		return ""
	}
	// After "(comm) " the remaining fields are state(3) ... starttime(22),
	// so starttime is index 19.
	fields := strings.Fields(stat[rparen+2:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

// runningDaemonPID reads pidFilePath and cross-checks that the PID is
// still this binary -- and, when the pidfile carries a start-time token
// (line 2), that the PID has not since been recycled. SIGHUP terminates
// a process that hasn't installed its own handler for it, by POSIX
// default, so signalling a stale pidfile's PID would be a real way to
// kill an unrelated process rather than a merely-ineffective no-op. On
// flash-backed /opt a reboot makes PID reuse ordinary, not exotic.
func runningDaemonPID() (int, error) {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
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
	if len(lines) > 1 {
		if want := strings.TrimSpace(lines[1]); want != "" {
			if got := procStartToken(pid); got != want {
				return 0, fmt.Errorf("pid %d from %s started at %q, pidfile expects %q -- pid was recycled, stale pidfile", pid, pidFilePath(), got, want)
			}
		}
	}
	return pid, nil
}

// offerDaemonRestart restarts the failover daemon through its init
// script, after a Y/n prompt. Called by applyDaemonChange only once a
// live reload wasn't possible. Where the init script isn't present (dev
// box, foreground use) it just prints how to start the daemon.
func offerDaemonRestart(in *bufio.Reader) {
	if fi, err := os.Stat(initScript); err != nil || fi.IsDir() {
		fmt.Println("запусти демон:  keenetic-xray daemon")
		return
	}
	fmt.Print("\nПерезапустить демон сейчас, чтобы применить? [Y/n]: ")
	line, _ := in.ReadString('\n')
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "n") {
		fmt.Printf("не перезапущен — применить позже:  %s restart\n", initScript)
		return
	}
	// Detached, after a beat: rc.func's stop kills processes by name
	// (PROCS=keenetic-xray), so a synchronous restart here would take
	// this very process (`keenetic-xray setup` / `proxy0 set` / …) down
	// with the daemon. Let the caller return first, then restart.
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("sleep 1; %s restart", initScript))
	restartDetached(cmd)
	if err := cmd.Start(); err != nil {
		fmt.Printf("перезапуск не удался (%v) — сделай сам:  %s restart\n", err, initScript)
		return
	}
	_ = cmd.Process.Release()
	fmt.Println("демон перезапускается…")
}
