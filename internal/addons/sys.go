package addons

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// The vars below are the only places this package touches the system.
// Tests swap them (see sys_test.go's withSys helper) so component logic
// runs without opkg, rc.func, or a real /opt. Same pattern as
// internal/keenetic (lookNdmc/ndmcRun) and internal/install (cron hooks).
var (
	// opkgRun executes `opkg <args...>` and returns combined output.
	opkgRun = func(ctx context.Context, args ...string) (string, error) {
		return runCombined(ctx, "opkg", args...)
	}
	// initdRun executes `/opt/etc/init.d/<script> <action>`; script is a
	// bare name like "S51nfqws2".
	initdRun = func(ctx context.Context, script, action string) (string, error) {
		return runCombined(ctx, filepath.Join(initdDir, script), action)
	}
	// processMatches reports whether `ps` shows a line matching pattern
	// (a plain substring; ps|grep, not pgrep -- busybox may lack pgrep).
	processMatches = func(ctx context.Context, pattern string) bool {
		out, err := runCombined(ctx, "sh", "-c", "ps 2>/dev/null | grep -v grep")
		if err != nil {
			return false
		}
		return strings.Contains(out, pattern)
	}
	// portListening reports whether something holds tcp/udp <port> locally
	// (netstat is in busybox; ss usually isn't).
	portListening = func(ctx context.Context, port int) bool {
		out, err := runCombined(ctx, "sh", "-c", "netstat -ln 2>/dev/null")
		if err != nil {
			return false
		}
		return strings.Contains(out, fmt.Sprintf(":%d ", port))
	}

	readFile  = os.ReadFile
	writeFile = func(path string, b []byte, perm os.FileMode) error {
		if dir := filepath.Dir(path); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		return os.WriteFile(path, b, perm)
	}
	removeFile = os.Remove
	mkdirAll   = func(path string) error { return os.MkdirAll(path, 0o755) }
)

const initdDir = "/opt/etc/init.d"

func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// opkgInstalledVersion returns the installed version of pkg, or "" if
// it isn't installed. `opkg list-installed <pkg>` prints
// "<pkg> - <version>" when present, nothing when not.
func opkgInstalledVersion(ctx context.Context, pkg string) string {
	out, err := opkgRun(ctx, "list-installed", pkg)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == pkg && f[1] == "-" {
			return f[2]
		}
	}
	return ""
}

// opkgInstall runs `opkg update` (best-effort) then `opkg install
// pkg...`. A failed update isn't fatal -- the feeds may already be
// fresh -- but a failed install is.
func opkgInstall(ctx context.Context, pkgs ...string) error {
	_, _ = opkgRun(ctx, "update")
	if out, err := opkgRun(ctx, append([]string{"install"}, pkgs...)...); err != nil {
		return fmt.Errorf("opkg install %s: %w\n%s", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
	}
	return nil
}

// opkgRemove runs `opkg remove pkg...`.
func opkgRemove(ctx context.Context, pkgs ...string) error {
	if out, err := opkgRun(ctx, append([]string{"remove"}, pkgs...)...); err != nil {
		return fmt.Errorf("opkg remove %s: %w\n%s", strings.Join(pkgs, " "), err, strings.TrimSpace(out))
	}
	return nil
}
