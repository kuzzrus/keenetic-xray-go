package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// These read /proc for diag's memory section: what the router has, and
// what the daemon and every xray instance take -- the numbers asked for
// by hand on 2026-09-28 (RSS, open files against the limit). Off Linux
// there is no /proc, and they report that instead of guessing.

// memInfo returns MemTotal and MemAvailable from /proc/meminfo, in kB.
func memInfo() (totalKB, availKB int, err error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.Atoi(f[1])
		switch f[0] {
		case "MemTotal:":
			totalKB = n
		case "MemAvailable:":
			availKB = n
		}
	}
	return totalKB, availKB, nil
}

// procUsage is diag's one line for a process.
type procUsage struct {
	RSSKB   int
	FDs     int
	FDLimit string // the soft limit exactly as /proc/<pid>/limits prints it
	Args    string // cmdline, spaces for NULs, cut short
}

func procUsageOf(pid int) (procUsage, error) {
	dir := "/proc/" + strconv.Itoa(pid)
	status, err := os.ReadFile(dir + "/status")
	if err != nil {
		return procUsage{}, err
	}
	var u procUsage
	for _, line := range strings.Split(string(status), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			u.RSSKB, _ = strconv.Atoi(f[1])
		}
	}
	if fds, err := os.ReadDir(dir + "/fd"); err == nil {
		u.FDs = len(fds)
	}
	if limits, err := os.ReadFile(dir + "/limits"); err == nil {
		for _, line := range strings.Split(string(limits), "\n") {
			if strings.HasPrefix(line, "Max open files") {
				if f := strings.Fields(strings.TrimPrefix(line, "Max open files")); len(f) > 0 {
					u.FDLimit = f[0]
				}
			}
		}
	}
	if cmd, err := os.ReadFile(dir + "/cmdline"); err == nil {
		u.Args = strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(u.Args) > 90 {
			u.Args = u.Args[:90] + "…"
		}
	}
	return u, nil
}

// pidsNamed lists the processes whose /proc/<pid>/comm is name.
func pidsNamed(name string) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil && strings.TrimSpace(string(b)) == name {
			pids = append(pids, pid)
		}
	}
	return pids
}

// writeDiagMemory is diag's memory section.
func writeDiagMemory(w io.Writer) {
	total, avail, err := memInfo()
	if err != nil {
		fmt.Fprintf(w, "нет /proc (%v) — не на роутере\n", err)
		return
	}
	fmt.Fprintf(w, "память: всего %d MB, доступно %d MB\n", total/1024, avail/1024)
	line := func(label string, pid int) {
		u, err := procUsageOf(pid)
		if err != nil {
			fmt.Fprintf(w, "%-7s pid %d: %v\n", label, pid, err)
			return
		}
		fmt.Fprintf(w, "%-7s pid %-6d RSS %4d MB  файлов %d/%s  %s\n", label, pid, u.RSSKB/1024, u.FDs, u.FDLimit, u.Args)
	}
	if pid, err := runningDaemonPID(); err == nil {
		line("daemon", pid)
	} else {
		fmt.Fprintf(w, "daemon  не запущен (%v)\n", err)
	}
	pids := pidsNamed("xray")
	if len(pids) == 0 {
		fmt.Fprintln(w, "xray    не запущен")
	}
	for _, pid := range pids {
		line("xray", pid)
	}
}
