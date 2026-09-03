package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const initScript = "/opt/etc/init.d/S99keenetic-xray"

// offerDaemonRestart restarts the failover daemon through its init
// script, after a Y/n prompt. The daemon has no live config reload, so a
// `setup` or `proxy0` change only takes effect after this -- forgetting
// it is the classic "I configured everything but nothing listens".
// Where the init script isn't present (dev box, foreground use) it just
// prints how to start the daemon.
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
