package xrayctl

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ValidateConfig runs `<binary> run -test -c <configPath>`: xray builds the
// whole instance from the config -- every inbound and outbound handler --
// and exits without starting it, so no port is bound and no device is
// touched. It is how a config naming something this xray-core does not know
// (the `tun` inbound on a core from before it existed) is caught before the
// production process is restarted into a crash loop. On failure the error
// carries the tail of what xray printed. env is added to the child's
// environment, like Supervisor.Env.
func ValidateConfig(ctx context.Context, binary, configPath string, env []string) error {
	cmd := exec.CommandContext(ctx, binary, "run", "-test", "-c", configPath)
	if env != nil {
		cmd.Env = append(append([]string{}, os.Environ()...), env...)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("xray -test: %w", ctx.Err())
	}
	return fmt.Errorf("xray -test: %v: %s", err, tailLines(string(out), 3))
}

// tailLines is the last n non-empty lines of s, joined with " | ".
func tailLines(s string, n int) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
