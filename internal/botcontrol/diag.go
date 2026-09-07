package botcontrol

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// selfExe / runSelf are the seam for `h.diag` -- overridable in tests.
var (
	selfExe = os.Executable
	runSelf = func(ctx context.Context, exe string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, exe, args...).Output()
	}
)

// diag shells out to this same binary's `diag` subcommand and returns
// its bundle. The bundle is already secret-redacted (config.Redacted);
// Handle's scrubSecrets runs over it too as a second net.
func (h *RouterHandler) diag(ctx context.Context) (string, error) {
	exe, err := selfExe()
	if err != nil {
		return "", fmt.Errorf("не нашёл свой бинарь для diag: %w", err)
	}
	cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	out, err := runSelf(cctx, exe, "diag")
	if err != nil && len(out) == 0 {
		return "", fmt.Errorf("diag не отработал: %w", err)
	}
	return string(out), nil
}
