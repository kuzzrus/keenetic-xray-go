//go:build !unix

package diskspace

import (
	"fmt"
	"os"
)

// FreeBytes is a stub for non-unix platforms (a Windows dev machine). The
// daemon only ever runs on Linux, so this exists purely to keep the
// package buildable off-target. It reports an implausibly large amount of
// free space -- enough that install.DecideVariant always picks the Full
// variant -- while still returning an error for a path that does not
// exist, matching the real implementation's contract for the callers that
// exercise it cross-platform.
func FreeBytes(path string) (int64, error) {
	if _, err := os.Stat(path); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	const oneEiB = 1 << 60
	return oneEiB, nil
}
