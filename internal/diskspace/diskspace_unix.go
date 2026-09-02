//go:build unix

package diskspace

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// FreeBytes returns the free space, in bytes, on the filesystem containing
// path, after resolving symlinks.
func FreeBytes(path string) (int64, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// path may not exist yet (e.g. during postinst before any
		// directories are created) -- fall back to the unresolved path
		// so the caller still gets a real statfs error rather than an
		// EvalSymlinks one.
		resolved = path
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(resolved, &stat); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", resolved, err)
	}

	// Statfs_t.Bsize's underlying type differs across Go's linux/GOARCH
	// targets (int32 on some, int64 on others) -- cast both operands to
	// int64 explicitly rather than assuming a fixed width, since this
	// must build for both arm64 and mipsle.
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}
