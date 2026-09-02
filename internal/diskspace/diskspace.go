// Package diskspace resolves the real filesystem behind a path (Entware
// routinely symlinks /opt to a USB mount, not the tiny internal flash
// overlay) and reports its free space.
//
// The real implementation lives in diskspace_unix.go and uses statfs(2),
// so it builds on unix only. diskspace_other.go provides a stub for other
// platforms (a Windows dev machine): the daemon itself only ever runs on
// Linux routers, but keeping the package buildable everywhere lets
// `go build ./...`, `go vet`, and the editor tooling work off-target.
package diskspace
