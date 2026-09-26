package version

import (
	"runtime/debug"
	"time"
)

// BuildTime reports the commit time of the source this binary was built
// from, read from the VCS stamp the Go toolchain embeds on its own -- no
// ldflags involved. Release builds already carry it: v0.32.80 reports
// vcs.time=2026-09-24T20:56:47Z, the exact merge whose data it embeds.
//
// ok is false when there is no stamp (go test, a build outside a git
// checkout, -buildvcs=false) and also when the tree was dirty: a
// modified checkout no longer matches the commit its time belongs to,
// so that time says nothing reliable about what the binary embeds.
func BuildTime() (t time.Time, ok bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return time.Time{}, false
	}
	return buildTimeFrom(info.Settings)
}

// buildTimeFrom is BuildTime's parsing half, separated so it can be
// tested -- a test binary carries no VCS stamp of its own.
func buildTimeFrom(settings []debug.BuildSetting) (time.Time, bool) {
	var raw string
	clean := false
	for _, s := range settings {
		switch s.Key {
		case "vcs.time":
			raw = s.Value
		case "vcs.modified":
			clean = s.Value == "false"
		}
	}
	if raw == "" || !clean {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
