package version

import (
	"runtime/debug"
	"testing"
	"time"
)

func TestBuildTimeFrom(t *testing.T) {
	stamp := "2026-09-24T20:56:47Z"
	want, _ := time.Parse(time.RFC3339, stamp)

	cases := []struct {
		name     string
		settings []debug.BuildSetting
		ok       bool
	}{
		{"clean release build", []debug.BuildSetting{
			{Key: "vcs.revision", Value: "5bd005a0ec43538c9c91536d41e7ee11f8548c74"},
			{Key: "vcs.time", Value: stamp},
			{Key: "vcs.modified", Value: "false"},
		}, true},
		// A dirty tree no longer matches the commit its time belongs to,
		// so the time must not be trusted to describe what got embedded.
		{"dirty tree", []debug.BuildSetting{
			{Key: "vcs.time", Value: stamp},
			{Key: "vcs.modified", Value: "true"},
		}, false},
		{"modified flag missing", []debug.BuildSetting{
			{Key: "vcs.time", Value: stamp},
		}, false},
		{"no vcs stamp at all", nil, false},
		{"unparseable time", []debug.BuildSetting{
			{Key: "vcs.time", Value: "yesterday"},
			{Key: "vcs.modified", Value: "false"},
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := buildTimeFrom(c.settings)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if ok && !got.Equal(want) {
				t.Errorf("time = %v, want %v", got, want)
			}
		})
	}
}
