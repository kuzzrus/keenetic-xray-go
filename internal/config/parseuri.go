package config

import (
	"fmt"
	"strings"
)

// ParseProfileURI parses any share link this project understands --
// "vless://..." or "naive+<scheme>://..." -- into a Profile, dispatching
// on scheme. This is the one place that should decide which parser a raw
// link goes to; callers (profile add, setup's wizard and non-interactive
// path, subscription list parsing, a slot's own source) go through it
// instead of each hardcoding its own scheme check, so a new protocol only
// needs teaching here.
func ParseProfileURI(raw string) (Profile, error) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(trimmed, "vless://"):
		return ParseVLESSURI(trimmed)
	case strings.HasPrefix(trimmed, "naive+"):
		return ParseNaiveURI(trimmed)
	default:
		scheme, _, _ := strings.Cut(trimmed, "://")
		return Profile{}, fmt.Errorf("unrecognized share-link scheme %q (want vless:// or naive+https://)", scheme)
	}
}
