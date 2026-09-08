// Package health runs the periodic all-profiles quality sweep: on a
// schedule the daemon probes every saved profile (not just the live one)
// through a throwaway isolated xray, so `status` can show which backups
// are actually reachable before a failover ever has to pick one. The
// sweep is strictly read-only w.r.t. live traffic -- it never touches
// the production or recovery-pretest xray, only its own scratch inbound
// on a separate port.
package health

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Result is one profile's last probe outcome.
type Result struct {
	Key       string    `json:"key"`    // config.Profile.ImportKey()
	Remark    string    `json:"remark"` // display name at sweep time
	OK        bool      `json:"ok"`
	Detail    string    `json:"detail,omitempty"` // short failure class, when !OK
	CheckedAt time.Time `json:"checked_at"`
}

// State is the whole last sweep, as persisted next to the daemon log.
type State struct {
	SweptAt time.Time `json:"swept_at"`
	Results []Result  `json:"results"`
}

// Load reads a State file. Any problem (missing, unreadable, malformed)
// yields a zero State, never an error -- a stale or absent sweep just
// means `status` shows nothing for it.
func Load(path string) State {
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return State{}
	}
	return s
}

// Save writes s atomically with 0600 perms (same as config.json -- a
// Remark can hint at a location).
func Save(path string, s State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StatusLines renders the last sweep as a compact block for `status`
// output (CLI and the bot heartbeat), or "" when there's nothing on
// record. `now` is passed in so callers/tests control the clock.
func StatusLines(s State, now time.Time) string {
	if len(s.Results) == 0 {
		return ""
	}
	rs := append([]Result(nil), s.Results...)
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].OK != rs[j].OK {
			return !rs[i].OK // failures first
		}
		return rs[i].Remark < rs[j].Remark
	})

	out := fmt.Sprintf("опрос профилей (%s назад):", humanAge(now.Sub(s.SweptAt)))
	for _, r := range rs {
		mark := "✅"
		extra := ""
		if !r.OK {
			mark = "⚠️"
			if r.Detail != "" {
				extra = "  " + r.Detail
			}
		}
		out += fmt.Sprintf("\n  %s %s%s", mark, r.Remark, extra)
	}
	return out
}

// humanAge is a tiny relative-time formatter: "12 мин", "3 ч", "2 дн".
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "меньше минуты"
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d дн", int(d.Hours()/24))
	}
}
