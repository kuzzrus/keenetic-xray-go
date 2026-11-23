package subscription

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RefreshState is the daemon's bookkeeping for the periodic subscription
// refresh, kept in a small file of its own rather than in config.json: a failed
// attempt has to be remembered (for the retry back-off) without rewriting the
// config, and nothing here is a setting. It holds no secrets -- LastError is
// stored with URLs redacted (RedactURLs).
type RefreshState struct {
	LastAttempt  time.Time `json:"last_attempt,omitempty"`
	LastSuccess  time.Time `json:"last_success,omitempty"`
	Failures     int       `json:"failures,omitempty"` // consecutive failed attempts
	FailingSince time.Time `json:"failing_since,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
	FailNotified bool      `json:"fail_notified,omitempty"` // the operator was told about this streak
	// WarnHash identifies the slot notes the operator was last told about, so
	// the same one (a server gone from the subscription) is said once, not
	// every refresh. Survives successes and failures alike; "" once there are none.
	WarnHash string `json:"warn_hash,omitempty"`
}

// LoadRefreshState reads the state file; a missing or unreadable one is the
// zero state (nothing attempted yet), never an error.
func LoadRefreshState(path string) RefreshState {
	b, err := os.ReadFile(path)
	if err != nil {
		return RefreshState{}
	}
	var s RefreshState
	if json.Unmarshal(b, &s) != nil {
		return RefreshState{}
	}
	return s
}

// SaveRefreshState writes the state atomically (temp file + rename).
func SaveRefreshState(path string, s RefreshState) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".subscription-refresh-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// NoteSuccess records a successful attempt and ends any failing streak.
func (s *RefreshState) NoteSuccess(now time.Time) {
	*s = RefreshState{LastAttempt: now, LastSuccess: now, WarnHash: s.WarnHash}
}

// NoteFailure records a failed attempt; the last success is kept.
func (s *RefreshState) NoteFailure(now time.Time, msg string) {
	if s.Failures == 0 || s.FailingSince.IsZero() {
		s.FailingSince = now
		s.FailNotified = false
	}
	s.Failures++
	s.LastAttempt = now
	s.LastError = msg
}

// RetryDelay is how long to wait before the next attempt after the given number
// of consecutive failures: a transient failure (the tunnel is still coming up,
// the provider hiccuped) is retried soon, a persistent one settles at every six
// hours instead of hammering the provider.
func RetryDelay(failures int) time.Duration {
	switch {
	case failures <= 1:
		return 10 * time.Minute
	case failures == 2:
		return 30 * time.Minute
	case failures == 3:
		return 2 * time.Hour
	default:
		return 6 * time.Hour
	}
}

// Due is when the next automatic refresh is due. lastFetched is
// Subscription.LastFetchedAt, which a manual refresh stamps too; the later of it
// and the last success is the anchor, so refreshing by hand pushes the schedule
// back. A timestamp from the future (the clock was wrong when it was written, or
// is now) counts as unknown. With no anchor at all the answer is "now".
//
// After failures the retry back-off applies instead -- unless a success (a manual
// refresh) has come since the last attempt, which ends the streak.
func (s RefreshState) Due(lastFetched, now time.Time, interval time.Duration) time.Time {
	sane := func(t time.Time) time.Time {
		if t.After(now.Add(time.Minute)) {
			return time.Time{}
		}
		return t
	}
	anchor := sane(s.LastSuccess)
	if lf := sane(lastFetched); lf.After(anchor) {
		anchor = lf
	}
	attempt := sane(s.LastAttempt)
	if s.Failures > 0 && !attempt.IsZero() && !anchor.After(attempt) {
		d := RetryDelay(s.Failures)
		if d > interval {
			d = interval
		}
		return attempt.Add(d)
	}
	if anchor.IsZero() {
		return now
	}
	return anchor.Add(interval)
}

// FailureOverdue reports whether the failing streak has gone on for a whole
// interval without the operator being told: the moment to say that the
// subscription has stopped updating. A fetch that fails once and succeeds on a
// retry never gets here.
func (s RefreshState) FailureOverdue(now time.Time, interval time.Duration) bool {
	return s.Failures > 0 && !s.FailNotified && !s.FailingSince.IsZero() && now.Sub(s.FailingSince) >= interval
}
