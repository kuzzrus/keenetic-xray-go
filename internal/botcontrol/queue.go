package botcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// RouterState is one router's queued commands and most recent result, as
// tracked by the control server.
type RouterState struct {
	Pending      []Command `json:"pending,omitempty"`
	LastResult   *Result   `json:"last_result,omitempty"`
	LastPollAt   time.Time `json:"last_poll_at,omitempty"`
	LastStatus   string    `json:"last_status,omitempty"`    // rendered snapshot from the agent's heartbeat
	LastStatusAt time.Time `json:"last_status_at,omitempty"` // when that snapshot was received
}

type storeState struct {
	Routers  map[string]*RouterState  `json:"routers"`
	Registry map[string]*RouterRecord `json:"registry,omitempty"`
}

// Store tracks per-router command queues and results, persisted to a JSON
// file on every mutation (write-temp-then-rename) so a control-server
// restart can never lose a command that was queued but not yet delivered
// to its router, or leave a truncated/corrupt queue file behind if it
// crashes mid-write.
type Store struct {
	path string

	mu    sync.Mutex
	state storeState
}

var commandSeq uint64

func newCommandID() string {
	n := atomic.AddUint64(&commandSeq, 1)
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), n)
}

// LoadStore reads path if it exists, or returns an empty Store bound to
// path (so later mutations persist there) if it doesn't -- a missing
// queue file is the ordinary state for a fresh control-server, not an
// error. Pass an empty path to get a Store that never persists, e.g. in
// tests.
func LoadStore(path string) (*Store, error) {
	s := &Store{path: path, state: newStoreState()}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if s.state.Routers == nil {
		s.state.Routers = make(map[string]*RouterState)
	}
	if s.state.Registry == nil {
		s.state.Registry = make(map[string]*RouterRecord)
	}
	return s, nil
}

func newStoreState() storeState {
	return storeState{
		Routers:  make(map[string]*RouterState),
		Registry: make(map[string]*RouterRecord),
	}
}

// Enqueue appends a command to routerID's pending queue and returns the
// command's assigned ID.
func (s *Store) Enqueue(routerID, action string, args []string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cmd := Command{ID: newCommandID(), Action: action, Args: args, Queued: time.Now()}
	rs := s.routerLocked(routerID)
	rs.Pending = append(rs.Pending, cmd)
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return cmd.ID, nil
}

// Dequeue pops and returns routerID's next pending command, or nil if
// there isn't one. Called from the /agent/poll handler.
func (s *Store) Dequeue(routerID string) (*Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs := s.routerLocked(routerID)
	rs.LastPollAt = time.Now()
	if len(rs.Pending) == 0 {
		return nil, s.saveLocked()
	}
	cmd := rs.Pending[0]
	rs.Pending = rs.Pending[1:]
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return &cmd, nil
}

// SetStatus stores the rendered status snapshot from a router's
// heartbeat. Called from the /agent/heartbeat handler.
func (s *Store) SetStatus(routerID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.routerLocked(routerID)
	rs.LastStatus = status
	rs.LastStatusAt = time.Now()
	return s.saveLocked()
}

// RecordResult stores result as routerID's most recent result. Called
// from the /agent/result handler.
func (s *Store) RecordResult(routerID string, result Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rs := s.routerLocked(routerID)
	r := result
	rs.LastResult = &r
	return s.saveLocked()
}

// LastResult returns routerID's most recently recorded result, or nil if
// none has been recorded yet.
func (s *Store) LastResult(routerID string) *Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.state.Routers[routerID]
	if !ok {
		return nil
	}
	return rs.LastResult
}

// LastPollAt returns when routerID last polled, or the zero time if it
// never has.
func (s *Store) LastPollAt(routerID string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rs, ok := s.state.Routers[routerID]; ok {
		return rs.LastPollAt
	}
	return time.Time{}
}

// PendingCount returns how many commands are queued but not yet
// delivered for routerID.
func (s *Store) PendingCount(routerID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.state.Routers[routerID]
	if !ok {
		return 0
	}
	return len(rs.Pending)
}

// RouterIDs returns the IDs of every router the store has state for
// (enqueued a command for, or received a poll/result from), sorted.
func (s *Store) RouterIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.state.Routers))
	for id := range s.state.Routers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// AwaitResult polls (every 200ms, cheaply -- this is a low-traffic
// personal control server, not a place to justify a pubsub mechanism)
// for routerID to record a result matching commandID, up to timeout. It
// returns (nil, false) on timeout or context cancellation. Used by the
// Telegram bot so an online router's reply feels synchronous even though
// the wire protocol underneath is poll-based.
func (s *Store) AwaitResult(ctx context.Context, routerID, commandID string, timeout time.Duration) (*Result, bool) {
	deadline := time.Now().Add(timeout)
	for {
		if r := s.LastResult(routerID); r != nil && r.CommandID == commandID {
			return r, true
		}
		if !time.Now().Before(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// routerLocked returns routerID's state, creating it if necessary. Caller
// must hold s.mu.
func (s *Store) routerLocked(routerID string) *RouterState {
	rs, ok := s.state.Routers[routerID]
	if !ok {
		rs = &RouterState{}
		s.state.Routers[routerID] = rs
	}
	return rs
}

// saveLocked persists the store to s.path via write-temp-then-rename.
// Caller must hold s.mu.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding queue store: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating queue directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".queue-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("renaming temp file into place: %w", err)
	}
	return nil
}
