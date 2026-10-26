package adaptiveroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// What the daemon knows about its own adaptive routing -- the counters and
// the per-address notes -- lives in memory (see stats.go). A CLI run over SSH
// is another process and cannot see it, so the daemon publishes a copy to a
// file the CLI reads. The file belongs on a RAM disk (cmd/keenetic-xray puts
// it under /tmp): it is refreshed every few seconds while things are
// happening and must never cost flash writes.

const snapshotVersion = 1

// Snapshot is the published copy.
type Snapshot struct {
	Version int           `json:"version"`
	At      time.Time     `json:"at"`
	Stats   StatsSnapshot `json:"stats"`
	Notes   []Note        `json:"notes"`
}

// Lookup returns the note for addr, for JoinEntries.
func (s *Snapshot) Lookup(addr string) (Note, bool) {
	if s == nil {
		return Note{}, false
	}
	for _, n := range s.Notes {
		if n.Addr == addr {
			return n, true
		}
	}
	return Note{}, false
}

// WriteSnapshot publishes the current counters and notes to path, atomically.
func WriteSnapshot(path string, now time.Time) error {
	snap := Snapshot{Version: snapshotVersion, At: now, Stats: Stats(now), Notes: allNotes()}
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".adaptive-snapshot-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ReadSnapshot loads what WriteSnapshot published. A file written by a
// different version of the program is reported as missing: its layout is not
// a contract.
func ReadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	if snap.Version != snapshotVersion {
		return nil, os.ErrNotExist
	}
	return &snap, nil
}

// SnapshotIfDirty publishes the snapshot when something changed since the
// last time and at least minInterval has passed; it reports whether it wrote.
// Cheap to call every tick.
func SnapshotIfDirty(path string, now time.Time, minInterval time.Duration) (bool, error) {
	stats.mu.Lock()
	due := stats.dirty && (stats.lastWrite.IsZero() || now.Sub(stats.lastWrite) >= minInterval)
	if due {
		stats.dirty = false
		stats.lastWrite = now
	}
	stats.mu.Unlock()
	if !due {
		return false, nil
	}
	if err := WriteSnapshot(path, now); err != nil {
		stats.mu.Lock()
		stats.dirty = true // try again on a later call
		stats.mu.Unlock()
		return false, err
	}
	return true, nil
}
