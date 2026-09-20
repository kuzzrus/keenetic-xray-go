package botcontrol

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_EnqueueDequeueFIFO(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}

	id1, err := s.Enqueue("router-1", ActionStatus, nil)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	id2, err := s.Enqueue("router-1", ActionSwitchPrimary, []string{"x"})
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("Enqueue returned the same ID twice: %q", id1)
	}

	got, err := s.Dequeue("router-1")
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got == nil || got.ID != id1 || got.Action != ActionStatus {
		t.Errorf("first Dequeue = %+v, want ID=%s Action=%s", got, id1, ActionStatus)
	}

	got, err = s.Dequeue("router-1")
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got == nil || got.ID != id2 || got.Action != ActionSwitchPrimary {
		t.Errorf("second Dequeue = %+v, want ID=%s Action=%s", got, id2, ActionSwitchPrimary)
	}

	got, err = s.Dequeue("router-1")
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if got != nil {
		t.Errorf("third Dequeue = %+v, want nil (queue empty)", got)
	}
}

func TestStore_DequeueUnknownRouterIsEmptyNotError(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	cmd, err := s.Dequeue("never-seen")
	if err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if cmd != nil {
		t.Errorf("Dequeue on unknown router = %+v, want nil", cmd)
	}
}

func TestStore_RecordResultAndLastResult(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if r := s.LastResult("router-1"); r != nil {
		t.Errorf("LastResult before any result = %+v, want nil", r)
	}

	result := Result{CommandID: "abc", Output: "did status", Completed: time.Now()}
	if err := s.RecordResult("router-1", result); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}

	got := s.LastResult("router-1")
	if got == nil || got.CommandID != "abc" || got.Output != "did status" {
		t.Errorf("LastResult = %+v, want CommandID=abc Output=\"did status\"", got)
	}

	// A second result replaces the first.
	result2 := Result{CommandID: "def", Output: "did switch_primary", Completed: time.Now()}
	if err := s.RecordResult("router-1", result2); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	got = s.LastResult("router-1")
	if got == nil || got.CommandID != "def" {
		t.Errorf("LastResult after second record = %+v, want CommandID=def", got)
	}
}

// TestStore_ResultFor_SurvivesLaterCommandsResult is the regression test
// for BOT-01's result-clobbering gap: a second command's result used to
// replace LastResult before the first command's own AwaitResult had a
// chance to observe it, timing that caller out despite the router having
// genuinely answered. ResultFor must still find the first result even
// after the second has also been recorded.
func TestStore_ResultFor_SurvivesLaterCommandsResult(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	first := Result{CommandID: "first", Output: "did status", Completed: time.Now()}
	if err := s.RecordResult("router-1", first); err != nil {
		t.Fatalf("RecordResult(first): %v", err)
	}
	second := Result{CommandID: "second", Output: "did switch_primary", Completed: time.Now()}
	if err := s.RecordResult("router-1", second); err != nil {
		t.Fatalf("RecordResult(second): %v", err)
	}

	if got := s.ResultFor("router-1", "first"); got == nil || got.Output != "did status" {
		t.Errorf("ResultFor(first) = %+v, want the first command's own result, not lost to the second's", got)
	}
	if got := s.ResultFor("router-1", "second"); got == nil || got.Output != "did switch_primary" {
		t.Errorf("ResultFor(second) = %+v", got)
	}
	// LastResult keeps its existing "most recent" meaning.
	if got := s.LastResult("router-1"); got == nil || got.CommandID != "second" {
		t.Errorf("LastResult = %+v, want the second (most recent) result", got)
	}
}

// TestStore_ResultFor_BoundedHistory checks RecentResults' size cap: old
// entries fall off once more than maxRecentResults have been recorded, so
// the store file can't grow without bound.
func TestStore_ResultFor_BoundedHistory(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	for i := 0; i < maxRecentResults+3; i++ {
		id := fmt.Sprintf("cmd-%d", i)
		if err := s.RecordResult("router-1", Result{CommandID: id, Completed: time.Now()}); err != nil {
			t.Fatalf("RecordResult(%s): %v", id, err)
		}
	}
	if got := s.ResultFor("router-1", "cmd-0"); got != nil {
		t.Errorf("ResultFor(cmd-0) = %+v, want nil -- it should have aged out of the bounded history", got)
	}
	if got := s.ResultFor("router-1", fmt.Sprintf("cmd-%d", maxRecentResults+2)); got == nil {
		t.Error("ResultFor for the most recent command should still be found")
	}
}

// TestStore_Dequeue_RollsBackOnSaveFailure is the regression test for the
// gap the audit found worse than its own framing: Dequeue used to pop
// the command from memory *first*, and only then try to save -- a save
// failure returned an error but left the command permanently gone from
// both memory and disk, not merely "not yet delivered". A failed save
// must leave the command queued for the next poll to retry.
func TestStore_Dequeue_RollsBackOnSaveFailure(t *testing.T) {
	dir := t.TempDir()
	// A file where saveLocked's own MkdirAll(filepath.Dir(s.path), ...)
	// expects a directory -- makes every save fail deterministically,
	// cross-platform, without needing OS-specific permission tricks.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Store{path: filepath.Join(blocker, "queue.json"), state: newStoreState()}

	if _, err := s.Enqueue("router-1", ActionStatus, nil); err == nil {
		t.Fatal("Enqueue should fail too (same broken path), got nil error")
	}
	// Enqueue's own save failure aside, force a command into Pending
	// directly so Dequeue has something to (fail to) pop.
	rs := s.routerLocked("router-1")
	rs.Pending = []Command{{ID: "c1", Action: ActionStatus}}

	cmd, err := s.Dequeue("router-1")
	if err == nil {
		t.Fatal("Dequeue should have failed to save, got nil error")
	}
	if cmd != nil {
		t.Errorf("Dequeue = %+v, want nil on a save failure", cmd)
	}
	if len(rs.Pending) != 1 || rs.Pending[0].ID != "c1" {
		t.Errorf("Pending after a failed Dequeue = %+v, want the command still queued for retry", rs.Pending)
	}
}

func TestStore_PendingCount(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if n := s.PendingCount("router-1"); n != 0 {
		t.Errorf("PendingCount on unknown router = %d, want 0", n)
	}

	if _, err := s.Enqueue("router-1", ActionStatus, nil); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := s.Enqueue("router-1", ActionSwitchPrimary, nil); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if n := s.PendingCount("router-1"); n != 2 {
		t.Errorf("PendingCount = %d, want 2", n)
	}

	if _, err := s.Dequeue("router-1"); err != nil {
		t.Fatalf("Dequeue: %v", err)
	}
	if n := s.PendingCount("router-1"); n != 1 {
		t.Errorf("PendingCount after one Dequeue = %d, want 1", n)
	}
}

func TestStore_RouterIDsSorted(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if _, err := s.Enqueue("zeta", ActionStatus, nil); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := s.Enqueue("alpha", ActionStatus, nil); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	ids := s.RouterIDs()
	if len(ids) != 2 || ids[0] != "alpha" || ids[1] != "zeta" {
		t.Errorf("RouterIDs = %v, want [alpha zeta]", ids)
	}
}

func TestStore_PersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "queue.json")

	s1, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	id, err := s1.Enqueue("router-1", ActionStatus, nil)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := s1.RecordResult("router-2", Result{CommandID: "other", Output: "hi"}); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}

	s2, err := LoadStore(path)
	if err != nil {
		t.Fatalf("reload LoadStore: %v", err)
	}
	cmd, err := s2.Dequeue("router-1")
	if err != nil {
		t.Fatalf("Dequeue after reload: %v", err)
	}
	if cmd == nil || cmd.ID != id {
		t.Errorf("Dequeue after reload = %+v, want ID=%s", cmd, id)
	}
	if r := s2.LastResult("router-2"); r == nil || r.CommandID != "other" {
		t.Errorf("LastResult after reload = %+v, want CommandID=other", r)
	}
}

func TestStore_LoadStoreMissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	s, err := LoadStore(path)
	if err != nil {
		t.Fatalf("LoadStore on missing file: %v", err)
	}
	if len(s.RouterIDs()) != 0 {
		t.Errorf("fresh store should have no routers, got %v", s.RouterIDs())
	}
}

func TestStore_AwaitResult_ReturnsImmediatelyIfAlreadyPresent(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if err := s.RecordResult("router-1", Result{CommandID: "abc", Output: "ok"}); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}

	start := time.Now()
	result, ok := s.AwaitResult(context.Background(), "router-1", "abc", time.Second)
	if !ok || result == nil || result.Output != "ok" {
		t.Fatalf("AwaitResult = %+v, %v, want ok=true Output=ok", result, ok)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("AwaitResult took %v for an already-present result, want near-instant", elapsed)
	}
}

func TestStore_AwaitResult_SeesLaterResult(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = s.RecordResult("router-1", Result{CommandID: "target", Output: "eventually"})
	}()

	result, ok := s.AwaitResult(context.Background(), "router-1", "target", 2*time.Second)
	if !ok || result == nil || result.Output != "eventually" {
		t.Fatalf("AwaitResult = %+v, %v, want ok=true Output=eventually", result, ok)
	}
}

func TestStore_AwaitResult_TimesOut(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	result, ok := s.AwaitResult(context.Background(), "router-1", "never-comes", 100*time.Millisecond)
	if ok || result != nil {
		t.Errorf("AwaitResult = %+v, %v, want ok=false nil on timeout", result, ok)
	}
}

func TestStore_AwaitResult_IgnoresMismatchedCommandID(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	if err := s.RecordResult("router-1", Result{CommandID: "stale", Output: "old"}); err != nil {
		t.Fatalf("RecordResult: %v", err)
	}
	result, ok := s.AwaitResult(context.Background(), "router-1", "fresh", 100*time.Millisecond)
	if ok || result != nil {
		t.Errorf("AwaitResult = %+v, %v, want ok=false (stale result must not match)", result, ok)
	}
}

func TestStore_AwaitResult_ContextCancelled(t *testing.T) {
	s, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, ok := s.AwaitResult(ctx, "router-1", "id", time.Second)
	if ok || result != nil {
		t.Errorf("AwaitResult with cancelled context = %+v, %v, want ok=false", result, ok)
	}
}
