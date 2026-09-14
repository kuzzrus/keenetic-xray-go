package classifier

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadState_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now()

	s := NewState()
	s.Test[0].add("1.1.1.1", now, time.Hour)
	s.OK[1].add("2.2.2.2", now, time.Hour)
	s.Cooldown[0].add("3.3.3.3", now, time.Hour)
	s.Watch[0].add("4.4.4.4", now, time.Hour)     // deliberately not persisted
	s.Blocks[0].add("5.6.7.0/24", now, time.Hour) // deliberately not persisted -- rederived from OK

	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Test[0].has("1.1.1.1", now) {
		t.Error("test entry did not survive the roundtrip")
	}
	if !loaded.OK[1].has("2.2.2.2", now) {
		t.Error("ok entry did not survive the roundtrip")
	}
	if !loaded.Cooldown[0].has("3.3.3.3", now) {
		t.Error("cooldown entry did not survive the roundtrip")
	}
	if loaded.Watch[0].has("4.4.4.4", now) {
		t.Error("watch state should not be persisted")
	}
	if loaded.Blocks[0].has("5.6.7.0/24", now) {
		t.Error("blocks state should not be persisted")
	}
}

func TestLoadState_DropsExpiredEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	past := time.Now().Add(-time.Hour)

	s := NewState()
	s.OK[0].add("1.1.1.1", past, time.Second) // already expired by the time we save it
	if err := SaveState(path, s); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OK[0].has("1.1.1.1", time.Now()) {
		t.Error("an already-expired entry should not survive a load")
	}
}

func TestLoadState_MissingFileIsEmptyNotError(t *testing.T) {
	loaded, err := LoadState(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("missing state file should not be an error, got %v", err)
	}
	if loaded.OK[0].has("anything", time.Now()) {
		t.Error("expected an empty state")
	}
}
