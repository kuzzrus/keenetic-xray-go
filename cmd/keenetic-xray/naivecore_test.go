package main

import (
	"path/filepath"
	"testing"
)

// TestCmdEnsureNaiveCore_Dispatched confirms `internal ensure-naive-core`
// is wired through to naivecore.Ensure (Dest/BaseURL follow the env
// overrides) -- the fetch/verify/smoke logic itself is naivecore's own
// test suite's job, not this CLI wrapper's.
func TestCmdEnsureNaiveCore_Dispatched(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEENETIC_XRAY_NAIVE_BINARY", filepath.Join(dir, "naive"))
	// Dead address so the fetch fails fast and deterministically instead
	// of hitting the real release URL from a test.
	t.Setenv("KEENETIC_XRAY_NAIVE_BASE_URL", "http://127.0.0.1:0")

	if err := run([]string{"internal", "ensure-naive-core"}); err == nil {
		t.Error("expected an error when naive can't be fetched from an unreachable BaseURL")
	}
	// --force must parse without error (it only flips a bool; the actual
	// force-reinstall behavior is naivecore.TestEnsure_ForceReinstallsOverRunningBinary).
	if err := run([]string{"internal", "ensure-naive-core", "--force"}); err == nil {
		t.Error("expected an error when naive can't be fetched (--force still needs a reachable BaseURL)")
	}
}
