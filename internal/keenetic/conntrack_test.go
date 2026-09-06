package keenetic

import (
	"context"
	"testing"
)

func TestFlushConntrack(t *testing.T) {
	origRun, origPresent := conntrackRun, conntrackPresent
	t.Cleanup(func() { conntrackRun, conntrackPresent = origRun, origPresent })

	// Absent -> no-op, no error, no exec.
	conntrackPresent = func() bool { return false }
	var ran [][]string
	conntrackRun = func(_ context.Context, args ...string) error { ran = append(ran, args); return nil }
	if err := FlushConntrack(context.Background()); err != nil {
		t.Fatalf("FlushConntrack (absent) = %v, want nil", err)
	}
	if len(ran) != 0 {
		t.Errorf("ran %v with conntrack absent, want nothing", ran)
	}

	// Present -> runs `conntrack -F`.
	conntrackPresent = func() bool { return true }
	if err := FlushConntrack(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ran) != 1 || len(ran[0]) != 1 || ran[0][0] != "-F" {
		t.Errorf("ran %v, want a single [-F]", ran)
	}
}
