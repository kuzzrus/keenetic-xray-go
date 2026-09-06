package applog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterTrimsAndTails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "daemon.log") // dir doesn't exist yet
	w, err := New(path, 2048)                               // small cap so trimming triggers
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	for i := 0; i < 400; i++ {
		if _, err := fmt.Fprintf(w, "line %04d filler-filler-filler\n", i); err != nil {
			t.Fatal(err)
		}
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 2048 {
		t.Errorf("file is %d bytes, should have been trimmed under the 2048 cap", fi.Size())
	}

	tail, err := Tail(path, 5)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(tail, "\n")
	if len(lines) != 5 {
		t.Fatalf("Tail(5) = %d lines:\n%s", len(lines), tail)
	}
	if !strings.Contains(lines[len(lines)-1], "line 0399") {
		t.Errorf("last line = %q, want the most recent write", lines[len(lines)-1])
	}
	// The first surviving line must be whole (trim cuts at a newline).
	if !strings.HasPrefix(strings.TrimSpace(lines[0]), "line ") {
		t.Errorf("first tail line looks truncated: %q", lines[0])
	}
}

func TestTailMissingFile(t *testing.T) {
	got, err := Tail(filepath.Join(t.TempDir(), "nope.log"), 10)
	if err != nil || got != "" {
		t.Errorf("Tail(missing) = (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestTeeNil(t *testing.T) {
	if _, err := fmt.Fprint(Tee(nil), "discarded"); err != nil {
		t.Errorf("Tee(nil) write errored: %v", err)
	}
}
