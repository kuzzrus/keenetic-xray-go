package knownranges

import "testing"

func TestParse_LookupFindsContainingRange(t *testing.T) {
	table := Parse(`
# comment line, ignored
31.13.64.0/18
157.240.0.0/16

8.8.8.0/24
`)
	if got := table.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3", got)
	}

	cidr, ok := table.Lookup("31.13.72.1")
	if !ok || cidr != "31.13.64.0/18" {
		t.Fatalf("Lookup(31.13.72.1) = %q, %v, want 31.13.64.0/18, true", cidr, ok)
	}

	cidr, ok = table.Lookup("157.240.2.35")
	if !ok || cidr != "157.240.0.0/16" {
		t.Fatalf("Lookup(157.240.2.35) = %q, %v, want 157.240.0.0/16, true", cidr, ok)
	}
}

func TestParse_LookupNoMatch(t *testing.T) {
	table := Parse("8.8.8.0/24\n")
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup(1.2.3.4) matched, want no match")
	}
}

func TestParse_SkipsBlankCommentAndIPv6Lines(t *testing.T) {
	table := Parse("\n# header\n8.8.8.0/24\n2001:4860::/32\n\n")
	if got := table.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1 (IPv6 line should be skipped)", got)
	}
}

func TestParse_SkipsUnparseableLines(t *testing.T) {
	table := Parse("not-a-cidr\n8.8.8.0\n8.8.8.0/24\n")
	if got := table.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}

func TestParse_EmptyInput(t *testing.T) {
	table := Parse("")
	if got := table.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup on empty table matched, want no match")
	}
}

func TestTable_NilIsSafeAndEmpty(t *testing.T) {
	var table *Table
	if got := table.Len(); got != 0 {
		t.Fatalf("nil Table.Len() = %d, want 0", got)
	}
	if _, ok := table.Lookup("1.2.3.4"); ok {
		t.Fatal("nil Table.Lookup matched, want no match")
	}
}

func TestTable_LookupUnparseableIP(t *testing.T) {
	table := Parse("8.8.8.0/24\n")
	if _, ok := table.Lookup("not-an-ip"); ok {
		t.Fatal("Lookup(not-an-ip) matched, want no match")
	}
}

// resetCurrent restores the process-wide table to empty after a test
// that calls SetCurrent -- current is package state, shared across every
// test in this package.
func resetCurrent(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetCurrent(nil) })
}

func TestCurrent_NothingLoadedYet(t *testing.T) {
	resetCurrent(t)
	SetCurrent(nil)

	if got := CurrentLen(); got != 0 {
		t.Fatalf("CurrentLen() = %d, want 0", got)
	}
	if _, ok := Lookup("8.8.8.8"); ok {
		t.Fatal("Lookup with nothing loaded: want no match, got one")
	}
}

func TestCurrent_SetCurrentThenLookup(t *testing.T) {
	resetCurrent(t)
	SetCurrent(Parse("8.8.8.0/24\n"))

	if got := CurrentLen(); got != 1 {
		t.Fatalf("CurrentLen() = %d, want 1", got)
	}
	cidr, ok := Lookup("8.8.8.8")
	if !ok || cidr != "8.8.8.0/24" {
		t.Fatalf("Lookup(8.8.8.8) = %q, %v, want 8.8.8.0/24, true", cidr, ok)
	}
	if _, ok := Lookup("1.2.3.4"); ok {
		t.Fatal("Lookup(1.2.3.4): want no match against an unrelated table")
	}
}
