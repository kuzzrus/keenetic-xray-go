package tungate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// scripted drives a Gate with canned check results and records what it did
// to the interface.
type scripted struct {
	mu      sync.Mutex
	results []error // consumed one per Probe; the last one repeats
	sets    []bool  // every Set call, in order
	setErr  error   // returned by Set while non-nil
	notes   []string
}

func (s *scripted) probe(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.results) == 0 {
		return nil
	}
	r := s.results[0]
	if len(s.results) > 1 {
		s.results = s.results[1:]
	}
	return r
}

func (s *scripted) set(_ context.Context, open bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sets = append(s.sets, open)
	return s.setErr
}

func (s *scripted) gate() *Gate {
	return &Gate{
		Probe: s.probe, Set: s.set,
		Notify: func(closed bool, detail string) {
			s.mu.Lock()
			defer s.mu.Unlock()
			state := "open"
			if closed {
				state = "closed"
			}
			s.notes = append(s.notes, state+": "+detail)
		},
	}
}

func (s *scripted) setCalls() []bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]bool(nil), s.sets...)
}

var (
	errDead = errors.New("таймаут")
	ctx     = context.Background()
)

// Three failed checks in a row close the gate -- not two -- and the first
// success opens it again.
func TestGate_ClosesAfterConsecutiveFailuresAndReopens(t *testing.T) {
	s := &scripted{results: []error{errDead, errDead, nil, errDead, errDead, errDead, errDead, nil}}
	g := s.gate()

	for i := 0; i < 2; i++ {
		g.Step(ctx)
	}
	if g.Closed() {
		t.Fatal("closed after two failures")
	}
	g.Step(ctx) // success: the count starts over
	g.Step(ctx)
	g.Step(ctx)
	if g.Closed() {
		t.Fatal("closed after two failures that followed a success")
	}
	g.Step(ctx) // third in a row
	closed, since, why := g.State()
	if !closed || since.IsZero() || why != "таймаут" {
		t.Fatalf("State = %v %v %q, want closed with the reason", closed, since, why)
	}
	if got := s.setCalls(); len(got) != 1 || got[0] != false {
		t.Fatalf("Set calls = %v, want one close", got)
	}

	g.Step(ctx) // still failing: no second Set
	if got := s.setCalls(); len(got) != 1 {
		t.Fatalf("a closed gate was closed again: %v", got)
	}
	g.Step(ctx) // success
	if g.Closed() {
		t.Fatal("still closed after the tunnel answered")
	}
	if got := s.setCalls(); len(got) != 2 || got[1] != true {
		t.Fatalf("Set calls = %v, want close then open", got)
	}
	if len(s.notes) != 2 || !strings.HasPrefix(s.notes[0], "closed: туннель не отвечает (3 проверок подряд: таймаут)") || !strings.HasPrefix(s.notes[1], "open:") {
		t.Errorf("notes = %q", s.notes)
	}
}

func TestGate_FailsToCloseIsConfigurable(t *testing.T) {
	s := &scripted{results: []error{errDead}}
	g := s.gate()
	g.FailsToClose = 5
	for i := 0; i < 4; i++ {
		g.Step(ctx)
	}
	if g.Closed() {
		t.Fatal("closed before FailsToClose")
	}
	g.Step(ctx)
	if !g.Closed() {
		t.Fatal("not closed at FailsToClose")
	}
}

// A refused Set changes nothing and is retried by the next check: closing
// keeps its failure count, opening keeps being asked for.
func TestGate_RetriesARefusedSet(t *testing.T) {
	s := &scripted{results: []error{errDead}, setErr: errors.New("ndm busy")}
	g := s.gate()
	var logged []string
	g.Logf = func(f string, a ...any) { logged = append(logged, f) }

	for i := 0; i < 3; i++ {
		g.Step(ctx)
	}
	if g.Closed() {
		t.Fatal("recorded a close the router refused")
	}
	s.mu.Lock()
	s.setErr = nil
	s.mu.Unlock()
	g.Step(ctx) // the 4th failure: still >= 3, so it tries again
	if !g.Closed() {
		t.Fatal("did not retry the close")
	}
	if len(logged) != 1 {
		t.Errorf("logged %d failures, want 1", len(logged))
	}

	// Now the open is refused once, then taken.
	s.mu.Lock()
	s.results, s.setErr = []error{nil}, errors.New("ndm busy")
	s.mu.Unlock()
	g.Step(ctx)
	if !g.Closed() {
		t.Fatal("recorded an open the router refused")
	}
	s.mu.Lock()
	s.setErr = nil
	s.mu.Unlock()
	g.Step(ctx)
	if g.Closed() {
		t.Fatal("did not retry the open")
	}
}

// ErrOff: the transport is off; a gate that was holding the interface lets
// go once, best effort, and never asks again. ErrSkip: no information.
func TestGate_OffAndSkip(t *testing.T) {
	s := &scripted{results: []error{errDead, errDead, errDead, ErrSkip, ErrSkip, ErrOff, ErrOff, ErrOff}}
	g := s.gate()
	for i := 0; i < 3; i++ {
		g.Step(ctx)
	}
	if !g.Closed() {
		t.Fatal("setup: gate not closed")
	}
	g.Step(ctx)
	g.Step(ctx) // skips change nothing
	if !g.Closed() {
		t.Fatal("a skipped check changed the gate")
	}
	s.mu.Lock()
	s.setErr = errors.New("no such interface") // it is gone already
	s.mu.Unlock()
	g.Step(ctx) // off
	if g.Closed() {
		t.Fatal("still closed after the transport was switched off")
	}
	before := len(s.setCalls())
	g.Step(ctx)
	g.Step(ctx)
	if got := len(s.setCalls()); got != before {
		t.Errorf("kept calling Set (%d -> %d) with the transport off", before, got)
	}
	if len(s.notes) != 1 {
		t.Errorf("notes = %q, want only the close (turning off needs no announcement)", s.notes)
	}
}

// Stopping the daemon must not leave the interface administratively down.
func TestGate_RunOpensOnShutdown(t *testing.T) {
	s := &scripted{results: []error{errDead}}
	g := s.gate()
	g.Interval = 5 * time.Millisecond
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(runCtx); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for !g.Closed() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !g.Closed() {
		t.Fatal("Run never closed the gate")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if g.Closed() {
		t.Error("gate left closed after shutdown")
	}
	calls := s.setCalls()
	if len(calls) < 2 || calls[len(calls)-1] != true {
		t.Errorf("Set calls = %v, want the last to be an open", calls)
	}
}

// State may be read from another goroutine (the bot) while Run steps.
func TestGate_StateIsRaceFree(t *testing.T) {
	s := &scripted{results: []error{errDead, errDead, errDead, nil}}
	g := s.gate()
	g.Interval = time.Millisecond
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { g.Run(runCtx); close(done) }()
	for i := 0; i < 200; i++ {
		g.State()
		g.Closed()
		time.Sleep(100 * time.Microsecond)
	}
	cancel()
	<-done
}
