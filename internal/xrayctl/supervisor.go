// Package xrayctl runs and health-checks a local xray-core process:
// Supervisor keeps it alive (restarting with backoff on an unexpected
// exit), and Probe verifies the live proxy actually works end to end.
package xrayctl

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

const (
	DefaultBackoffMin = 1 * time.Second
	DefaultBackoffMax = 30 * time.Second
	killGracePeriod   = 5 * time.Second
)

// Supervisor runs a single xray-core process against a config file and
// keeps it running: if the process exits on its own (crash, killed by
// something else), Supervisor restarts it with exponential backoff that
// resets once a run has lasted at least BackoffMax. A deliberate Stop()
// does not trigger a restart.
//
// The same Supervisor type is used for both the production instance and
// the isolated recovery-pretest instance (internal/failover, M4) -- only
// BinaryPath/ConfigPath/Name differ between them.
type Supervisor struct {
	BinaryPath string
	ConfigPath string
	Name       string    // for logging, e.g. "production" or "pretest"
	Stderr     io.Writer // where the child's stderr goes; nil discards it
	Env        []string  // extra env vars for the child; nil inherits the parent's environment

	BackoffMin time.Duration // 0 -> DefaultBackoffMin
	BackoffMax time.Duration // 0 -> DefaultBackoffMax

	OnRestart func() // called once per crash-triggered restart (not on a deliberate Restart/Stop)

	mu      sync.Mutex
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	stopped chan struct{}
}

// Start launches the supervised process and returns once the first
// attempt has been made to launch it; restarts after that happen in the
// background until Stop is called. Start must not be called twice without
// an intervening Stop.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return fmt.Errorf("%s: already started", s.name())
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.stopped = make(chan struct{})
	stopped := s.stopped
	s.mu.Unlock()

	go s.superviseLoop(ctx, stopped)
	return nil
}

// Stop terminates the supervised process (SIGTERM, then SIGKILL if it
// doesn't exit within a grace period) and waits for supervision to fully
// stop. Safe to call even if Start was never called, and safe to call
// more than once.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	stopped := s.stopped
	s.cancel = nil
	s.mu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	<-stopped
}

// Restart is Stop followed by Start -- used when the config file changed
// and the process needs to pick it up, as opposed to an unexpected crash.
func (s *Supervisor) Restart() error {
	s.Stop()
	return s.Start()
}

// Running reports whether the supervised process is currently believed to
// be alive.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil
}

func (s *Supervisor) name() string {
	if s.Name != "" {
		return s.Name
	}
	return "xray"
}

func (s *Supervisor) superviseLoop(ctx context.Context, stopped chan struct{}) {
	defer close(stopped)

	backoff := s.backoffMin()
	for {
		start := time.Now()
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return // Stop was called
		}

		if time.Since(start) >= s.backoffMax() {
			backoff = s.backoffMin() // ran long enough to call it stable
		}
		fmt.Fprintf(s.stderrOrDiscard(), "%s: exited (%v), restarting in %v\n", s.name(), err, backoff)
		if s.OnRestart != nil {
			s.OnRestart()
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > s.backoffMax() {
			backoff = s.backoffMax()
		}
	}
}

func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.BinaryPath, "run", "-c", s.ConfigPath)
	cmd.Stderr = s.stderrOrDiscard()
	if s.Env != nil {
		cmd.Env = append(append([]string{}, os.Environ()...), s.Env...)
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = killGracePeriod

	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()

	err := cmd.Run()

	s.mu.Lock()
	s.cmd = nil
	s.mu.Unlock()

	return err
}

func (s *Supervisor) stderrOrDiscard() io.Writer {
	if s.Stderr != nil {
		return s.Stderr
	}
	return io.Discard
}

func (s *Supervisor) backoffMin() time.Duration {
	if s.BackoffMin > 0 {
		return s.BackoffMin
	}
	return DefaultBackoffMin
}

func (s *Supervisor) backoffMax() time.Duration {
	if s.BackoffMax > 0 {
		return s.BackoffMax
	}
	return DefaultBackoffMax
}
