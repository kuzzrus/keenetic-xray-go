// Package failover implements the primary/backup VLESS failover state
// machine: fail away from primary on 3 consecutive live-probe failures,
// and fail back only after 3 consecutive successes against an isolated,
// zero-risk pretest instance plus a live confirmation check.
package failover

import (
	"context"
	"time"
)

// Role identifies which configured profile is meant.
type Role int

const (
	RolePrimary Role = iota
	RoleBackup
)

func (r Role) String() string {
	if r == RoleBackup {
		return "backup"
	}
	return "primary"
}

// State names the failover daemon's current phase.
type State int

const (
	// StateActivePrimary: primary is live; probing it directly.
	StateActivePrimary State = iota
	// StateActiveBackup: backup is live, not currently retrying recovery.
	// Reached either right after a failed recovery confirmation or by an
	// explicit operator switch to backup; either way a
	// RollbackBackoffSeconds timer must elapse before recovery testing
	// (re)starts.
	StateActiveBackup
	// StateTestingRecovery: backup is live; an isolated throwaway
	// instance is probing primary in the background.
	StateTestingRecovery
	// StateCooldown: transient, entered right after any switch; no new
	// switch is evaluated until it elapses.
	StateCooldown
)

func (s State) String() string {
	switch s {
	case StateActivePrimary:
		return "ACTIVE_PRIMARY"
	case StateActiveBackup:
		return "ACTIVE_BACKUP"
	case StateTestingRecovery:
		return "TESTING_RECOVERY"
	case StateCooldown:
		return "COOLDOWN"
	default:
		return "UNKNOWN"
	}
}

// Actions is everything the state machine needs the outside world to do.
// The machine itself never touches a process or the network directly --
// that's what keeps it deterministically unit-testable with a fake.
type Actions interface {
	// ProbeLive runs one health check against the currently-live production proxy.
	ProbeLive(ctx context.Context) error
	// ProbeIsolated runs one health check against the isolated recovery-pretest instance.
	ProbeIsolated(ctx context.Context) error
	// SwitchLiveTo points the production proxy at the given profile and restarts it.
	SwitchLiveTo(ctx context.Context, role Role) error
	// StartIsolatedPretest brings up the throwaway instance that tests primary.
	StartIsolatedPretest(ctx context.Context) error
	// StopIsolatedPretest tears the throwaway instance down.
	StopIsolatedPretest(ctx context.Context) error
}

// Clock abstracts time so tests can control it deterministically.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Config is the subset of config.FailoverConfig the state machine needs.
// Defined locally (rather than importing internal/config) so this package
// stays a leaf with no dependency on the config package's persistence
// concerns -- callers pass the numbers straight out of a loaded Config.
type Config struct {
	FailuresRequired          int
	RecoverySuccessesRequired int
	CooldownCycles            int
	RollbackBackoffSeconds    int
}

// Machine is the failover state machine. It holds no goroutine or timer of
// its own; a driver (Daemon, in daemon.go) calls Tick once per health-check
// interval.
type Machine struct {
	cfg     Config
	actions Actions
	clock   Clock

	state State

	consecutiveFailures int       // ActivePrimary: consecutive live-probe failures
	isolatedSuccesses   int       // TestingRecovery: consecutive isolated-probe successes
	cooldownRemaining   int       // Cooldown: ticks left
	cooldownNext        State     // Cooldown: state to enter once it elapses
	backoffUntil        time.Time // ActiveBackup: don't retry recovery testing before this

	onTransition func(from, to State) // nil, or a sink for state changes (Daemon records history + emits events); also used by tests
}

// NewMachine builds a Machine starting in the given state. A nil clock
// uses the real wall clock.
func NewMachine(cfg Config, actions Actions, clock Clock, initial State) *Machine {
	if clock == nil {
		clock = realClock{}
	}
	return &Machine{cfg: cfg, actions: actions, clock: clock, state: initial}
}

// State returns the machine's current phase.
func (m *Machine) State() State { return m.state }

// Tick evaluates one health-check interval's worth of state machine logic.
func (m *Machine) Tick(ctx context.Context) {
	switch m.state {
	case StateActivePrimary:
		m.tickActivePrimary(ctx)
	case StateActiveBackup:
		m.tickActiveBackup(ctx)
	case StateTestingRecovery:
		m.tickTestingRecovery(ctx)
	case StateCooldown:
		m.tickCooldown()
	}
}

func (m *Machine) tickActivePrimary(ctx context.Context) {
	if err := m.actions.ProbeLive(ctx); err != nil {
		m.consecutiveFailures++
		if m.consecutiveFailures < m.cfg.FailuresRequired {
			return
		}
		// No pre-test on this direction, deliberately: we're leaving a
		// known-bad path, so a pre-test would only double detection
		// latency for no safety benefit.
		m.consecutiveFailures = 0
		_ = m.actions.SwitchLiveTo(ctx, RoleBackup)
		_ = m.actions.StartIsolatedPretest(ctx)
		m.enterCooldown(StateTestingRecovery)
		return
	}
	m.consecutiveFailures = 0
}

func (m *Machine) tickActiveBackup(ctx context.Context) {
	if m.clock.Now().Before(m.backoffUntil) {
		return // still waiting out the post-rollback backoff
	}
	_ = m.actions.StartIsolatedPretest(ctx)
	m.isolatedSuccesses = 0
	m.transitionTo(StateTestingRecovery)
}

func (m *Machine) tickTestingRecovery(ctx context.Context) {
	if err := m.actions.ProbeIsolated(ctx); err != nil {
		m.isolatedSuccesses = 0
		return
	}
	m.isolatedSuccesses++
	if m.isolatedSuccesses < m.cfg.RecoverySuccessesRequired {
		return
	}
	m.isolatedSuccesses = 0

	if err := m.actions.SwitchLiveTo(ctx, RolePrimary); err != nil {
		return // couldn't even switch; try again next tick
	}
	_ = m.actions.StopIsolatedPretest(ctx)

	if err := m.actions.ProbeLive(ctx); err != nil {
		// Roll back immediately -- a known-good backup beats a flapping
		// primary -- then back off before hammering it with retries.
		_ = m.actions.SwitchLiveTo(ctx, RoleBackup)
		m.backoffUntil = m.clock.Now().Add(m.rollbackBackoff())
		m.transitionTo(StateActiveBackup)
		return
	}

	m.enterCooldown(StateActivePrimary)
}

func (m *Machine) tickCooldown() {
	m.cooldownRemaining--
	if m.cooldownRemaining <= 0 {
		m.transitionTo(m.cooldownNext)
	}
}

func (m *Machine) enterCooldown(next State) {
	m.cooldownRemaining = m.cfg.CooldownCycles
	m.cooldownNext = next
	m.transitionTo(StateCooldown)
	if m.cooldownRemaining <= 0 {
		m.transitionTo(next) // CooldownCycles configured as 0 -- skip immediately
	}
}

func (m *Machine) transitionTo(next State) {
	if m.state == next {
		return
	}
	prev := m.state
	m.state = next
	if m.onTransition != nil {
		m.onTransition(prev, next)
	}
}

func (m *Machine) rollbackBackoff() time.Duration {
	return time.Duration(m.cfg.RollbackBackoffSeconds) * time.Second
}

// forcePrimary handles an explicit operator command (CLI/bot) to run on
// primary now, bypassing the failure-counting logic. It clears the
// failure/success counters and any pending rollback backoff so nothing
// defers the switch.
func (m *Machine) forcePrimary() {
	m.consecutiveFailures = 0
	m.isolatedSuccesses = 0
	m.backoffUntil = time.Time{}
	m.transitionTo(StateActivePrimary)
}

// forceBackup handles an explicit operator command to run on backup now.
// Unlike forcePrimary it arms the rollback backoff (RollbackBackoffSeconds
// from now) rather than clearing it, so the next Tick doesn't immediately
// start probing primary for automatic recovery and undo a deliberate
// operator choice. Once the backoff elapses, normal auto-recovery resumes.
func (m *Machine) forceBackup() {
	m.consecutiveFailures = 0
	m.isolatedSuccesses = 0
	m.backoffUntil = m.clock.Now().Add(m.rollbackBackoff())
	m.transitionTo(StateActiveBackup)
}
