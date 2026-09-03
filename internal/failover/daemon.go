package failover

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// Paths are the filesystem locations the daemon reads/writes.
type Paths struct {
	XrayBinary       string
	ProductionConfig string
	PretestConfig    string
	Env              []string // extra env vars for the supervised xray-core processes; nil inherits the parent's environment (test hook, see xrayctl.Supervisor.Env)
}

// realActions implements Actions against real xray-core processes (via
// xrayctl.Supervisor) and real config files (via internal/config). It is
// the only piece of this package that touches a process or the network;
// Machine itself never does.
type realActions struct {
	paths Paths
	cfg   *config.Config
	socks string // "127.0.0.1:<SOCKSPort>", precomputed once

	prod    *xrayctl.Supervisor
	pretest *xrayctl.Supervisor

	liveRole Role // the role production was last successfully switched to
}

func newRealActions(paths Paths, cfg *config.Config) *realActions {
	return &realActions{
		paths: paths,
		cfg:   cfg,
		socks: fmt.Sprintf("127.0.0.1:%d", cfg.Failover.SOCKSPort),
		prod: &xrayctl.Supervisor{
			BinaryPath: paths.XrayBinary,
			ConfigPath: paths.ProductionConfig,
			Name:       "production",
			Env:        paths.Env,
		},
	}
}

func (a *realActions) ProbeLive(ctx context.Context) error {
	return xrayctl.Probe(ctx, xrayctl.ProbeOptions{
		SOCKSAddr: a.socks,
		URL:       a.cfg.Failover.HealthCheckURL,
		Timeout:   a.probeTimeout(),
	})
}

func (a *realActions) ProbeIsolated(ctx context.Context) error {
	return xrayctl.Probe(ctx, xrayctl.ProbeOptions{
		SOCKSAddr: fmt.Sprintf("127.0.0.1:%d", a.cfg.Failover.PretestPort),
		URL:       a.cfg.Failover.HealthCheckURL,
		Timeout:   a.probeTimeout(),
	})
}

func (a *realActions) probeTimeout() time.Duration {
	interval := time.Duration(a.cfg.Failover.CheckIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = time.Duration(config.DefaultFailoverConfig().CheckIntervalSeconds) * time.Second
	}
	return interval
}

func (a *realActions) SwitchLiveTo(ctx context.Context, role Role) error {
	profile := a.cfg.Primary()
	if role == RoleBackup {
		profile = a.cfg.Backup()
	}
	if profile == nil {
		return fmt.Errorf("no %s profile configured", role)
	}

	// When Proxy0 is enabled the production inbound must be reachable from
	// Keenetic's Proxy interface over the LAN, so bind all interfaces
	// rather than loopback. The pretest instance stays loopback-only.
	listen := ""
	if a.cfg.Proxy0.Enabled {
		listen = "0.0.0.0"
	}
	data, err := config.GenerateXrayConfig(config.XrayConfigOptions{
		SOCKSPort:  a.cfg.Failover.SOCKSPort,
		HTTPPort:   a.cfg.Failover.HTTPPort,
		ListenHost: listen,
		Outbound:   *profile,
	})
	if err != nil {
		return fmt.Errorf("generating production config: %w", err)
	}
	if err := os.WriteFile(a.paths.ProductionConfig, data, 0o600); err != nil {
		return fmt.Errorf("writing production config: %w", err)
	}

	if err := a.prod.Restart(); err != nil {
		return err
	}
	a.liveRole = role
	return nil
}

func (a *realActions) StartIsolatedPretest(ctx context.Context) error {
	primary := a.cfg.Primary()
	if primary == nil {
		return fmt.Errorf("no primary profile configured")
	}

	data, err := config.GenerateXrayConfig(config.XrayConfigOptions{
		SOCKSPort: a.cfg.Failover.PretestPort,
		Outbound:  *primary,
	})
	if err != nil {
		return fmt.Errorf("generating pretest config: %w", err)
	}
	if err := os.WriteFile(a.paths.PretestConfig, data, 0o600); err != nil {
		return fmt.Errorf("writing pretest config: %w", err)
	}

	if a.pretest != nil {
		a.pretest.Stop()
	}
	a.pretest = &xrayctl.Supervisor{
		BinaryPath: a.paths.XrayBinary,
		ConfigPath: a.paths.PretestConfig,
		Name:       "pretest",
		Env:        a.paths.Env,
	}
	return a.pretest.Start()
}

func (a *realActions) StopIsolatedPretest(ctx context.Context) error {
	if a.pretest != nil {
		a.pretest.Stop()
		a.pretest = nil
	}
	return nil
}

// Daemon drives a Machine on a real ticker, using real xray-core processes
// and config files. Subscription refresh is deliberately not wired in
// here -- it's CLI/bot-triggered, not something the core failover loop
// needs to own.
//
// Machine itself is not safe for concurrent use -- it's designed to be
// driven by a single goroutine (Run's own loop). External callers (the
// bot-control agent, running in its own goroutine) never touch it
// directly: ForceSwitch/State submit a closure on the commands channel
// and Run's select loop executes it in between ticks, so a command can
// never race with an in-flight Tick.
type Daemon struct {
	machine  *Machine
	actions  *realActions
	cfg      *config.Config
	commands chan daemonCommand

	startedAt   time.Time
	transitions []Transition // bounded history, oldest first; appended on the Run goroutine only
	events      chan Event   // buffered; non-blocking sends, dropped if full
}

// Transition is one recorded failover state change, for `status` output
// and push notifications.
type Transition struct {
	At   time.Time
	From State
	To   State
}

// EventKind tags a Daemon Event.
type EventKind int

const (
	// EventDaemonStart: Run has started and production is up on primary.
	EventDaemonStart EventKind = iota
	// EventFailover: the state machine changed phase (From -> To).
	EventFailover
)

// Event is a noteworthy daemon occurrence, for out-of-band notification
// (the bot DMs the operator). Rendering to human text is the consumer's
// job -- this package stays free of UX strings.
type Event struct {
	At   time.Time
	Kind EventKind
	From State // EventFailover
	To   State // EventFailover
}

// maxTransitions bounds the in-memory history: it feeds `status` output
// and push notifications, it is not an audit log.
const maxTransitions = 20

// eventBuffer is how many unconsumed events are held before new ones are
// dropped -- if nothing is draining Events() there is nobody to notify.
const eventBuffer = 16

type daemonCommand struct {
	fn   func(context.Context)
	done chan struct{}
}

// NewDaemon builds a Daemon wired to real components.
func NewDaemon(paths Paths, cfg *config.Config) *Daemon {
	actions := newRealActions(paths, cfg)
	machine := NewMachine(failoverConfig(cfg.Failover), actions, nil, StateActivePrimary)
	d := &Daemon{
		machine:   machine,
		actions:   actions,
		cfg:       cfg,
		commands:  make(chan daemonCommand),
		startedAt: time.Now(),
		events:    make(chan Event, eventBuffer),
	}
	// transitionTo runs only on the Run goroutine (via Tick) or on a
	// command closure (via ForceSwitch), both serialized by Run's select
	// loop -- the same goroutine Snapshot reads on, so the slice needs no
	// lock.
	machine.onTransition = d.recordTransition
	return d
}

func (d *Daemon) recordTransition(from, to State) {
	now := time.Now()
	d.transitions = append(d.transitions, Transition{At: now, From: from, To: to})
	if len(d.transitions) > maxTransitions {
		d.transitions = d.transitions[len(d.transitions)-maxTransitions:]
	}
	d.emit(Event{At: now, Kind: EventFailover, From: from, To: to})
}

// emit does a non-blocking send on the events channel -- a full buffer
// (nobody draining) drops the event rather than stalling the Run loop.
func (d *Daemon) emit(ev Event) {
	select {
	case d.events <- ev:
	default:
	}
}

// Events is a stream of noteworthy daemon occurrences for out-of-band
// notification. Buffered and lossy: an event is dropped if the consumer
// falls too far behind. Never closed; it stops producing when Run stops.
func (d *Daemon) Events() <-chan Event { return d.events }

// Snapshot is a consistent read of the daemon's observable state.
type Snapshot struct {
	State       State
	LiveRole    Role      // which profile production is pointed at (last successful SwitchLiveTo)
	StartedAt   time.Time // time.Since(StartedAt) is uptime
	Transitions []Transition
}

// Snapshot reads State, LiveRole, StartedAt and the transition history in
// one hop on the Run goroutine, so the fields can't disagree with each
// other. Like State, the bool is false if Run isn't active to answer.
func (d *Daemon) Snapshot(ctx context.Context) (Snapshot, bool) {
	var s Snapshot
	ran := d.do(ctx, func(context.Context) {
		s.State = d.machine.State()
		s.LiveRole = d.actions.liveRole
		s.StartedAt = d.startedAt
		s.Transitions = make([]Transition, len(d.transitions))
		copy(s.Transitions, d.transitions)
	})
	return s, ran
}

func failoverConfig(c config.FailoverConfig) Config {
	return Config{
		FailuresRequired:          c.FailuresRequired,
		RecoverySuccessesRequired: c.RecoverySuccessesRequired,
		CooldownCycles:            c.CooldownCycles,
		RollbackBackoffSeconds:    c.RollbackBackoffSeconds,
	}
}

// do runs fn on Run's own goroutine and waits for it to finish, returning
// false if ctx is done before Run picked it up (including if Run was
// never started, or has already returned). Safe to call from any
// goroutine.
func (d *Daemon) do(ctx context.Context, fn func(context.Context)) bool {
	done := make(chan struct{})
	select {
	case d.commands <- daemonCommand{fn: fn, done: done}:
	case <-ctx.Done():
		return false
	}
	select {
	case <-done:
		return true
	case <-ctx.Done():
		return false
	}
}

// State returns the daemon's current failover state. Safe to call
// concurrently with Run; the second return value is false if Run isn't
// currently active to answer.
func (d *Daemon) State(ctx context.Context) (State, bool) {
	var s State
	ran := d.do(ctx, func(context.Context) { s = d.machine.State() })
	return s, ran
}

// ForceSwitch immediately points production at role, bypassing the normal
// failure-counting logic -- for an explicit operator command (CLI/bot),
// not the automatic health-check loop. Switching to backup also arms the
// rollback backoff, so automatic recovery won't undo it on the next tick.
// Safe to call concurrently with Run.
func (d *Daemon) ForceSwitch(ctx context.Context, role Role) error {
	var switchErr error
	ran := d.do(ctx, func(ctx context.Context) {
		if switchErr = d.actions.SwitchLiveTo(ctx, role); switchErr != nil {
			return
		}
		if role == RolePrimary {
			_ = d.actions.StopIsolatedPretest(ctx)
			d.machine.forcePrimary()
		} else {
			d.machine.forceBackup()
		}
	})
	if !ran {
		return fmt.Errorf("failover: daemon is not running")
	}
	return switchErr
}

// Run starts the production xray-core process on primary and then drives
// the state machine's Tick once per CheckIntervalSeconds, and any
// commands submitted via do (ForceSwitch/State), until ctx is cancelled.
//
// If cfg has no primary/backup configured yet, Run idles instead of
// erroring out -- it logs a hint and waits for ctx to be cancelled. This
// matters because postinst starts the daemon via init.d immediately on
// install, before the user has ever had a chance to run `keenetic-xray
// setup`; erroring out here made that startup exit almost instantly,
// which made the init script's post-start "is it still running" check
// report failure and the whole opkg installation register as failed --
// confirmed on real hardware. There's no live config-reload here (the
// project has no CLI<->daemon IPC yet, a known, separately-documented
// gap): after running `setup`, the daemon needs a manual restart
// (`/opt/etc/init.d/S99keenetic-xray restart`) to pick up the new
// profiles.
func (d *Daemon) Run(ctx context.Context) error {
	if d.cfg.Primary() == nil || d.cfg.Backup() == nil {
		fmt.Println("failover: no primary/backup profiles configured yet -- run `keenetic-xray setup`, then restart this daemon")
		<-ctx.Done()
		return ctx.Err()
	}

	if err := d.actions.SwitchLiveTo(ctx, RolePrimary); err != nil {
		return fmt.Errorf("starting production instance: %w", err)
	}
	defer d.actions.prod.Stop()
	d.emit(Event{At: time.Now(), Kind: EventDaemonStart})

	ticker := time.NewTicker(d.actions.probeTimeout())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = d.actions.StopIsolatedPretest(ctx)
			return ctx.Err()
		case <-ticker.C:
			d.machine.Tick(ctx)
		case cmd := <-d.commands:
			cmd.fn(ctx)
			close(cmd.done)
		}
	}
}
