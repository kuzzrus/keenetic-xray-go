package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/selfupdate"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// postUpdateProbe builds watchPostUpdate's independent liveness check: a
// real HTTP GET through the production SOCKS inbound, same target/
// fallback/retry config the failover daemon's own health checks already
// use (see cmd/keenetic-xray/adaptiveroute.go's adaptiveRouteHealthCheck
// for the identical pattern). A single attempt per call -- watchPostUpdate
// itself is what retries, on its own postUpdatePoll cadence.
//
// The Failover fields cfg points at are read once, here, synchronously --
// not from inside the returned closure, which watchPostUpdate calls
// repeatedly on its own goroutine over the post-update window (up to
// postUpdateWindow). cfg is the same *config.Config the daemon holds, so
// re-reading it on every probe would race a concurrent bot-triggered
// mutation or Daemon.ReloadConfig (CFG-01); this closure only ever cares
// about the config as of the moment the self-update that triggered it
// completed, so a one-time snapshot is the correct behavior, not just the
// safe one.
func postUpdateProbe(cfg *config.Config) func(context.Context) error {
	opts := xrayctl.ProbeOptions{
		SOCKSAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.Failover.SOCKSPort),
		URL:          cfg.Failover.HealthCheckURL,
		FallbackURLs: cfg.Failover.HealthCheckFallbackURLs,
		Retries:      cfg.Failover.CheckRetries,
		RetryDelay:   time.Duration(cfg.Failover.CheckRetryDelaySeconds) * time.Second,
		Timeout:      8 * time.Second,
	}
	return func(ctx context.Context) error {
		pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		return xrayctl.Probe(pctx, opts)
	}
}

// postUpdateWindow is how long the daemon waits for itself to reach a
// steady state after a self-update before declaring the update bad.
// postUpdatePoll is the gap between checks. Both overridden in tests.
var (
	postUpdateWindow = 2 * time.Minute
	postUpdatePoll   = 10 * time.Second
)

// steadyStateFn reports the failover machine's current state; d.State.
type steadyStateFn func(context.Context) (failover.State, bool)

// watchPostUpdate runs once at daemon startup. If a self-update marker is
// present and fresh, it waits for the daemon to reach ActivePrimary/
// ActiveBackup *and* pass an independent live probe within
// postUpdateWindow, and emits a single event either way: a confirmation
// (marker cleared), or a loud "didn't come up -- откат: keenetic-xray
// internal self-rollback" (marker kept so the command can use it).
// Closes out when done.
//
// The probe matters on its own, not just as a slower way to confirm what
// state already says: State() alone was found (2026-09-20 audit) to be
// able to report a false ActivePrimary indefinitely in a single-profile
// setup (no backup configured) -- that mode runs with no health-check
// ticker at all (see internal/failover's own doc comment), so if the
// *very first* SwitchLiveTo at daemon startup silently failed (its error
// is deliberately not fatal to Run -- FAIL-02, still open), nothing ever
// re-evaluates the Machine's state again, and it just sits at its
// initial ActivePrimary value forever with no working xray process
// behind it at all. A real probe through the actual SOCKS/HTTP inbound
// can't be fooled by that.
func watchPostUpdate(ctx context.Context, state steadyStateFn, probe func(context.Context) error, markerPath string, out chan<- botcontrol.Event, logf func(string, ...any)) {
	defer close(out)

	m, ok := selfupdate.ReadMarker(markerPath)
	if !ok {
		return
	}
	// A leftover from something else entirely (this build somehow didn't
	// swap, or the marker is just old) -- don't nag about it, just tidy up.
	if time.Since(m.StartedAt) > 15*time.Minute {
		_ = selfupdate.ClearMarker(markerPath)
		return
	}
	// A fresh marker whose PrevVersion already matches what's running:
	// a same-version reinstall (`update` re-run with nothing new to
	// install). Real work happened -- opkg genuinely reinstalled and
	// restarted the daemon -- so this gets its own confirmation instead
	// of silently vanishing the way a stale leftover does; before this,
	// the operator had no way to tell "reinstalled cleanly" apart from
	// "the marker just got lost" (2026-09-20 audit, UPD-02).
	if m.PrevVersion == trimV(version.Version) {
		_ = selfupdate.ClearMarker(markerPath)
		logf("post-update: переустановка версии %s завершена", trimV(version.Version))
		send(ctx, out, botcontrol.Event{
			Kind: "self_update",
			Text: fmt.Sprintf("✅ переустановка %s завершена", trimV(version.Version)),
			Time: time.Now(),
		})
		return
	}

	logf("post-update: слежу за переходом %s → %s (до %s)", m.PrevVersion, trimV(version.Version), postUpdateWindow)
	deadline := time.Now().Add(postUpdateWindow)
	for {
		if st, ran := state(ctx); ran && (st == failover.StateActivePrimary || st == failover.StateActiveBackup) {
			perr := probe(ctx)
			if perr == nil {
				_ = selfupdate.ClearMarker(markerPath)
				logf("post-update: демон в эфире (%s), живой пробник прошёл", st)
				send(ctx, out, botcontrol.Event{
					Kind: "self_update",
					Text: fmt.Sprintf("✅ обновление %s → %s: демон в эфире", m.PrevVersion, trimV(version.Version)),
					Time: time.Now(),
				})
				return
			}
			// A freshly-restarted xray may just need another moment to
			// actually start accepting connections -- same reasoning as
			// StateConfirmingRecovery not probing in the switching tick.
			// Keep polling rather than treating one failed probe as final.
			logf("post-update: состояние %s, но живой пробник пока не проходит (%v)", st, perr)
		}
		if !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(postUpdatePoll):
		}
	}

	logf("post-update: демон не вышел в эфир за %s после обновления до %s", postUpdateWindow, trimV(version.Version))
	send(ctx, out, botcontrol.Event{
		Kind: "self_update",
		Text: fmt.Sprintf("⚠️ обновление до %s: демон не вышел в эфир за %s.\nОткат:  keenetic-xray internal self-rollback", trimV(version.Version), postUpdateWindow),
		Time: time.Now(),
	})
	// Marker kept on purpose: `internal self-rollback` needs it.
}

func send(ctx context.Context, out chan<- botcontrol.Event, ev botcontrol.Event) {
	select {
	case out <- ev:
	case <-ctx.Done():
	}
}

func trimV(s string) string {
	if len(s) > 0 && s[0] == 'v' {
		return s[1:]
	}
	return s
}

// cmdSelfRollback reinstalls the .ipk recorded in the self-update marker
// -- the recovery path when an update left the daemon unable to start --
// then starts whatever is installed, the same way the watchdog hook does
// and for the same reason (see execInitStart).
func cmdSelfRollback(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: keenetic-xray internal self-rollback")
	}
	if err := runRollback(selfUpdateMarkerPath()); err != nil {
		fmt.Printf("откат не выполнен: %v\n", err)
	}
	return execInitStart("self-rollback")
}

// runRollback runs selfupdate.Rollback for both callers, the watchdog
// hook and `internal self-rollback`, with opkg's output kept in its own
// log file (rollbackLogPath).
//
// It also ignores the signals an init script's stop can send while opkg
// runs the package's prerm. The init script shipped since 2026-09-27
// stops only the verified daemon PID, but an rc.func-era one --
// possibly the very version being rolled back to, if a later step
// reinstalls it -- killed every process named keenetic-xray, this one
// included, mid-install (N2).
func runRollback(markerPath string) error {
	signal.Ignore(syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	defer signal.Reset(syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return selfupdate.Rollback(ctx, markerPath, selfupdate.RollbackOptions{
		OpkgLog: rollbackLogPath(),
		Log:     func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	})
}

// autoRollbackMarkerWindow mirrors watchPostUpdate's own 15-minute
// staleness check: a marker older than this (or already matching the
// currently-running version) isn't evidence of a live, still-unresolved
// update -- it's a leftover from something else, and a watchdog restart
// while it happens to still exist isn't this update's fault.
const autoRollbackMarkerWindow = 15 * time.Minute

// markerIsFreshForRollback decides whether a daemon restart happening
// right now, with marker m on disk, counts as evidence this specific
// update broke startup -- factored out of cmdWatchdogRestartHook so the
// decision itself (no I/O, no rollback attempt) is unit-testable on its
// own, mirroring watchPostUpdate's identical staleness reasoning: ok
// must be true (a marker exists at all), it must be no older than
// autoRollbackMarkerWindow, and its PrevVersion must actually differ
// from currentVersion -- if they already match, either a rollback (or
// the update itself) already landed and this marker is just stale
// leftover from a stage that's already resolved.
func markerIsFreshForRollback(m selfupdate.Marker, ok bool, currentVersion string) bool {
	return ok && time.Since(m.StartedAt) <= autoRollbackMarkerWindow && m.PrevVersion != currentVersion
}

// rollbackConfirmDelay is how long decideWatchdog waits before looking
// again when a fresh update marker would otherwise make it roll back. A
// daemon legitimately restarting -- self-update's own postinst, a config
// change -- looks dead for a few seconds, and a rollback is the one
// thing here that must never fire on a false alarm (N1).
var rollbackConfirmDelay = 20 * time.Second

// decideWatchdog's view of the system -- vars so its decision is testable
// without a router.
var (
	watchdogDaemonAlive = func() bool { _, err := runningDaemonPID(); return err == nil }
	watchdogOpkgBusy    = func() bool { return processNamed("opkg") }
	watchdogSleep       = time.Sleep
)

type watchdogAction int

const (
	watchdogLeaveAlone watchdogAction = iota
	watchdogStart
	watchdogRollback
)

// decideWatchdog decides what cmdWatchdogRestartHook does, checking for
// itself rather than trusting whoever called it.
//
// It used to trust the cron script's verdict outright -- and that
// verdict came from `S99keenetic-xray status`, which the rc.func-based
// init script didn't implement, so it said "down" on every tick (BOOT-02).
// Inside the rollback window after an update, a healthy new version was
// then rolled back (N1). Now: a daemon that is actually running (its own
// pidfile, verified) is left alone; so is anything while opkg runs,
// since an install in progress legitimately has the daemon stopped for a
// while; and a rollback needs the daemon found dead twice,
// rollbackConfirmDelay apart.
func decideWatchdog(markerFresh bool) (watchdogAction, string) {
	if watchdogDaemonAlive() {
		return watchdogLeaveAlone, "the daemon is running -- nothing to do"
	}
	if watchdogOpkgBusy() {
		return watchdogLeaveAlone, "opkg is running (an install or update in progress) -- not touching the daemon mid-way"
	}
	if !markerFresh {
		return watchdogStart, ""
	}
	watchdogSleep(rollbackConfirmDelay)
	if watchdogDaemonAlive() {
		return watchdogLeaveAlone, "the daemon came up while confirming -- no rollback"
	}
	if watchdogOpkgBusy() {
		return watchdogLeaveAlone, "opkg started while confirming -- no rollback"
	}
	return watchdogRollback, ""
}

// cmdWatchdogRestartHook is what the watchdog's cron script calls
// instead of a bare `<initScript> start` whenever it finds the daemon
// not running (see internal/install.writeWatchdogScript). If a
// self-update marker is present and fresh, the daemon being down right
// now is treated as evidence *this specific update* broke startup --
// rather than blindly restart the same broken build every 2 minutes
// forever, this rolls back to the version the marker recorded instead.
// Any other case -- no marker, a stale one, or the rollback attempt
// itself failing -- is an ordinary start, so a plain crash unrelated to
// any update is still just a plain restart, never a rollback. See
// decideWatchdog for when it does nothing at all.
//
// Runs as its own one-shot process spawned by cron, deliberately not as
// code inside the long-running daemon: if the new build is broken badly
// enough that it can never even start, there is no running daemon
// process left to notice or react -- the logic has to live somewhere
// that keeps working regardless of whether that specific binary can run
// at all, which a freshly separately-invoked `internal` subcommand is.
func cmdWatchdogRestartHook(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: keenetic-xray internal watchdog-restart-hook")
	}
	markerPath := selfUpdateMarkerPath()
	m, ok := selfupdate.ReadMarker(markerPath)

	action, why := decideWatchdog(markerIsFreshForRollback(m, ok, trimV(version.Version)))
	switch action {
	case watchdogLeaveAlone:
		fmt.Println("watchdog:", why)
		return nil
	case watchdogRollback:
		fmt.Printf("watchdog: daemon down with an unresolved update marker (%s -> %s, started %s ago) -- rolling back instead of restarting\n",
			m.PrevVersion, trimV(version.Version), time.Since(m.StartedAt).Round(time.Second))
		if err := runRollback(markerPath); err != nil {
			fmt.Printf("watchdog: auto-rollback failed (%v) -- starting whatever is installed now\n", err)
		} else if nerr := writeAutoRollbackNotice(trimV(version.Version), m.PrevVersion); nerr != nil {
			fmt.Printf("watchdog: rollback succeeded but couldn't record a notice for the next boot: %v\n", nerr)
		}
	}
	// Both an ordinary restart and the end of a rollback land here. The
	// rolled-back package's postinst has usually started the daemon
	// already, and then this is a harmless "already running".
	return execInitStart("watchdog")
}

// processNamed reports whether any running process's /proc/<pid>/comm
// is name. False wherever /proc isn't there (off Linux).
func processNamed(name string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, err := os.ReadFile("/proc/" + e.Name() + "/comm"); err == nil && strings.TrimSpace(string(b)) == name {
			return true
		}
	}
	return false
}

// autoRollbackNotice is what cmdWatchdogRestartHook leaves behind after a
// successful auto-rollback -- Rollback itself already clears the
// self-update marker on success, so by the time the rolled-back build's
// own watchAutoRollbackNotice goroutine runs (next boot), the marker is
// long gone and can't be what carries this news forward.
type autoRollbackNotice struct {
	BadVersion   string    `json:"bad_version"`    // the update that broke startup and got rolled back
	RolledBackTo string    `json:"rolled_back_to"` // the version now running again
	At           time.Time `json:"at"`
}

func writeAutoRollbackNotice(badVersion, rolledBackTo string) error {
	b, err := json.Marshal(autoRollbackNotice{BadVersion: badVersion, RolledBackTo: rolledBackTo, At: time.Now()})
	if err != nil {
		return err
	}
	return os.WriteFile(autoRollbackNoticePath(), b, 0o644)
}

// watchAutoRollbackNotice runs once at daemon startup, the same shape as
// watchPostUpdate: if the watchdog had to auto-rollback a bad update
// before this process ever got a chance to run, tell the operator now
// instead of leaving it to be found by chance in the log. A missing or
// unreadable notice file is the common case (no rollback happened) and
// not an error -- just nothing to report.
func watchAutoRollbackNotice(ctx context.Context, out chan<- botcontrol.Event) {
	defer close(out)
	path := autoRollbackNoticePath()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	_ = os.Remove(path)
	var n autoRollbackNotice
	if json.Unmarshal(b, &n) != nil {
		return
	}
	send(ctx, out, botcontrol.Event{
		Kind: "self_update",
		Text: fmt.Sprintf("♻️ автоматический откат: обновление до %s не смогло запуститься, watchdog откатил обратно на %s", n.BadVersion, n.RolledBackTo),
		Time: time.Now(),
	})
}
