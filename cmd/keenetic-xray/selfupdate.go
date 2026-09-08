package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/selfupdate"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

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
// ActiveBackup within postUpdateWindow and emits a single event either
// way: a confirmation (marker cleared), or a loud "didn't come up --
// откат: keenetic-xray internal self-rollback" (marker kept so the
// command can use it). Closes out when done.
func watchPostUpdate(ctx context.Context, state steadyStateFn, markerPath string, out chan<- botcontrol.Event, logf func(string, ...any)) {
	defer close(out)

	m, ok := selfupdate.ReadMarker(markerPath)
	if !ok {
		return
	}
	// Not a fresh update we're supervising -- a leftover, or a build that
	// somehow didn't swap. Either way don't nag; just tidy up.
	if time.Since(m.StartedAt) > 15*time.Minute || m.PrevVersion == trimV(version.Version) {
		_ = selfupdate.ClearMarker(markerPath)
		return
	}

	logf("post-update: слежу за переходом %s → %s (до %s)", m.PrevVersion, trimV(version.Version), postUpdateWindow)
	deadline := time.Now().Add(postUpdateWindow)
	for {
		if st, ran := state(ctx); ran && (st == failover.StateActivePrimary || st == failover.StateActiveBackup) {
			_ = selfupdate.ClearMarker(markerPath)
			logf("post-update: демон в эфире (%s)", st)
			send(ctx, out, botcontrol.Event{
				Kind: "self_update",
				Text: fmt.Sprintf("✅ обновление %s → %s: демон в эфире", m.PrevVersion, trimV(version.Version)),
				Time: time.Now(),
			})
			return
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
// -- the recovery path when an update left the daemon unable to start.
func cmdSelfRollback(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: keenetic-xray internal self-rollback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return selfupdate.Rollback(ctx, selfUpdateMarkerPath(), selfupdate.RollbackOptions{
		Log: func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	})
}
