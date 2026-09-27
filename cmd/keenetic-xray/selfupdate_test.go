package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/selfupdate"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

func drainOne(t *testing.T, ch <-chan botcontrol.Event) (botcontrol.Event, bool) {
	t.Helper()
	select {
	case ev, ok := <-ch:
		return ev, ok
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for watchPostUpdate to finish")
		return botcontrol.Event{}, false
	}
}

func fixedState(st failover.State) steadyStateFn {
	return func(context.Context) (failover.State, bool) { return st, true }
}

// probeOK/probeFail stand in for watchPostUpdate's real xrayctl.Probe-based
// check in tests that don't need a real SOCKS listener.
func probeOK(context.Context) error   { return nil }
func probeFail(context.Context) error { return errProbeUnreachable }

var errProbeUnreachable = errors.New("probe: connection refused")

func TestWatchPostUpdate_NoMarker(t *testing.T) {
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown), probeOK,
		filepath.Join(t.TempDir(), "none.json"), out, func(string, ...any) {})
	if _, ok := <-out; ok {
		t.Error("no marker -> no event, channel just closes")
	}
}

func TestWatchPostUpdate_Healthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "self-update.json")
	if err := selfupdate.WriteMarker(path, selfupdate.Marker{
		PrevVersion: "0.26.6", IPKURL: "https://h/x.ipk", Arch: "aarch64-3.10", StartedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateActivePrimary), probeOK, path, out, func(string, ...any) {})

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "✅") || !strings.Contains(ev.Text, "0.26.6") {
		t.Errorf("want a ✅ confirmation event, got %+v ok=%v", ev, ok)
	}
	if _, present := selfupdate.ReadMarker(path); present {
		t.Error("marker should be cleared once the daemon is confirmed up")
	}
}

func TestWatchPostUpdate_Unhealthy_KeepsMarkerAndWarns(t *testing.T) {
	defer func(w, p time.Duration) { postUpdateWindow, postUpdatePoll = w, p }(postUpdateWindow, postUpdatePoll)
	postUpdateWindow, postUpdatePoll = 40*time.Millisecond, 10*time.Millisecond

	path := filepath.Join(t.TempDir(), "self-update.json")
	_ = selfupdate.WriteMarker(path, selfupdate.Marker{
		PrevVersion: "0.26.6", IPKURL: "https://h/x.ipk", Arch: "aarch64-3.10", StartedAt: time.Now(),
	})
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown), probeOK, path, out, func(string, ...any) {})

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "⚠️") || !strings.Contains(ev.Text, "self-rollback") {
		t.Errorf("want a ⚠️ warning naming the rollback command, got %+v", ev)
	}
	if _, present := selfupdate.ReadMarker(path); !present {
		t.Error("marker must be kept so `internal self-rollback` can use it")
	}
}

// TestWatchPostUpdate_StateSaysActiveButProbeNeverPasses_KeepsMarkerAndWarns
// is the regression test for the actual gap found by the 2026-09-20 audit:
// State() alone can report a false ActivePrimary indefinitely (most
// concretely in a single-profile setup, which runs with no health-check
// ticker at all -- if the very first SwitchLiveTo at daemon startup
// silently failed, nothing ever re-evaluates the Machine's state again).
// A state that never leaves ActivePrimary must NOT be declared healthy
// while the independent probe keeps failing.
func TestWatchPostUpdate_StateSaysActiveButProbeNeverPasses_KeepsMarkerAndWarns(t *testing.T) {
	defer func(w, p time.Duration) { postUpdateWindow, postUpdatePoll = w, p }(postUpdateWindow, postUpdatePoll)
	postUpdateWindow, postUpdatePoll = 40*time.Millisecond, 10*time.Millisecond

	path := filepath.Join(t.TempDir(), "self-update.json")
	_ = selfupdate.WriteMarker(path, selfupdate.Marker{
		PrevVersion: "0.26.6", IPKURL: "https://h/x.ipk", Arch: "aarch64-3.10", StartedAt: time.Now(),
	})
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateActivePrimary), probeFail, path, out, func(string, ...any) {})

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "⚠️") || !strings.Contains(ev.Text, "self-rollback") {
		t.Errorf("want a ⚠️ warning despite State()==ActivePrimary, got %+v ok=%v", ev, ok)
	}
	if _, present := selfupdate.ReadMarker(path); !present {
		t.Error("marker must be kept -- a state that never leaves ActivePrimary must not clear it")
	}
}

// TestWatchPostUpdate_SameVersionReinstall_NotifiesAndClears covers the
// third UPD-02 gap: before this, a same-version reinstall's marker was
// silently cleared with no event at all, indistinguishable from the
// marker just having gotten lost -- real work happened (opkg genuinely
// reinstalled, the daemon genuinely restarted) and deserves its own
// confirmation, distinct from the stale-leftover case.
func TestWatchPostUpdate_SameVersionReinstall_NotifiesAndClears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "self-update.json")
	_ = selfupdate.WriteMarker(path, selfupdate.Marker{
		PrevVersion: trimV(version.Version), IPKURL: "https://h/x.ipk", Arch: "aarch64-3.10", StartedAt: time.Now(),
	})
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateActivePrimary), probeOK, path, out, func(string, ...any) {})

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "переустановка") || !strings.Contains(ev.Text, trimV(version.Version)) {
		t.Errorf("want a same-version reinstall confirmation, got %+v ok=%v", ev, ok)
	}
	if _, present := selfupdate.ReadMarker(path); present {
		t.Error("marker should be cleared after a confirmed same-version reinstall")
	}
}

func TestMarkerIsFreshForRollback(t *testing.T) {
	fresh := selfupdate.Marker{PrevVersion: "0.26.6", StartedAt: time.Now()}
	if !markerIsFreshForRollback(fresh, true, "0.31.7") {
		t.Error("a fresh marker for a different version should count as fresh")
	}
	if markerIsFreshForRollback(selfupdate.Marker{}, false, "0.31.7") {
		t.Error("no marker at all should never count as fresh")
	}
	stale := selfupdate.Marker{PrevVersion: "0.26.6", StartedAt: time.Now().Add(-30 * time.Minute)}
	if markerIsFreshForRollback(stale, true, "0.31.7") {
		t.Error("a marker older than autoRollbackMarkerWindow should not count as fresh")
	}
	alreadyBack := selfupdate.Marker{PrevVersion: "0.31.7", StartedAt: time.Now()}
	if markerIsFreshForRollback(alreadyBack, true, "0.31.7") {
		t.Error("a marker whose PrevVersion already matches the running version should not count as fresh")
	}
}

func TestWatchAutoRollbackNotice_NoNotice(t *testing.T) {
	t.Setenv("KEENETIC_XRAY_AUTOROLLBACK_NOTICE", filepath.Join(t.TempDir(), "none.json"))
	out := make(chan botcontrol.Event, 1)
	watchAutoRollbackNotice(context.Background(), out)
	if _, ok := <-out; ok {
		t.Error("no notice file -> no event, channel just closes")
	}
}

func TestWatchAutoRollbackNotice_SendsEventAndClearsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auto-rollback-notice.json")
	t.Setenv("KEENETIC_XRAY_AUTOROLLBACK_NOTICE", path)
	if err := writeAutoRollbackNotice("0.32.0", "0.31.7"); err != nil {
		t.Fatal(err)
	}

	out := make(chan botcontrol.Event, 1)
	watchAutoRollbackNotice(context.Background(), out)

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "0.32.0") || !strings.Contains(ev.Text, "0.31.7") {
		t.Errorf("want an event naming both versions, got %+v ok=%v", ev, ok)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("notice file should be removed once consumed")
	}
}

func TestWatchAutoRollbackNotice_MalformedFileIsSilentlyDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auto-rollback-notice.json")
	t.Setenv("KEENETIC_XRAY_AUTOROLLBACK_NOTICE", path)
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := make(chan botcontrol.Event, 1)
	watchAutoRollbackNotice(context.Background(), out)
	if _, ok := <-out; ok {
		t.Error("malformed notice -> no event")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("malformed notice file should still be removed, not reprocessed forever")
	}
}

func TestWatchPostUpdate_StaleMarkerTidiedSilently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "self-update.json")
	_ = selfupdate.WriteMarker(path, selfupdate.Marker{
		PrevVersion: "0.26.6", IPKURL: "https://h/x.ipk", Arch: "aarch64-3.10",
		StartedAt: time.Now().Add(-30 * time.Minute),
	})
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown), probeOK, path, out, func(string, ...any) {})

	if _, ok := <-out; ok {
		t.Error("a stale marker should be tidied without an event")
	}
	if _, present := selfupdate.ReadMarker(path); present {
		t.Error("stale marker should be cleared")
	}
}

// stubWatchdog replaces decideWatchdog's view of the system: alive and
// opkg answer successive calls from the given sequences (the last value
// repeats), and the confirmation pause is recorded instead of slept.
func stubWatchdog(t *testing.T, alive, opkg []bool) (slept *bool) {
	t.Helper()
	next := func(seq []bool) func() bool {
		i := 0
		return func() bool {
			v := seq[min(i, len(seq)-1)]
			i++
			return v
		}
	}
	origAlive, origOpkg, origSleep := watchdogDaemonAlive, watchdogOpkgBusy, watchdogSleep
	t.Cleanup(func() { watchdogDaemonAlive, watchdogOpkgBusy, watchdogSleep = origAlive, origOpkg, origSleep })
	var s bool
	watchdogDaemonAlive, watchdogOpkgBusy = next(alive), next(opkg)
	watchdogSleep = func(time.Duration) { s = true }
	return &s
}

// TestDecideWatchdog is N1 (2026-09-27 external review): the hook used
// to trust the cron script's "daemon down" -- which was always wrong,
// since the rc.func-based init script had no `status` -- and inside the
// rollback window after an update it rolled back a healthy new version.
func TestDecideWatchdog(t *testing.T) {
	cases := []struct {
		name       string
		alive      []bool
		opkg       []bool
		fresh      bool
		want       watchdogAction
		wantPaused bool
	}{
		{"daemon actually running, fresh marker", []bool{true}, []bool{false}, true, watchdogLeaveAlone, false},
		{"daemon actually running, no marker", []bool{true}, []bool{false}, false, watchdogLeaveAlone, false},
		{"opkg mid-install", []bool{false}, []bool{true}, true, watchdogLeaveAlone, false},
		{"down, no marker: plain restart", []bool{false}, []bool{false}, false, watchdogStart, false},
		{"down twice with a fresh marker: rollback", []bool{false, false}, []bool{false}, true, watchdogRollback, true},
		{"came up while confirming", []bool{false, true}, []bool{false}, true, watchdogLeaveAlone, true},
		{"opkg started while confirming", []bool{false, false}, []bool{false, true}, true, watchdogLeaveAlone, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slept := stubWatchdog(t, c.alive, c.opkg)
			got, why := decideWatchdog(c.fresh)
			if got != c.want {
				t.Errorf("got %v (%s), want %v", got, why, c.want)
			}
			if *slept != c.wantPaused {
				t.Errorf("paused to confirm = %v, want %v", *slept, c.wantPaused)
			}
		})
	}
}
