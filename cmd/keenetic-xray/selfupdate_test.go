package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/selfupdate"
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

func TestWatchPostUpdate_NoMarker(t *testing.T) {
	out := make(chan botcontrol.Event, 1)
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown),
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
	watchPostUpdate(context.Background(), fixedState(failover.StateActivePrimary), path, out, func(string, ...any) {})

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
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown), path, out, func(string, ...any) {})

	ev, ok := drainOne(t, out)
	if !ok || !strings.Contains(ev.Text, "⚠️") || !strings.Contains(ev.Text, "self-rollback") {
		t.Errorf("want a ⚠️ warning naming the rollback command, got %+v", ev)
	}
	if _, present := selfupdate.ReadMarker(path); !present {
		t.Error("marker must be kept so `internal self-rollback` can use it")
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
	watchPostUpdate(context.Background(), fixedState(failover.StateCooldown), path, out, func(string, ...any) {})

	if _, ok := <-out; ok {
		t.Error("a stale marker should be tidied without an event")
	}
	if _, present := selfupdate.ReadMarker(path); present {
		t.Error("stale marker should be cleared")
	}
}
