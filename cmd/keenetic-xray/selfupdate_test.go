package main

import (
	"context"
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
