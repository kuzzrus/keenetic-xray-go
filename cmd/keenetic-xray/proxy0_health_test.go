package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// errRefused stands in for the router answering a command with an error
// -- not keenetic.Transient.
var errRefused = errors.New(`ndmc "ping-check profile kxray mode tls": exit status 1`)

func quiet(string, ...any) {}

// TestProxy0HealthState_BacksOffAfterRefusal: an attempt the router
// refused must not repeat on every 2-minute reconcile tick -- each one
// that gets past the read ends in `system configuration save`, a flash
// write.
func TestProxy0HealthState_BacksOffAfterRefusal(t *testing.T) {
	var s proxy0HealthState
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	if !s.due(now) {
		t.Fatal("a fresh state must be due")
	}
	if s.failed(now, errRefused, false, quiet) {
		t.Error("a refused command asked to be retried soon")
	}
	if s.due(now.Add(reconcileInterval)) {
		t.Error("retried on the very next reconcile tick after a refusal")
	}
	if !s.due(now.Add(proxy0HealthRetryAfter)) {
		t.Error("never retried once proxy0HealthRetryAfter passed")
	}
	s.succeeded()
	if !s.due(now) {
		t.Error("a success must clear the backoff")
	}
}

// TestProxy0HealthState_TransientRetriesSoon is BOOT-05: a router that
// didn't answer in time, or couldn't save, is retried within seconds --
// by the retrier, with reconcile keeping out of its way meanwhile -- not
// after an hour.
func TestProxy0HealthState_TransientRetriesSoon(t *testing.T) {
	var s proxy0HealthState
	now := time.Now()
	for _, err := range []error{
		fmt.Errorf("reading Proxy0: %w", context.DeadlineExceeded),
		fmt.Errorf("%w: busy", keenetic.ErrNotSaved),
	} {
		if !s.failed(now, err, false, quiet) {
			t.Errorf("failed(%v) = false, want a quick retry", err)
		}
		if !s.due(now) {
			t.Errorf("after %v: not due, want no hour-long backoff", err)
		}
	}

	release := make(chan struct{})
	started := make(chan struct{})
	s.startRetry(func() { close(started); <-release })
	<-started
	if s.due(now) {
		t.Error("due while the retrier runs -- reconcile would race it")
	}
	s.startRetry(func() { t.Error("a second retrier started while one runs") })
	close(release)
	waitFor(t, func() bool { return s.due(now) })
}

// TestProxy0HealthState_SavesAfterAnUnsavedChange: an attempt that
// changed the check and then failed (the save, or the read-back before
// it) may leave it bound but unsaved. The next attempt finds nothing to
// change, so it must save regardless -- or a reboot before the USB
// mounts, exactly when the check matters, would come up without it.
func TestProxy0HealthState_SavesAfterAnUnsavedChange(t *testing.T) {
	var s proxy0HealthState
	s.failed(time.Now(), errRefused, false, quiet)
	if s.needsSave() {
		t.Error("an attempt that changed nothing left a save pending")
	}
	s.failed(time.Now(), fmt.Errorf("%w: busy", keenetic.ErrNotSaved), true, quiet)
	if !s.needsSave() {
		t.Fatal("a changed-but-failed attempt did not leave a save pending")
	}
	s.succeeded()
	if s.needsSave() {
		t.Error("a success left a save pending")
	}
}

// TestProxy0HealthState_LogsAFailureOnce: a retrier failing the same way
// every minute must not fill daemon.log.
func TestProxy0HealthState_LogsAFailureOnce(t *testing.T) {
	var s proxy0HealthState
	var lines int
	logf := func(string, ...any) { lines++ }
	for range 3 {
		s.failed(time.Now(), context.DeadlineExceeded, false, logf)
	}
	if lines != 1 {
		t.Errorf("logged %d lines for three identical failures, want 1", lines)
	}
	s.failed(time.Now(), errRefused, false, logf)
	if lines != 2 {
		t.Error("a different failure was not logged")
	}
	if !s.succeeded() {
		t.Error("succeeded after a failure must report the recovery")
	}
	if s.succeeded() {
		t.Error("a second success reported a recovery")
	}
}

func TestProxy0HealthState_UnsupportedFirmwareStopsForGood(t *testing.T) {
	s := proxy0HealthState{unsupported: true}
	if s.due(time.Now().Add(100 * proxy0HealthRetryAfter)) {
		t.Error("firmware without tls must never be retried within a run")
	}
}

func TestProxy0HealthRetryAfter_WellAboveReconcileInterval(t *testing.T) {
	if proxy0HealthRetryAfter < 10*reconcileInterval {
		t.Errorf("proxy0HealthRetryAfter = %v is too close to reconcileInterval = %v", proxy0HealthRetryAfter, reconcileInterval)
	}
	if proxy0HealthRetryMax >= reconcileInterval {
		t.Errorf("proxy0HealthRetryMax = %v, want quicker than reconcile's own %v", proxy0HealthRetryMax, reconcileInterval)
	}
}

// TestRetryProxy0HealthCheck_UntilSettled: the retrier keeps going while
// attempts ask for it and stops at the first that doesn't.
func TestRetryProxy0HealthCheck_UntilSettled(t *testing.T) {
	shrinkProxy0HealthRetry(t)
	attempts := 0
	retryProxy0HealthCheck(context.Background(), func(context.Context) bool {
		attempts++
		return attempts < 4
	})
	if attempts != 4 {
		t.Fatalf("%d attempts, want 4 (three retry-soon, then settled)", attempts)
	}
}

func TestRetryProxy0HealthCheck_StopsWithTheDaemon(t *testing.T) {
	shrinkProxy0HealthRetry(t)
	ctx, cancel := context.WithCancel(context.Background())
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		retryProxy0HealthCheck(ctx, func(context.Context) bool {
			n.Add(1)
			return true // never settles
		})
	}()
	waitFor(t, func() bool { return n.Load() >= 2 })
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("retrier kept running after ctx was cancelled")
	}
}

func shrinkProxy0HealthRetry(t *testing.T) {
	t.Helper()
	lo, hi := proxy0HealthRetryMin, proxy0HealthRetryMax
	proxy0HealthRetryMin, proxy0HealthRetryMax = time.Millisecond, 8*time.Millisecond
	t.Cleanup(func() { proxy0HealthRetryMin, proxy0HealthRetryMax = lo, hi })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 2s")
		}
		time.Sleep(time.Millisecond)
	}
}
