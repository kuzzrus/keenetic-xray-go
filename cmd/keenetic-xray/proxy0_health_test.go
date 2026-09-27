package main

import (
	"testing"
	"time"
)

// TestProxy0HealthState_BacksOffAfterFailure: an attempt that fails must
// not repeat on every 2-minute reconcile tick -- each one that gets past
// the read ends in `system configuration save`, a flash write.
func TestProxy0HealthState_BacksOffAfterFailure(t *testing.T) {
	var s proxy0HealthState
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

	if !s.due(now) {
		t.Fatal("a fresh state must be due")
	}
	s.setFailed(now)
	if s.due(now.Add(reconcileInterval)) {
		t.Error("retried on the very next reconcile tick after a failure")
	}
	if !s.due(now.Add(proxy0HealthRetryAfter)) {
		t.Error("never retried once proxy0HealthRetryAfter passed")
	}
	s.setFailed(time.Time{})
	if !s.due(now) {
		t.Error("a success must clear the backoff")
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
}
