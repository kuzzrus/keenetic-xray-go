//go:build unix

package main

import (
	"context"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWatchReconcileSignal_DebouncesBurst(t *testing.T) {
	old := signalDebounce
	signalDebounce = 80 * time.Millisecond
	t.Cleanup(func() { signalDebounce = old })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs int32
	watchReconcileSignal(ctx, func() { atomic.AddInt32(&runs, 1) })
	time.Sleep(20 * time.Millisecond) // let signal.Notify register

	for i := 0; i < 4; i++ {
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGUSR1)
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)

	if got := atomic.LoadInt32(&runs); got != 1 {
		t.Fatalf("runs = %d, want 1 (a 4-signal burst debounces to one reconcile)", got)
	}
}
