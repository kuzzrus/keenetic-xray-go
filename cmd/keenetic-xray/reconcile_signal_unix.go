//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// signalDebounce is how long watchReconcileSignal waits for a burst of
// SIGUSR1s to settle before running the reconcile once. A firmware
// reconfig fires several netfilter rebuilds back to back.
var signalDebounce = time.Second

// watchReconcileSignal runs `run` once per SIGUSR1 -- the signal the
// netfilter.d hook sends when ndm rebuilds the firewall -- debounced so a
// burst collapses into a single reconcile.
func watchReconcileSignal(ctx context.Context, run func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ch:
			}
			timer := time.NewTimer(signalDebounce)
		drain:
			for {
				select {
				case <-ch:
				case <-timer.C:
					break drain
				case <-ctx.Done():
					timer.Stop()
					return
				}
			}
			run()
		}
	}()
}
