// Package tungate keeps the TUN transport honest while the tunnel behind it
// is dead.
//
// The OpkgTun interface has carrier exactly while xray holds its device, and
// ndm withdraws every `auto` route through an interface without carrier.
// That covers xray dying. It does not cover xray living on with a dead
// tunnel -- the VLESS server down or blocked, every profile failing: the
// device is still held, the routes stay, and whatever is routed into the
// interface is accepted by xray and goes nowhere. Proxy0 closes that gap
// with a ping-check profile bound to the interface; this closes it with the
// one lever hardware-verified for an OpkgTun interface: `interface OpkgTunN
// down` withdraws the routes at once (xray keeps running) and `up` brings
// them back in about two seconds.
//
// The checks go through xray's SOCKS inbound, not through the TUN, so they
// keep working while the gate is closed -- that is what lets it reopen.
package tungate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrOff is what a Probe returns while the TUN transport is not in use
	// (off, or no interface yet): the gate has nothing to guard, and if it
	// is holding the interface closed it lets go.
	ErrOff = errors.New("tun transport is off")
	// ErrSkip is what a Probe returns when it could not tell anything (the
	// config could not be read, say): neither a success nor a failure.
	ErrSkip = errors.New("no verdict this time")
)

const (
	defaultInterval     = 5 * time.Second
	defaultFailsToClose = 3
)

// Gate closes the TUN interface after FailsToClose consecutive failed checks
// of the live tunnel and opens it again at the first success. A routine xray
// restart (a few seconds) fits inside FailsToClose x Interval, so it never
// trips it.
type Gate struct {
	// Probe is one end-to-end check through the live proxy: nil means the
	// tunnel works. It may return ErrOff or ErrSkip.
	Probe func(ctx context.Context) error
	// Set opens (true) or closes (false) the interface.
	Set func(ctx context.Context, open bool) error
	// Notify, if set, is told about every change with a short reason. It
	// must not block.
	Notify func(closed bool, detail string)
	// Logf, if set, gets the gate's own trouble (a failed Set).
	Logf func(format string, args ...any)

	Interval     time.Duration // between checks; 0 -> 5s
	FailsToClose int           // consecutive failures that close the gate; 0 -> 3

	mu      sync.Mutex
	closed  bool
	since   time.Time
	fails   int
	lastErr string
}

func (g *Gate) interval() time.Duration {
	if g.Interval > 0 {
		return g.Interval
	}
	return defaultInterval
}

func (g *Gate) failsToClose() int {
	if g.FailsToClose > 0 {
		return g.FailsToClose
	}
	return defaultFailsToClose
}

// State reports whether the gate is closed, since when, and the reason the
// last failed check gave. Safe from any goroutine.
func (g *Gate) State() (closed bool, since time.Time, why string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closed, g.since, g.lastErr
}

// Closed is State's first value.
func (g *Gate) Closed() bool {
	closed, _, _ := g.State()
	return closed
}

// Run checks every Interval until ctx ends. On the way out it opens a gate
// it is holding closed, so stopping the daemon never leaves the interface
// administratively down behind it.
func (g *Gate) Run(ctx context.Context) {
	t := time.NewTicker(g.interval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if g.Closed() {
				c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				g.set(c, true, "демон останавливается")
				cancel()
			}
			return
		case <-t.C:
			g.Step(ctx)
		}
	}
}

// Step is one check and the state change it causes.
func (g *Gate) Step(ctx context.Context) {
	err := g.Probe(ctx)
	switch {
	case errors.Is(err, ErrSkip):
		return
	case errors.Is(err, ErrOff):
		g.mu.Lock()
		wasClosed := g.closed
		g.fails, g.lastErr, g.closed, g.since = 0, "", false, time.Time{}
		g.mu.Unlock()
		if wasClosed {
			// Off means off: leave the interface as we found it. Best
			// effort and never retried -- the interface is probably gone.
			_ = g.Set(ctx, true)
		}
		return
	case err == nil:
		g.mu.Lock()
		wasClosed := g.closed
		g.fails, g.lastErr = 0, ""
		g.mu.Unlock()
		if wasClosed {
			g.set(ctx, true, "туннель снова отвечает")
		}
		return
	}

	g.mu.Lock()
	g.fails++
	n, wasClosed := g.fails, g.closed
	g.lastErr = err.Error()
	g.mu.Unlock()
	if !wasClosed && n >= g.failsToClose() {
		g.set(ctx, false, fmt.Sprintf("туннель не отвечает (%d проверок подряд: %s)", n, err))
	}
}

// set applies the change and, only if the router took it, records it and
// tells Notify. A change the router refused is retried by the next Step: the
// failure count (closing) or the success (opening) is still there.
func (g *Gate) set(ctx context.Context, open bool, detail string) {
	err := g.Set(ctx, open)
	g.mu.Lock()
	if err != nil {
		g.mu.Unlock()
		if g.Logf != nil {
			verb := "close"
			if open {
				verb = "open"
			}
			g.Logf("tun-gate: could not %s the interface: %v", verb, err)
		}
		return
	}
	if open {
		g.closed, g.since = false, time.Time{}
	} else {
		g.closed, g.since = true, time.Now()
	}
	g.mu.Unlock()
	if g.Notify != nil {
		g.Notify(!open, detail)
	}
}
