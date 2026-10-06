package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/tungate"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// tunGate is the daemon's TUN gate (see internal/tungate): it closes the
// OpkgTun interface while the tunnel behind xray is dead, which carrier alone
// cannot tell. nil outside the daemon. Assigned once in cmdDaemon before any
// goroutine that reads it is started; the reconcile loop and the bot read it.
var tunGate *tungate.Gate

// tunGateProbeTimeout bounds one check. Three of them in a row, five seconds
// apart, close the gate -- a routine xray restart fits inside that.
const tunGateProbeTimeout = 4 * time.Second

// tunGateConfig hands the gate the current config without reloading the file
// on every check: the gate looks every few seconds, an operator changes the
// transport once in a while.
type tunGateConfig struct {
	mu  sync.Mutex
	cfg *config.Config
	at  time.Time
}

const tunGateConfigTTL = 30 * time.Second

// get returns the last good config, reloading it at most every
// tunGateConfigTTL. A config that cannot be read keeps the previous one; with
// none yet, ok is false.
func (s *tunGateConfig) get() (cfg *config.Config, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg == nil || time.Since(s.at) > tunGateConfigTTL {
		if c, err := config.Load(configPath()); err == nil {
			s.cfg, s.at = c, time.Now()
		} else if s.cfg == nil {
			return nil, false
		}
	}
	return s.cfg, true
}

// probe is one end-to-end check of the live tunnel, through xray's SOCKS
// inbound (not through the TUN, so it keeps working while the gate is
// closed). ErrOff while the transport is not in use.
func (s *tunGateConfig) probe(ctx context.Context) error {
	cfg, ok := s.get()
	if !ok {
		return tungate.ErrSkip
	}
	if t := cfg.TunTransport; !t.Enabled || t.Iface == "" || !keenetic.Available() {
		return tungate.ErrOff
	}
	return xrayctl.Probe(ctx, xrayctl.ProbeOptions{
		SOCKSAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.Failover.SOCKSPort),
		URL:          cfg.Failover.HealthCheckURL,
		FallbackURLs: cfg.Failover.HealthCheckFallbackURLs,
		Timeout:      tunGateProbeTimeout,
	})
}

// set opens or closes the configured interface.
func (s *tunGateConfig) set(ctx context.Context, open bool) error {
	cfg, ok := s.get()
	if !ok || cfg.TunTransport.Iface == "" {
		return errors.New("no TUN interface configured")
	}
	return keenetic.SetTunAdmin(ctx, cfg.TunTransport.Iface, open)
}

// newTunGate builds the daemon's gate. Changes go to daemon.log and, as
// events, to the bot.
func newTunGate(d *failover.Daemon, logf func(string, ...any)) *tungate.Gate {
	src := &tunGateConfig{}
	return &tungate.Gate{
		Probe: src.probe,
		Set:   src.set,
		Logf:  logf,
		Notify: func(closed bool, detail string) {
			kind, word := failover.EventTunGateOpened, "open"
			if closed {
				kind, word = failover.EventTunGateClosed, "closed"
			}
			logf("tun-gate: %s -- %s", word, detail)
			d.Notify(failover.Event{Kind: kind, Detail: detail})
		},
	}
}
