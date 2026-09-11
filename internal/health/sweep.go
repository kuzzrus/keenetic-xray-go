package health

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

// Sweeper probes every profile in turn through its own scratch xray and
// writes the result to StatePath. One is built by the daemon when
// FailoverConfig.QualitySweepMinutes > 0.
type Sweeper struct {
	XrayBinary string               // xray-core binary
	ConfigPath string               // scratch config file it rewrites per profile
	StatePath  string               // where Save() puts the State
	Port       int                  // scratch SOCKS inbound port (loopback only)
	XHTTPMode  string               // config.Config.XHTTPMode passthrough
	Env        []string             // extra env for the child (nil inherits)
	Stderr     io.Writer            // child stderr sink; nil discards
	Probe      xrayctl.ProbeOptions // URL/fallbacks/timeout; SOCKSAddr is filled per run
	Log        func(format string, a ...any)

	// Seams for tests.
	genConfig func(config.XrayConfigOptions) ([]byte, error)
	startXray func(ctx context.Context, cfgPath string) (stop func(), err error)
	probe     func(ctx context.Context, opts xrayctl.ProbeOptions) error
	sleep     func(context.Context, time.Duration)
	now       func() time.Time
}

func (s *Sweeper) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log(format, a...)
	}
}

func (s *Sweeper) init() {
	if s.genConfig == nil {
		s.genConfig = config.GenerateXrayConfig
	}
	if s.startXray == nil {
		s.startXray = s.startScratchXray
	}
	if s.probe == nil {
		s.probe = xrayctl.Probe
	}
	if s.sleep == nil {
		s.sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	if s.now == nil {
		s.now = time.Now
	}
}

// Run sweeps once at startup (after a short settle) and then every
// `interval`, until ctx is done. profiles() is called fresh each cycle
// so a config reload is picked up without restarting the daemon.
func (s *Sweeper) Run(ctx context.Context, profiles func() []config.Profile, interval time.Duration) {
	s.init()
	s.sleep(ctx, 30*time.Second) // let the production tunnel settle first
	for ctx.Err() == nil {
		st := s.SweepOnce(ctx, profiles())
		if ctx.Err() == nil {
			if err := Save(s.StatePath, st); err != nil {
				s.logf("quality sweep: сохранение состояния: %v", err)
			} else {
				ok := 0
				for _, r := range st.Results {
					if r.OK {
						ok++
					}
				}
				s.logf("quality sweep: %d/%d профилей отвечают", ok, len(st.Results))
			}
		}
		s.sleep(ctx, interval)
	}
}

// SweepOnce probes each distinct profile (deduped by ImportKey) in
// sequence and returns the collected State. Safe to call directly in
// tests.
func (s *Sweeper) SweepOnce(ctx context.Context, profiles []config.Profile) State {
	s.init()
	st := State{SweptAt: s.now()}
	seen := map[string]bool{}
	for _, p := range profiles {
		if ctx.Err() != nil {
			break
		}
		key := p.ImportKey()
		if seen[key] {
			continue
		}
		seen[key] = true
		st.Results = append(st.Results, s.probeProfile(ctx, p, key))
		s.sleep(ctx, 300*time.Millisecond) // don't hammer
	}
	return st
}

func (s *Sweeper) probeProfile(ctx context.Context, p config.Profile, key string) Result {
	r := Result{Key: key, Remark: p.Remark, CheckedAt: s.now()}

	data, err := s.genConfig(config.XrayConfigOptions{
		SOCKSPort: s.Port,
		Outbound:  p,
		XHTTPMode: s.XHTTPMode,
	})
	if err != nil {
		r.Detail = "конфиг не собрался"
		return r
	}
	if err := os.WriteFile(s.ConfigPath, data, 0o600); err != nil {
		r.Detail = "конфиг не записался"
		return r
	}

	stop, err := s.startXray(ctx, s.ConfigPath)
	if err != nil {
		r.Detail = "xray не стартовал"
		return r
	}
	defer stop()

	opts := s.Probe
	opts.SOCKSAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port))
	if opts.Retries < 3 {
		opts.Retries = 3 // first attempts race the scratch xray coming up
	}
	if opts.RetryDelay <= 0 {
		opts.RetryDelay = time.Second
	}
	start := s.now()
	if err := s.probe(ctx, opts); err != nil {
		r.Detail = classifyProbeErr(err)
		return r
	}
	r.OK = true
	r.LatencyMS = s.now().Sub(start).Milliseconds()
	return r
}

// startScratchXray launches `xray run -c <cfg>` bound to ctx and returns
// a stop() that kills it and waits. The child is loopback-only (the
// scratch config never sets ListenHost), so nothing on the LAN can reach
// it.
func (s *Sweeper) startScratchXray(ctx context.Context, cfgPath string) (func(), error) {
	cctx, cancel := context.WithCancel(ctx)
	c := exec.CommandContext(cctx, s.XrayBinary, "run", "-c", cfgPath)
	if s.Env != nil {
		c.Env = append(os.Environ(), s.Env...)
	}
	c.Stderr = s.Stderr
	if err := c.Start(); err != nil {
		cancel()
		return nil, err
	}
	done := make(chan struct{})
	go func() { _, _ = c.Process.Wait(); close(done) }()
	return func() {
		cancel()
		if c.Process != nil {
			_ = c.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}, nil
}

// classifyProbeErr collapses a probe error into a short RU label for the
// status line.
func classifyProbeErr(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "нет ответа (таймаут)"
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return "нет ответа (таймаут)"
	case strings.Contains(s, "refused"):
		return "соединение отклонено"
	case strings.Contains(s, "no such host") || strings.Contains(s, "lookup"):
		return "хост не резолвится"
	case strings.Contains(s, "status"):
		return "прокси вернул ошибку"
	default:
		return "не отвечает"
	}
}
