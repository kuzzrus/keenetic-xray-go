package botcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultPollInterval is how often the agent asks the control server for
// queued work when AgentOptions.PollInterval isn't set.
const DefaultPollInterval = 5 * time.Second

// DefaultHeartbeatInterval is how often the agent pushes a status
// snapshot so the router card stays fresh, when AgentOptions
// .HeartbeatInterval isn't set.
const DefaultHeartbeatInterval = 30 * time.Second

// DefaultCommandTimeout bounds one dispatched unit of work -- a poll's
// Handler.Handle call, or a heartbeat's StatusFunc call -- so a slow or
// stuck one can never freeze Run's single-threaded select loop past this
// ceiling. StatusFunc and several Handle actions read the failover
// Daemon's state (RouterHandler.status -> Daemon.Snapshot), which blocks
// on Daemon.do until its own goroutine is free -- normally fast, but
// bounded only by how long a Tick takes, which grew sharply once a probe
// could retry across several URLs (internal/xrayctl.Probe). Before this,
// ctx here was the agent's whole-process lifetime context (never
// cancelled short of shutdown), so nothing capped that wait: a
// sufficiently slow Tick could stall heartbeat, which stalls poll (same
// goroutine), for as long as the Tick ran. Comfortably under
// DefaultOfflineThreshold (90s, see OfflineWatcher) so a single slow call
// can't itself cost the router an "не выходит на связь" -- the very next
// poll tick still lands in time.
const DefaultCommandTimeout = 60 * time.Second

// Handler executes one Command and returns human-readable output, or an
// error. Injected so the polling/transport code here doesn't need to
// import the concrete failover/config/subscription plumbing directly --
// see RouterHandler in commands.go for the real implementation.
type Handler interface {
	Handle(ctx context.Context, cmd Command) (output string, err error)
}

// AgentOptions configures Run.
type AgentOptions struct {
	ControlServerURL string // e.g. "https://vps.example.com:8443"
	RouterID         string
	Token            string // Bearer token; compared constant-time server-side
	// FingerprintSHA256, when set, pins the server's leaf certificate by
	// hex SHA256, SSH-host-key style -- no CA trust needed, but a new
	// certificate (the server's own, or an operator migrating hosts)
	// means reconfiguring every agent. Empty means the opposite trade:
	// ControlServerURL must resolve to a domain serving a CA-issued
	// certificate (see the control server's ACME/autocert support), and
	// the agent verifies it the ordinary way instead.
	FingerprintSHA256 string
	PollInterval      time.Duration // 0 -> DefaultPollInterval
	HeartbeatInterval time.Duration // 0 -> DefaultHeartbeatInterval
	CommandTimeout    time.Duration // 0 -> DefaultCommandTimeout

	// StatusFunc, if set, renders the status snapshot the agent pushes to
	// /agent/heartbeat so the router card stays live. Nil disables the
	// heartbeat entirely (tests, minimal deployments).
	StatusFunc func(ctx context.Context) string

	// Events, if set, is drained by Run and each value POSTed to
	// /agent/event (best-effort). Optional -- a nil channel is simply
	// never selected.
	Events <-chan Event
}

func (o AgentOptions) validate() error {
	if o.ControlServerURL == "" || o.RouterID == "" || o.Token == "" {
		return fmt.Errorf("control server URL, router ID, and token are all required")
	}
	return nil
}

// Run polls the control server for queued commands, executes each via
// handle, and posts the result back, until ctx is cancelled. A poll that
// fails (network error, nothing queued) is silently retried on the next
// tick -- only ctx cancellation stops the loop.
func Run(ctx context.Context, opts AgentOptions, handle Handler) error {
	if err := opts.validate(); err != nil {
		return fmt.Errorf("botcontrol: %w", err)
	}

	client, err := newAgentClient(opts.FingerprintSHA256)
	if err != nil {
		return fmt.Errorf("botcontrol: %w", err)
	}

	interval := opts.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	hbInterval := opts.HeartbeatInterval
	if hbInterval <= 0 {
		hbInterval = DefaultHeartbeatInterval
	}
	hbTicker := time.NewTicker(hbInterval)
	defer hbTicker.Stop()

	cmdTimeout := opts.CommandTimeout
	if cmdTimeout <= 0 {
		cmdTimeout = DefaultCommandTimeout
	}
	if opts.StatusFunc != nil {
		runBounded(ctx, cmdTimeout, func(c context.Context) { sendHeartbeat(c, client, opts) }) // one right away so the card isn't blank
	}

	// unposted is a result pollOnce computed but couldn't deliver last
	// time (the command already ran -- re-running it is not an option,
	// only re-trying the delivery is). Single-slot, not a queue: Run's
	// own select loop only ever has one pollOnce in flight at a time, so
	// there's never more than one outcome waiting to be confirmed
	// delivered (BOT-01).
	var unposted *Result

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			runBounded(ctx, cmdTimeout, func(c context.Context) { unposted = pollOnce(c, client, opts, handle, unposted) })
		case <-hbTicker.C:
			if opts.StatusFunc != nil {
				runBounded(ctx, cmdTimeout, func(c context.Context) { sendHeartbeat(c, client, opts) })
			}
		case ev := <-opts.Events:
			postEvent(ctx, client, opts, ev)
		}
	}
}

// runBounded derives a child context capped at timeout and runs fn with
// it, so one dispatch from Run's loop can never withhold the goroutine
// from the next select iteration past that ceiling -- see
// DefaultCommandTimeout.
func runBounded(ctx context.Context, timeout time.Duration, fn func(context.Context)) {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	fn(callCtx)
}

// sendHeartbeat renders the current status via opts.StatusFunc and POSTs
// it to /agent/heartbeat so the control server's router card stays fresh.
// Best-effort; caller has checked opts.StatusFunc != nil.
func sendHeartbeat(ctx context.Context, client *http.Client, opts AgentOptions) {
	out := opts.StatusFunc(ctx)
	if out == "" {
		return
	}
	body, err := json.Marshal(Heartbeat{Status: out, Time: time.Now()})
	if err != nil {
		return
	}
	_ = doJSON(ctx, client, opts, "/agent/heartbeat", body, nil)
}

// postEvent forwards one unsolicited Event to the control server. Best
// -effort: a failure is dropped, the next poll proceeds regardless.
func postEvent(ctx context.Context, client *http.Client, opts AgentOptions, ev Event) {
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	_ = doJSON(ctx, client, opts, "/agent/event", body, nil)
}

// pollOnce delivers a still-unposted result (if unposted is non-nil, from
// a previous call's failed postResult) before asking for new work, then
// executes at most one newly-dequeued command. It returns the result
// that still needs delivering on the *next* call -- nil once everything
// in flight has actually reached the control server.
//
// Retrying the delivery, not the command: a command that already ran
// must never run a second time just because its result got lost in
// transit (BOT-01) -- re-sending the same already-computed Result is
// always safe, re-executing an arbitrary command (self-update, a daemon
// restart, ...) usually isn't.
func pollOnce(ctx context.Context, client *http.Client, opts AgentOptions, handle Handler, unposted *Result) *Result {
	if unposted != nil {
		if err := postResult(ctx, client, opts, *unposted); err != nil {
			return unposted // still not delivered -- retry again next tick
		}
		// Delivered. New work waits for the next regular tick rather than
		// also polling in this same call -- keeps each call to one round
		// trip, well inside runBounded's timeout budget, and PollInterval
		// is short enough that the wait costs nothing worth avoiding it for.
		return nil
	}

	cmd, err := poll(ctx, client, opts)
	if err != nil || cmd == nil {
		return nil
	}

	output, err := handle.Handle(ctx, *cmd)
	result := Result{CommandID: cmd.ID, Output: output, Completed: time.Now()}
	if err != nil {
		result.Err = err.Error()
	}
	if perr := postResult(ctx, client, opts, result); perr != nil {
		return &result
	}
	return nil
}

func poll(ctx context.Context, client *http.Client, opts AgentOptions) (*Command, error) {
	var resp PollResponse
	if err := doJSON(ctx, client, opts, "/agent/poll", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Command, nil
}

func postResult(ctx context.Context, client *http.Client, opts AgentOptions, result Result) error {
	body, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return doJSON(ctx, client, opts, "/agent/result", body, nil)
}

func doJSON(ctx context.Context, client *http.Client, opts AgentOptions, path string, body []byte, out any) error {
	url := strings.TrimRight(opts.ControlServerURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.Token)
	req.Header.Set(RouterIDHeader, opts.RouterID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: unexpected status %s", path, resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// newAgentClient returns the *http.Client the agent dials the control
// server with. An empty fingerprintHex means ControlServerURL is trusted
// the ordinary way -- a real CA-issued certificate for a domain (see the
// control server's ACME/autocert support) -- and this is just
// http.Client with sane defaults, no custom TLSClientConfig at all.
// Otherwise it's newPinnedClient: trusts exactly one TLS leaf
// certificate, the one whose SHA256 fingerprint matches fingerprintHex,
// SSH-host-key style, not a CA chain -- deliberate, not a workaround,
// for a self-signed certificate ordinary CA verification would always
// reject.
func newAgentClient(fingerprintHex string) (*http.Client, error) {
	if fingerprintHex == "" {
		return &http.Client{Timeout: 30 * time.Second}, nil
	}
	return newPinnedClient(fingerprintHex)
}

func newPinnedClient(fingerprintHex string) (*http.Client, error) {
	want, err := hex.DecodeString(fingerprintHex)
	if err != nil {
		return nil, fmt.Errorf("invalid fingerprint %q: %w", fingerprintHex, err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // VerifyPeerCertificate below does the real check
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("no certificate presented")
				}
				got := sha256.Sum256(rawCerts[0])
				if subtle.ConstantTimeCompare(got[:], want) != 1 {
					return fmt.Errorf("certificate fingerprint mismatch")
				}
				return nil
			},
		},
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}
