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

// Handler executes one Command and returns human-readable output, or an
// error. Injected so the polling/transport code here doesn't need to
// import the concrete failover/config/subscription plumbing directly --
// see RouterHandler in commands.go for the real implementation.
type Handler interface {
	Handle(ctx context.Context, cmd Command) (output string, err error)
}

// AgentOptions configures Run.
type AgentOptions struct {
	ControlServerURL  string // e.g. "https://vps.example.com:8443"
	RouterID          string
	Token             string        // Bearer token; compared constant-time server-side
	FingerprintSHA256 string        // hex SHA256 of the server's leaf cert, pinned SSH-host-key style
	PollInterval      time.Duration // 0 -> DefaultPollInterval
	HeartbeatInterval time.Duration // 0 -> DefaultHeartbeatInterval

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
	if o.ControlServerURL == "" || o.RouterID == "" || o.Token == "" || o.FingerprintSHA256 == "" {
		return fmt.Errorf("control server URL, router ID, token, and fingerprint are all required")
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

	client, err := newPinnedClient(opts.FingerprintSHA256)
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
	if opts.StatusFunc != nil {
		sendHeartbeat(ctx, client, opts) // one right away so the card isn't blank
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			pollOnce(ctx, client, opts, handle)
		case <-hbTicker.C:
			if opts.StatusFunc != nil {
				sendHeartbeat(ctx, client, opts)
			}
		case ev := <-opts.Events:
			postEvent(ctx, client, opts, ev)
		}
	}
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

func pollOnce(ctx context.Context, client *http.Client, opts AgentOptions, handle Handler) {
	cmd, err := poll(ctx, client, opts)
	if err != nil || cmd == nil {
		return
	}

	output, err := handle.Handle(ctx, *cmd)
	result := Result{CommandID: cmd.ID, Output: output, Completed: time.Now()}
	if err != nil {
		result.Err = err.Error()
	}
	_ = postResult(ctx, client, opts, result) // best-effort; the next poll proceeds regardless
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

// newPinnedClient returns an *http.Client that trusts exactly one TLS
// leaf certificate: the one whose SHA256 fingerprint matches
// fingerprintHex, SSH-host-key style -- not a CA chain. This is
// deliberate, not a workaround: the control server's certificate is
// self-signed, so ordinary CA verification would always fail.
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
