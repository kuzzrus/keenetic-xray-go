package keenetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RCI is Keenetic's local JSON mirror of the CLI tree. Up to KeeneticOS
// 5.1 it's served without authentication to 127.0.0.1; 5.2 wants an
// access token even there -- one the operator creates in the web UI
// (Пользователи и доступ → Токены доступа), sent as the RCITokenHeader
// header. Either way an Entware process on the router can read state
// even on firmware that sandboxes it away from the `ndmc` binary. This
// file lets the keenetic layer serve the reads that map cleanly -- `show
// running-config`, `show version`, `show interface <iface>` -- over RCI
// when it's enabled, each reformatted (see rci_reformat.go) into the
// exact text its ndmc parser expects; every write and every other read
// still goes through ndmcRun's exec path. (`show object-group` has no RCI
// node on :79 -- it stays on ndmc.) Off unless UseRCI is called (from the
// daemon, when config.RCI.Enabled).

// RCITokenHeader carries the RCI access token (KeeneticOS 5.2+).
const RCITokenHeader = "X-Ndma-Tkn"

// ErrRCIAuth is RCI refusing the request: HTTP 401/403 -- no token where
// the firmware wants one, or one it doesn't accept.
var ErrRCIAuth = errors.New("RCI требует токен доступа или не принял его (KeeneticOS 5.2+: Пользователи и доступ → Токены доступа)")

var (
	rciMu     sync.RWMutex
	rciActive *rciClient
)

type rciClient struct {
	base  string
	token string
	hc    *http.Client
}

// activeRCI returns the live client, or nil when RCI mode is off.
func activeRCI() *rciClient {
	rciMu.RLock()
	defer rciMu.RUnlock()
	return rciActive
}

// UseRCI turns on RCI-backed reads against base (scheme+host+port),
// sending token when it isn't empty. It probes /rci/show/version once so
// a bad URL or token fails loudly at startup rather than silently on the
// first reconcile -- and a failed probe turns RCI mode off, back to
// ndmc, instead of keeping whatever client was active before: a changed
// token or URL that doesn't work must not leave the old one in use.
// Passing "" as base clears it.
func UseRCI(base, token string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		setRCI(nil)
		return "", nil
	}
	c := newRCIClient(base, token)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := c.get(ctx, "/rci/show/version"); err != nil {
		setRCI(nil)
		return "", fmt.Errorf("RCI не отвечает на %s: %w", base, err)
	}
	setRCI(c)
	return base, nil
}

// ProbeRCI checks that base answers /rci/show/version with token, without
// switching RCI mode on. It returns the firmware's own version string.
func ProbeRCI(ctx context.Context, base, token string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	b, err := newRCIClient(base, token).get(ctx, "/rci/show/version")
	if err != nil {
		return "", err
	}
	txt, err := versionTextFromRCI(b)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(txt), "title:")), nil
}

func newRCIClient(base, token string) *rciClient {
	return &rciClient{
		base:  base,
		token: strings.TrimSpace(token),
		hc: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		},
	}
}

func setRCI(c *rciClient) {
	rciMu.Lock()
	rciActive = c
	rciMu.Unlock()
}

// RCIActive reports whether RCI-backed reads are on.
func RCIActive() bool { return activeRCI() != nil }

// tryRead serves the reads RCI can answer faithfully. ok is false for
// anything it doesn't handle (every write, `show object-group`, `show
// ip`, …) so ndmcRun falls through to exec.
//
//   - running-config / version are core reads on every reconcile: if RCI
//     mode is on it's because ndmc may be fenced off, so a fetch error is
//     still ok=true (surface it -- there's no fallback worth having).
//   - interface is peripheral (WG transport, LAN-IP fallback): a fetch
//     error there is ok=false so a router whose ndmc still works gets the
//     right answer; only a 200-with-unreadable-body is surfaced.
func (c *rciClient) tryRead(ctx context.Context, cmd string) (out string, ok bool, err error) {
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "show running-config":
		// /rci/show/running-config returns {"message": [<one CLI line per
		// entry>]} -- join it and you have byte-identical text to
		// `ndmc -c "show running-config"`, so every existing line parser
		// keeps working. (/ci/running-config.txt is 403 on the no-auth
		// loopback port.)
		b, e := c.get(ctx, "/rci/show/running-config")
		if e != nil {
			return "", true, e
		}
		txt, e := runningConfigFromRCI(b)
		return txt, true, e
	case cmd == "show version":
		b, e := c.get(ctx, "/rci/show/version")
		if e != nil {
			return "", true, e
		}
		txt, e := versionTextFromRCI(b)
		return txt, true, e
	case strings.HasPrefix(cmd, "show interface "):
		iface := strings.TrimSpace(strings.TrimPrefix(cmd, "show interface "))
		if iface == "" || strings.ContainsAny(iface, " \t") {
			return "", false, nil // "show interface" with no/odd arg -- not ours
		}
		b, e := c.get(ctx, "/rci/show/interface/"+url.PathEscape(iface))
		if e != nil {
			return "", false, nil // let ndmc try
		}
		txt, e := interfaceTextFromRCI(b)
		return txt, true, e
	default:
		return "", false, nil
	}
}

// runningConfigFromRCI turns {"message": [...]} (or {"message": "..."})
// from /rci/show/running-config into the CLI text the parsers expect.
func runningConfigFromRCI(b []byte) (string, error) {
	var v struct {
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("show running-config: RCI JSON: %w", err)
	}
	var lines []string
	if err := json.Unmarshal(v.Message, &lines); err == nil {
		return strings.Join(lines, "\n") + "\n", nil
	}
	var s string
	if err := json.Unmarshal(v.Message, &s); err == nil {
		return s, nil
	}
	return "", fmt.Errorf("show running-config: unexpected RCI `message` shape")
}

func (c *rciClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set(RCITokenHeader, c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%s -> HTTP %d: %w", path, resp.StatusCode, ErrRCIAuth)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s -> HTTP %d", path, resp.StatusCode)
	}
	return body, nil
}

// versionTextFromRCI turns /rci/show/version JSON into the single
// "title: X.Y.Z" line OSVersion's parser looks for. KeeneticOS reports
// the dotted version under a few possible keys across builds.
func versionTextFromRCI(b []byte) (string, error) {
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return "", fmt.Errorf("show version: RCI JSON: %w", err)
	}
	for _, k := range []string{"title", "release", "version"} {
		if s, ok := v[k].(string); ok && strings.TrimSpace(s) != "" {
			return "title: " + strings.TrimSpace(s) + "\n", nil
		}
	}
	return "", fmt.Errorf("show version: no version field in RCI response")
}
