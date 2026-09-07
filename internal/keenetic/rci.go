package keenetic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RCI is Keenetic's local JSON mirror of the CLI tree. KeeneticOS serves
// it without authentication to 127.0.0.1, so an Entware process on the
// router can read state even on firmware that sandboxes it away from the
// `ndmc` binary. This file lets the keenetic layer serve the reads that
// map cleanly -- `show running-config`, `show version`, `show interface
// <iface>`, `show object-group fqdn <name>` -- over RCI when it's
// enabled, each reformatted (see rci_reformat.go) into the exact text
// its ndmc parser expects; every write and every other read still goes
// through ndmcRun's exec path. Off unless UseRCI is called (from the
// daemon, when config.RCI.Enabled).

var (
	rciMu     sync.RWMutex
	rciActive *rciClient
)

type rciClient struct {
	base string
	hc   *http.Client
}

// activeRCI returns the live client, or nil when RCI mode is off.
func activeRCI() *rciClient {
	rciMu.RLock()
	defer rciMu.RUnlock()
	return rciActive
}

// UseRCI turns on RCI-backed reads against base (scheme+host+port). It
// probes /rci/show/version once so a bad URL fails loudly at startup
// rather than silently on the first reconcile. Passing "" clears it.
func UseRCI(base string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		rciMu.Lock()
		rciActive = nil
		rciMu.Unlock()
		return "", nil
	}
	c := &rciClient{
		base: base,
		hc: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := c.get(ctx, "/rci/show/version"); err != nil {
		return "", fmt.Errorf("RCI не отвечает на %s: %w", base, err)
	}
	rciMu.Lock()
	rciActive = c
	rciMu.Unlock()
	return base, nil
}

// RCIActive reports whether RCI-backed reads are on.
func RCIActive() bool { return activeRCI() != nil }

// tryRead serves the reads RCI can answer faithfully. ok is false for
// anything it doesn't handle (every write, `show ip`, …) so ndmcRun
// falls through to exec.
//
//   - running-config / version are core reads on every reconcile: if RCI
//     mode is on it's because ndmc may be fenced off, so a fetch error is
//     still ok=true (surface it -- there's no fallback worth having).
//   - interface / object-group are peripheral (WG transport, conntrack
//     flush): a fetch error there is ok=false so a router whose ndmc
//     still works gets the right answer; only a 200-with-unreadable-body
//     is surfaced.
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
	case strings.HasPrefix(cmd, "show object-group fqdn "):
		name := strings.TrimSpace(strings.TrimPrefix(cmd, "show object-group fqdn "))
		if name == "" || strings.ContainsAny(name, " \t") {
			return "", false, nil
		}
		b, e := c.get(ctx, "/rci/show/object-group/fqdn/"+url.PathEscape(name))
		if e != nil {
			return "", false, nil
		}
		txt, e := objectGroupTextFromRCI(b)
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
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
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
