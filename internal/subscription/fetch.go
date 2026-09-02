// Package subscription fetches, decodes, and parses V2Ray/Xray-style
// subscription URLs into internal/config Profiles, and re-matches a
// previously-selected primary/backup pair by remark across a refresh.
package subscription

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// FetchTimeout bounds how long a subscription fetch may take.
	FetchTimeout = 15 * time.Second
	// MaxBodyBytes bounds how large a subscription response may be --
	// subscriptions are normally a few KB; this just caps the worst case
	// against a broken or adversarial endpoint.
	MaxBodyBytes = 2 * 1024 * 1024
	// maxRedirects caps redirect-following. A subscription host commonly
	// 301s once to a CDN; a longer chain is more likely a
	// misconfiguration or an attempt to bounce the fetch elsewhere.
	maxRedirects = 5
	// userAgent is sent on every fetch -- some providers reject requests
	// without one.
	userAgent = "keenetic-xray"
)

// Fetch retrieves the raw body of a subscription URL, enforcing
// FetchTimeout and MaxBodyBytes.
func Fetch(ctx context.Context, url string) ([]byte, error) {
	return fetch(ctx, url, FetchTimeout, MaxBodyBytes)
}

func fetch(ctx context.Context, url string, timeout time.Duration, maxBytes int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: unexpected status %s", url, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d byte limit", maxBytes)
	}
	return body, nil
}
