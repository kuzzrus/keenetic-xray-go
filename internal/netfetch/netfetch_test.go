package netfetch

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeRT is one step of the chain: it either fails or answers with body,
// and records that it was asked.
type fakeRT struct {
	name  string
	fail  bool
	calls *[]string
	mu    *sync.Mutex
}

func (f fakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	*f.calls = append(*f.calls, f.name)
	f.mu.Unlock()
	if f.fail {
		return nil, errors.New(f.name + " failed")
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("via " + f.name)), Request: req}, nil
}

// withSteps stands fakes in for the chain's three steps.
func withSteps(t *testing.T, directFails, smallFails, tunnelFails bool, tunnel string) *[]string {
	t.Helper()
	var calls []string
	var mu sync.Mutex
	d, s, v, ts, lf := direct, smallHello, viaSOCKS, TunnelSOCKS, Logf
	t.Cleanup(func() { direct, smallHello, viaSOCKS, TunnelSOCKS, Logf = d, s, v, ts, lf })
	direct = fakeRT{"direct", directFails, &calls, &mu}
	smallHello = fakeRT{"small", smallFails, &calls, &mu}
	viaSOCKS = func(addr string) http.RoundTripper { return fakeRT{"tunnel@" + addr, tunnelFails, &calls, &mu} }
	TunnelSOCKS = func() string { return tunnel }
	Logf = nil
	return &calls
}

func get(t *testing.T, ctx context.Context) (string, error) {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://raw.githubusercontent.com/x/y", nil)
	resp, err := Client(time.Minute).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestChain_Order(t *testing.T) {
	cases := []struct {
		name                  string
		directF, smallF, tunF bool
		tunnel                string
		want                  string
		wantCalls             []string
	}{
		{"direct works", false, false, false, "127.0.0.1:1080", "via direct", []string{"direct"}},
		{"small hello rescues", true, false, false, "127.0.0.1:1080", "via small", []string{"direct", "small"}},
		{"tunnel rescues", true, true, false, "127.0.0.1:1080", "via tunnel@127.0.0.1:1080", []string{"direct", "small", "tunnel@127.0.0.1:1080"}},
		{"no tunnel running", true, true, false, "", "", []string{"direct", "small"}},
		{"nothing works", true, true, true, "127.0.0.1:1080", "", []string{"direct", "small", "tunnel@127.0.0.1:1080"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := withSteps(t, tc.directF, tc.smallF, tc.tunF, tc.tunnel)
			got, err := get(t, context.Background())
			if tc.want == "" {
				if err == nil {
					t.Fatalf("got %q, want every step's error", got)
				}
				for _, step := range *calls {
					if !strings.Contains(err.Error(), step) {
						t.Errorf("error %q does not name step %q", err, step)
					}
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if !slices.Equal(*calls, tc.wantCalls) {
				t.Errorf("steps tried %v, want %v", *calls, tc.wantCalls)
			}
		})
	}
}

// TestChain_CallerGaveUp: once the caller's own deadline or cancel is
// hit, no further step starts.
func TestChain_CallerGaveUp(t *testing.T) {
	calls := withSteps(t, true, false, false, "127.0.0.1:1080")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := get(t, ctx); err == nil {
		t.Fatal("a cancelled request succeeded")
	}
	if len(*calls) > 1 {
		t.Errorf("steps tried after the caller gave up: %v", *calls)
	}
}

// TestChain_LogsTheHostOnly: a subscription URL's path is often its
// access token -- the log line names the host, never the path.
func TestChain_LogsTheHostOnly(t *testing.T) {
	withSteps(t, true, false, false, "")
	var logged string
	Logf = func(f string, a ...any) { logged = fmt.Sprintf(f, a...) }
	if _, err := get(t, context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logged, "raw.githubusercontent.com") || strings.Contains(logged, "/x/y") {
		t.Errorf("log line = %q, want the host and not the path", logged)
	}
}

// socks5Server is a minimal SOCKS5 (no auth, CONNECT only) that counts
// the connections it relays -- the shape of xray's own socks inbound.
func socks5Server(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var relayed atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				if _, err := io.ReadFull(c, buf[:2]); err != nil {
					return
				}
				if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
					return
				}
				_, _ = c.Write([]byte{5, 0})
				if _, err := io.ReadFull(c, buf[:4]); err != nil {
					return
				}
				var host string
				switch buf[3] {
				case 1:
					_, _ = io.ReadFull(c, buf[:4])
					host = net.IP(buf[:4]).String()
				case 3:
					_, _ = io.ReadFull(c, buf[:1])
					n := int(buf[0])
					_, _ = io.ReadFull(c, buf[:n])
					host = string(buf[:n])
				default:
					return
				}
				_, _ = io.ReadFull(c, buf[:2])
				port := int(buf[0])<<8 | int(buf[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				relayed.Add(1)
				_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String(), &relayed
}

// TestSOCKSStep_ReallyGoesThroughTheProxy: the tunnel step is a real
// SOCKS5 client, and a request actually reaches its target through it.
func TestSOCKSStep_ReallyGoesThroughTheProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "from target")
	}))
	t.Cleanup(target.Close)
	addr, relayed := socks5Server(t)

	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	resp, err := socksTransport(addr).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "from target" || relayed.Load() != 1 {
		t.Errorf("body %q, relayed %d; want the target's answer through one relayed connection", b, relayed.Load())
	}
}

// TestSmallHello_OffersOnlyX25519: the second step's ClientHello carries
// a single X25519 key share -- not the default's post-quantum hybrid,
// which is what makes a modern ClientHello big.
func TestSmallHello_OffersOnlyX25519(t *testing.T) {
	var mu sync.Mutex
	offered := map[string][]tls.CurveID{}
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		offered[h.ServerName] = h.SupportedCurves
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	for name, small := range map[string]bool{"small.test": true, "default.test": false} {
		tr := newTransport(small)
		// Point the name at the test server; the untrusted certificate
		// fails the handshake after the ClientHello has been seen.
		dial := tr.DialContext
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dial(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		}
		req, _ := http.NewRequest(http.MethodGet, "https://"+name+"/", nil)
		if resp, err := tr.RoundTrip(req); err == nil {
			resp.Body.Close()
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if got := offered["small.test"]; !slices.Equal(got, []tls.CurveID{tls.X25519}) {
		t.Errorf("small hello offered %v, want only X25519", got)
	}
	if got := offered["default.test"]; !slices.Contains(got, tls.X25519MLKEM768) {
		t.Errorf("default offered %v -- expected the post-quantum hybrid this step exists to drop", got)
	}
}
