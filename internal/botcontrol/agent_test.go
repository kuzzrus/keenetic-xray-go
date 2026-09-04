package botcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fingerprintOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func TestNewPinnedClient_AcceptsMatchingFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client, err := newPinnedClient(fingerprintOf(t, srv))
	if err != nil {
		t.Fatalf("newPinnedClient: %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestNewPinnedClient_RejectsWrongFingerprint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wrongFingerprint := hex.EncodeToString(sha256.New().Sum(nil)) // sha256 of empty input -- not this server's cert
	client, err := newPinnedClient(wrongFingerprint)
	if err != nil {
		t.Fatalf("newPinnedClient: %v", err)
	}
	if _, err := client.Get(srv.URL); err == nil {
		t.Error("expected the request to fail with a mismatched fingerprint")
	}
}

func TestNewPinnedClient_InvalidFingerprintHex(t *testing.T) {
	if _, err := newPinnedClient("not-valid-hex!!"); err == nil {
		t.Error("expected error for invalid hex fingerprint")
	}
}

func TestAgentOptions_Validate(t *testing.T) {
	valid := AgentOptions{ControlServerURL: "https://x", RouterID: "r", Token: "t", FingerprintSHA256: "ab"}
	if err := valid.validate(); err != nil {
		t.Errorf("valid options should validate: %v", err)
	}

	cases := []AgentOptions{
		{RouterID: "r", Token: "t", FingerprintSHA256: "ab"},
		{ControlServerURL: "https://x", Token: "t", FingerprintSHA256: "ab"},
		{ControlServerURL: "https://x", RouterID: "r", FingerprintSHA256: "ab"},
		{ControlServerURL: "https://x", RouterID: "r", Token: "t"},
	}
	for i, c := range cases {
		if err := c.validate(); err == nil {
			t.Errorf("case %d: expected error for incomplete options %+v", i, c)
		}
	}
}

type fakeHandler struct {
	calls int32
}

func (h *fakeHandler) Handle(_ context.Context, cmd Command) (string, error) {
	atomic.AddInt32(&h.calls, 1)
	return "did " + cmd.Action, nil
}

// blockingHandler.Handle never returns on its own -- only ctx expiring
// does, simulating a call stuck on a resource that never frees up
// (Daemon.Snapshot waiting on a busy Daemon goroutine).
type blockingHandler struct{ calls int32 }

func (h *blockingHandler) Handle(ctx context.Context, cmd Command) (string, error) {
	atomic.AddInt32(&h.calls, 1)
	<-ctx.Done()
	return "did " + cmd.Action, nil
}

func TestRun_PollsExecutesAndPostsResult(t *testing.T) {
	var mu sync.Mutex
	served := false
	var gotResult Result
	var gotRouterID string

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if got := r.Header.Get(RouterIDHeader); got != "router-1" {
			t.Errorf("poll: %s header = %q, want %q", RouterIDHeader, got, "router-1")
		}
		w.Header().Set("Content-Type", "application/json")
		if served {
			_ = json.NewEncoder(w).Encode(PollResponse{})
			return
		}
		served = true
		_ = json.NewEncoder(w).Encode(PollResponse{Command: &Command{ID: "1", Action: ActionStatus}})
	})
	mux.HandleFunc("/agent/result", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		gotRouterID = r.Header.Get(RouterIDHeader)
		_ = json.NewDecoder(r.Body).Decode(&gotResult)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	handler := &fakeHandler{}
	opts := AgentOptions{
		ControlServerURL:  srv.URL,
		RouterID:          "router-1",
		Token:             "test-token",
		FingerprintSHA256: fingerprintOf(t, srv),
		PollInterval:      10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = Run(ctx, opts, handler)

	if atomic.LoadInt32(&handler.calls) == 0 {
		t.Fatal("handler was never called")
	}
	mu.Lock()
	defer mu.Unlock()
	if gotResult.CommandID != "1" || gotResult.Output != "did status" {
		t.Errorf("gotResult = %+v, want CommandID=\"1\" Output=\"did status\"", gotResult)
	}
	if gotRouterID != "router-1" {
		t.Errorf("result: %s header = %q, want %q", RouterIDHeader, gotRouterID, "router-1")
	}
}

func TestRun_SendsHeartbeatWhenStatusFuncSet(t *testing.T) {
	var mu sync.Mutex
	var gotStatus string

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/poll", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PollResponse{})
	})
	mux.HandleFunc("/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var hb Heartbeat
		_ = json.NewDecoder(r.Body).Decode(&hb)
		mu.Lock()
		gotStatus = hb.Status
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	opts := AgentOptions{
		ControlServerURL:  srv.URL,
		RouterID:          "router-1",
		Token:             "t",
		FingerprintSHA256: fingerprintOf(t, srv),
		PollInterval:      time.Second,
		StatusFunc:        func(context.Context) string { return "agent: v0.4.3\nfailover: ACTIVE_PRIMARY" },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = Run(ctx, opts, &fakeHandler{})

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(gotStatus, "ACTIVE_PRIMARY") {
		t.Errorf("heartbeat status = %q, want it to carry the rendered snapshot", gotStatus)
	}
}

// TestRunBounded_CapsStuckCallAtTimeout is the regression test for a
// real incident: a router went silent for 17+ minutes with no recovery.
// Root cause traced to Run's select loop dispatching Handle/StatusFunc
// with the agent's whole-lifetime ctx -- uncancelled short of shutdown,
// so a single slow call (Daemon.Snapshot blocking on Daemon.do until a
// busy Daemon goroutine frees up -- ordinarily fast, but unbounded if
// that goroutine is stuck mid-Tick) could hold Run's one goroutine
// hostage indefinitely, and since poll/heartbeat/handle all share that
// goroutine, nothing else -- including the next poll, the only thing
// that clears "не выходит на связь" -- could run either. This proves
// runBounded's timeout parameter actually cuts such a call short rather
// than waiting on it forever.
func TestRunBounded_CapsStuckCallAtTimeout(t *testing.T) {
	const budget = 50 * time.Millisecond
	done := make(chan time.Duration, 1)

	go func() {
		start := time.Now()
		runBounded(context.Background(), budget, func(c context.Context) {
			<-c.Done() // simulates a call stuck on a resource that never frees up on its own
		})
		done <- time.Since(start)
	}()

	select {
	case elapsed := <-done:
		if elapsed < budget {
			t.Errorf("runBounded returned after %v, want at least the %v budget", elapsed, budget)
		}
		if elapsed > 2*time.Second {
			t.Errorf("runBounded returned after %v, want it capped near the %v budget, not left hanging", elapsed, budget)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runBounded never returned -- a stuck fn must still be bounded by its timeout")
	}
}

// TestRun_SlowHandlerDoesNotStarvePolling is the end-to-end version of
// the same regression: wired through Run with a short CommandTimeout (a
// real deployment uses DefaultCommandTimeout, 60s -- far too long to
// wait out in a test, which is why this test overrides it), a Handle
// call stuck on ctx must still let the poll ticker recover on its own,
// with no external intervention, once the timeout elapses.
func TestRun_SlowHandlerDoesNotStarvePolling(t *testing.T) {
	var mu sync.Mutex
	polls := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		polls++
		n := polls
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			// Only the first poll hands back a command -- that's the one
			// the handler parks on. Later polls must still happen even
			// while it's stuck.
			_ = json.NewEncoder(w).Encode(PollResponse{Command: &Command{ID: "1", Action: ActionStatus}})
			return
		}
		_ = json.NewEncoder(w).Encode(PollResponse{})
	})
	mux.HandleFunc("/agent/result", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	handler := &blockingHandler{}
	opts := AgentOptions{
		ControlServerURL:  srv.URL,
		RouterID:          "router-1",
		Token:             "t",
		FingerprintSHA256: fingerprintOf(t, srv),
		PollInterval:      20 * time.Millisecond,
		CommandTimeout:    30 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = Run(ctx, opts, handler)

	mu.Lock()
	got := polls
	mu.Unlock()
	// 300ms at a 20ms poll interval is up to 15 ticks; the first one
	// dispatches the stuck Handle call, held for up to CommandTimeout
	// (30ms) before runBounded cuts it short. Before that bound existed,
	// this dispatch (and every poll after it, same goroutine) would have
	// hung for the rest of the test, leaving polls at 1.
	if got < 3 {
		t.Errorf("polls = %d, want several more after the first -- a stuck Handle call must not stall the poll ticker", got)
	}
}

func TestRun_WrongTokenNeverCallsHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/agent/poll", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	handler := &fakeHandler{}
	opts := AgentOptions{
		ControlServerURL:  srv.URL,
		RouterID:          "router-1",
		Token:             "wrong-token",
		FingerprintSHA256: fingerprintOf(t, srv),
		PollInterval:      10 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = Run(ctx, opts, handler)

	if atomic.LoadInt32(&handler.calls) != 0 {
		t.Error("handler should never be called when the server rejects the token")
	}
}
