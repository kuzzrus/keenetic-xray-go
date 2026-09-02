package botcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func testServer(t *testing.T) (*httptest.Server, *Store) {
	t.Helper()
	store, err := LoadStore("")
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	auth := StaticRouterAuth{"router-1": "token-1"}
	srv := NewServer(ServerConfig{Store: store, Auth: auth, Fingerprint: "deadbeef"})
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts, store
}

func TestServer_Fingerprint_Unauthenticated(t *testing.T) {
	ts, _ := testServer(t)

	resp, err := http.Get(ts.URL + "/fingerprint")
	if err != nil {
		t.Fatalf("GET /fingerprint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if got := buf.String(); got != "deadbeef\n" {
		t.Errorf("body = %q, want \"deadbeef\\n\"", got)
	}
}

func doAuthed(t *testing.T, ts *httptest.Server, path, routerID, token string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(RouterIDHeader, routerID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

func TestServer_Poll_WrongTokenRejected(t *testing.T) {
	ts, _ := testServer(t)
	resp := doAuthed(t, ts, "/agent/poll", "router-1", "wrong-token", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestServer_Poll_UnknownRouterRejected(t *testing.T) {
	ts, _ := testServer(t)
	resp := doAuthed(t, ts, "/agent/poll", "no-such-router", "token-1", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestServer_Auth_RejectionIsUniform(t *testing.T) {
	// An unknown router ID and a known router ID with the wrong token
	// must be indistinguishable from the client side -- same status,
	// same body -- so the endpoint can't be used to enumerate which
	// router IDs are registered.
	ts, _ := testServer(t)

	readAll := func(routerID, token string) (int, string) {
		resp := doAuthed(t, ts, "/agent/poll", routerID, token, nil)
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}

	unknownCode, unknownBody := readAll("no-such-router", "whatever")
	wrongCode, wrongBody := readAll("router-1", "wrong-token")

	if unknownCode != http.StatusUnauthorized || wrongCode != http.StatusUnauthorized {
		t.Fatalf("status codes = %d / %d, want 401 / 401", unknownCode, wrongCode)
	}
	if unknownBody != wrongBody {
		t.Errorf("bodies differ: unknown-router %q vs wrong-token %q", unknownBody, wrongBody)
	}
}

func TestServer_Poll_MissingRouterIDHeaderRejected(t *testing.T) {
	ts, _ := testServer(t)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/agent/poll", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer token-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestServer_Poll_EmptyThenQueuedCommand(t *testing.T) {
	ts, store := testServer(t)

	resp := doAuthed(t, ts, "/agent/poll", "router-1", "token-1", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var empty PollResponse
	if err := json.NewDecoder(resp.Body).Decode(&empty); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if empty.Command != nil {
		t.Errorf("Command = %+v, want nil (nothing queued yet)", empty.Command)
	}

	id, err := store.Enqueue("router-1", ActionStatus, nil)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	resp2 := doAuthed(t, ts, "/agent/poll", "router-1", "token-1", nil)
	defer resp2.Body.Close()
	var got PollResponse
	if err := json.NewDecoder(resp2.Body).Decode(&got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Command == nil || got.Command.ID != id || got.Command.Action != ActionStatus {
		t.Errorf("Command = %+v, want ID=%s Action=%s", got.Command, id, ActionStatus)
	}
}

func TestServer_Result_StoredAndRetrievable(t *testing.T) {
	ts, store := testServer(t)

	result := Result{CommandID: "cmd-1", Output: "all good", Completed: time.Now()}
	body, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp := doAuthed(t, ts, "/agent/result", "router-1", "token-1", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	got := store.LastResult("router-1")
	if got == nil || got.CommandID != "cmd-1" || got.Output != "all good" {
		t.Errorf("LastResult = %+v, want CommandID=cmd-1 Output=\"all good\"", got)
	}
}

func TestServer_Result_InvalidBodyRejected(t *testing.T) {
	ts, _ := testServer(t)
	resp := doAuthed(t, ts, "/agent/result", "router-1", "token-1", []byte("not json"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestServer_GetOnPollRejected(t *testing.T) {
	ts, _ := testServer(t)
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/agent/poll", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer token-1")
	req.Header.Set(RouterIDHeader, "router-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

func TestListenAndServeTLS_ShutsDownOnContextCancel(t *testing.T) {
	cert, err := GenerateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- ListenAndServeTLS(ctx, "127.0.0.1:0", cert, http.NotFoundHandler())
	}()

	// Give the listener goroutine a moment to actually start before
	// cancelling -- this test only cares that cancellation causes a
	// prompt, clean shutdown, not that binding itself is instant.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("ListenAndServeTLS returned %v, want context.Canceled", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("ListenAndServeTLS did not shut down within 6s of context cancellation")
	}
}
