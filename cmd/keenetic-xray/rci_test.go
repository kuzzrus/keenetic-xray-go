package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

func rciFakeRouter(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/rci/show/running-config", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"message":["system","    hostname test","!"]}`))
	})
	mux.HandleFunc("/rci/show/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"release":"5.1.3"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestRCIProbe_ExplicitURL(t *testing.T) {
	srv := rciFakeRouter(t)
	base, detail, err := rciProbe(srv.URL, "")
	if err != nil {
		t.Fatalf("rciProbe: %v", err)
	}
	if base != srv.URL {
		t.Errorf("base = %q, want %q", base, srv.URL)
	}
	if detail == "" {
		t.Error("detail should not be empty on success")
	}
}

func TestRCIProbe_AllCandidatesDown(t *testing.T) {
	// 127.0.0.1:1 is not listening.
	if _, _, err := rciProbe("http://127.0.0.1:1", ""); err == nil {
		t.Error("expected an error when nothing answers")
	}
}

func TestRCIEnableDisable_RoundTrip(t *testing.T) {
	srv := rciFakeRouter(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	if err := config.Default().Save(path); err != nil {
		t.Fatal(err)
	}

	if err := cmdRCI([]string{"enable", srv.URL}); err != nil {
		t.Fatalf("rci enable: %v", err)
	}
	cfg, _ := config.Load(path)
	if !cfg.RCI.Enabled || cfg.RCI.URL != srv.URL {
		t.Fatalf("after enable: RCI = %+v, want Enabled with URL %q", cfg.RCI, srv.URL)
	}

	if err := cmdRCI([]string{"disable"}); err != nil {
		t.Fatalf("rci disable: %v", err)
	}
	cfg, _ = config.Load(path)
	if cfg.RCI.Enabled {
		t.Errorf("after disable: RCI still enabled: %+v", cfg.RCI)
	}
}

func TestRCIEnable_DefaultURLNotPinned(t *testing.T) {
	// A probe that lands on config.DefaultRCIURL should store URL="" so a
	// later DefaultRCIURL change is picked up. We can't bind :79 in a
	// test, so just check the pin logic directly via BaseURL.
	c := config.RCIConfig{Enabled: true}
	if c.BaseURL() != config.DefaultRCIURL {
		t.Errorf("BaseURL() = %q, want default %q", c.BaseURL(), config.DefaultRCIURL)
	}
	c.URL = "http://127.0.0.1:80"
	if c.BaseURL() != "http://127.0.0.1:80" {
		t.Errorf("BaseURL() = %q, want the pinned value", c.BaseURL())
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it
// printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	return <-done
}

// TestRCIToken_StoredNeverPrinted: `rci token` saves the token, checks
// it against RCI, and never prints it back; without one, a 5.2-style
// router's refusal comes with the way to fix it.
func TestRCIToken_StoredNeverPrinted(t *testing.T) {
	const token = "4RZVZobf1GUbarwNL0irYboZut05Aqpby8y"
	inner := rciFakeRouter(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(keenetic.RCITokenHeader) != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	path := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", path)
	cfg := config.Default()
	cfg.RCI.URL = srv.URL
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}

	if err := cmdRCI([]string{"enable", srv.URL}); err == nil || !strings.Contains(err.Error(), "rci token") {
		t.Errorf("enable without a token: err = %v, want the `rci token` hint", err)
	}
	if err := cmdRCI([]string{"token", "not a token"}); err == nil {
		t.Error("a malformed token was accepted")
	}

	var cmdErr error
	out := captureStdout(t, func() { cmdErr = cmdRCI([]string{"token", token}) })
	if cmdErr != nil || !strings.Contains(out, "RCI отвечает") {
		t.Fatalf("rci token: %v\n%s", cmdErr, out)
	}
	if strings.Contains(out, token) {
		t.Errorf("rci token printed the token:\n%s", out)
	}
	if saved, _ := config.Load(path); saved.RCI.Token != token {
		t.Fatalf("saved token = %q", saved.RCI.Token)
	}
	if out := captureStdout(t, func() { _ = cmdRCI([]string{"show"}) }); strings.Contains(out, token) || !strings.Contains(out, "задан (") {
		t.Errorf("rci show:\n%s", out)
	}

	if err := cmdRCI([]string{"token", "clear"}); err != nil {
		t.Fatal(err)
	}
	if saved, _ := config.Load(path); saved.RCI.Token != "" {
		t.Error("`rci token clear` kept the token")
	}
}
