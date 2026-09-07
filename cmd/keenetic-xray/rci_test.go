package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func rciFakeRouter(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ci/running-config.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("system\n    hostname test\n!\n"))
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
	base, detail, err := rciProbe(srv.URL)
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
	if _, _, err := rciProbe("http://127.0.0.1:1"); err == nil {
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
