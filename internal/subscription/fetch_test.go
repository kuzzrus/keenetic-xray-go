package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetch_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello subscription"))
	}))
	defer srv.Close()

	body, err := fetch(context.Background(), srv.URL, time.Second, 1024)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(body) != "hello subscription" {
		t.Errorf("body = %q, want %q", body, "hello subscription")
	}
}

func TestFetch_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := fetch(context.Background(), srv.URL, time.Second, 1024); err == nil {
		t.Error("expected error for 404 status")
	}
}

func TestFetch_SizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 100)))
	}))
	defer srv.Close()

	if _, err := fetch(context.Background(), srv.URL, time.Second, 50); err == nil {
		t.Error("expected error when response exceeds size cap")
	}
}

func TestFetch_UnderSizeCapSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 50)))
	}))
	defer srv.Close()

	body, err := fetch(context.Background(), srv.URL, time.Second, 50)
	if err != nil {
		t.Fatalf("fetch at exactly the cap should succeed: %v", err)
	}
	if len(body) != 50 {
		t.Errorf("len(body) = %d, want 50", len(body))
	}
}

func TestFetch_StopsAfterTooManyRedirects(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer srv.Close()

	if _, err := fetch(context.Background(), srv.URL, time.Second, 1024); err == nil {
		t.Error("expected an error when the endpoint redirects endlessly")
	}
	if hits > maxRedirects+1 {
		t.Errorf("followed %d requests, want at most %d", hits, maxRedirects+1)
	}
}

func TestFetch_SendsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	if _, err := fetch(context.Background(), srv.URL, time.Second, 1024); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotUA != userAgent {
		t.Errorf("User-Agent = %q, want %q", gotUA, userAgent)
	}
}

func TestFetch_Timeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond before the test's timeout fires
	}))
	defer srv.Close()
	defer close(block) // unblock the handler before srv.Close() waits for it

	if _, err := fetch(context.Background(), srv.URL, 50*time.Millisecond, 1024); err == nil {
		t.Error("expected timeout error")
	}
}
