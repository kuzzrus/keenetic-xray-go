package xrayctl

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSOCKS5Server is a minimal SOCKS5 CONNECT-only server for testing
// Probe/dialSOCKS5 without a real xray binary: it accepts the standard
// no-auth handshake, then dials the requested domain:port itself and
// splices the two connections together.
func fakeSOCKS5Server(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleFakeSOCKS5Conn(conn)
		}
	}()

	return ln.Addr().String()
}

func handleFakeSOCKS5Conn(conn net.Conn) {
	defer conn.Close()

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return
	}
	nMethods := int(greeting[1])
	if _, err := io.CopyN(io.Discard, conn, int64(nMethods)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { // no-auth selected
		return
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	var host string
	switch header[3] {
	case 0x03: // domain name
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes)

	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // general failure
		return
	}
	defer target.Close()

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil { // success
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, conn); done <- struct{}{} }()
	go func() { io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

func TestProbe_Success(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	socksAddr := fakeSOCKS5Server(t)

	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr: socksAddr,
		URL:       backend.URL,
		Timeout:   2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProbe_UpstreamError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	socksAddr := fakeSOCKS5Server(t)

	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr: socksAddr,
		URL:       backend.URL,
		Timeout:   2 * time.Second,
	})
	if err == nil {
		t.Error("expected error for 500 status")
	}
}

func TestProbe_RetriesBeforeSucceeding(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 { // fail the first 2 attempts, succeed the 3rd
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	socksAddr := fakeSOCKS5Server(t)
	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr:  socksAddr,
		URL:        backend.URL,
		Retries:    2,
		RetryDelay: 10 * time.Millisecond,
		Timeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("backend was hit %d times, want 3 (2 failures + 1 success)", got)
	}
}

func TestProbe_ExhaustsRetriesThenFails(t *testing.T) {
	var hits int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()

	socksAddr := fakeSOCKS5Server(t)
	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr:  socksAddr,
		URL:        backend.URL,
		Retries:    2,
		RetryDelay: 10 * time.Millisecond,
		Timeout:    2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error once all attempts fail")
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Errorf("backend was hit %d times, want 3 (1 + 2 retries)", got)
	}
}

func TestProbe_FallsBackToSecondURL(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer good.Close()

	socksAddr := fakeSOCKS5Server(t)
	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr:    socksAddr,
		URL:          bad.URL,
		FallbackURLs: []string{good.URL},
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Probe: %v, want the fallback URL to save it", err)
	}
}

func TestProbe_AllURLsFail(t *testing.T) {
	bad1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad1.Close()
	bad2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad2.Close()

	socksAddr := fakeSOCKS5Server(t)
	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr:    socksAddr,
		URL:          bad1.URL,
		FallbackURLs: []string{bad2.URL},
		Timeout:      2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error when every URL fails")
	}
}

// TestProbe_OuterContextBoundsTotalTime is the regression test for a
// real incident: Probe's own Retries/RetryDelay/FallbackURLs/Timeout can
// add up to several times a single Timeout, and Probe has no ceiling of
// its own on the *sum* of every attempt across every URL -- a caller
// that wants "try hard, but never take dramatically longer than a
// single ordinary check" (internal/failover's Daemon.Run, whose one
// goroutine also services heartbeats and forced switches between ticks)
// must wrap ctx itself. This proves that wrap actually works: a short
// outer deadline cuts the whole call short even though the configured
// retry/fallback budget alone would run much longer.
func TestProbe_OuterContextBoundsTotalTime(t *testing.T) {
	var hits int32
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	alsoFailing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer alsoFailing.Close()

	socksAddr := fakeSOCKS5Server(t)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := Probe(ctx, ProbeOptions{
		SOCKSAddr:    socksAddr,
		URL:          failing.URL,
		FallbackURLs: []string{alsoFailing.URL},
		Retries:      5,
		RetryDelay:   500 * time.Millisecond, // retries alone: 2.5s+
		Timeout:      2 * time.Second,        // *2 URLs, up to ~12s+ if unbounded
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error -- every attempt fails")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Probe took %v, want it bounded by the outer context's ~150ms deadline, not by Retries*RetryDelay*len(URLs)", elapsed)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Error("expected at least one attempt before the deadline cut it off")
	}
}

func TestProbe_NoSOCKSServer(t *testing.T) {
	err := Probe(context.Background(), ProbeOptions{
		SOCKSAddr: "127.0.0.1:1", // nothing listens on tcpmux here
		URL:       "https://example.invalid/",
		Timeout:   500 * time.Millisecond,
	})
	if err == nil {
		t.Error("expected error when SOCKS5 proxy is unreachable")
	}
}
