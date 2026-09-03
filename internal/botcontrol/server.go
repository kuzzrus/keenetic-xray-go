package botcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// maxResultBytes caps an /agent/result request body. A command result is
// a short status string; this just stops a misbehaving or hostile agent
// (one holding a valid token) from streaming an unbounded body into the
// decoder.
const maxResultBytes = 256 * 1024

// RouterAuth resolves a router ID to its expected bearer token, and
// reports whether that router is known at all. Separated from Server so
// tests can supply a trivial in-memory implementation.
type RouterAuth interface {
	TokenFor(routerID string) (token string, ok bool)
}

// StaticRouterAuth is a fixed router-ID -> token map, typically loaded
// once at startup from the control server's own config file. Registering
// a new router means adding it there and restarting.
type StaticRouterAuth map[string]string

// TokenFor implements RouterAuth.
func (m StaticRouterAuth) TokenFor(routerID string) (string, bool) {
	token, ok := m[routerID]
	return token, ok
}

// ServerConfig configures NewServer.
type ServerConfig struct {
	Store       *Store
	Auth        RouterAuth
	Fingerprint string      // hex SHA256 of the serving certificate's leaf, served unauthenticated at /fingerprint
	Logger      *log.Logger // nil -> log.Default()

	// OnEvent, if set, is called for each authenticated POST /agent/event.
	// It runs on the request goroutine; keep it quick or hand off. nil ->
	// events are accepted and discarded.
	OnEvent func(routerID string, ev Event)
}

// Server is the control-server's HTTP API: unauthenticated /fingerprint
// for first-trust bootstrapping (an operator reads it once, out of band,
// to configure a new agent), and Bearer+X-Router-Id-authenticated
// /agent/poll and /agent/result for the router agents.
type Server struct {
	cfg ServerConfig
	mux *http.ServeMux
}

// NewServer builds a Server ready to be wrapped in an *http.Server (see
// ListenAndServeTLS).
func NewServer(cfg ServerConfig) *Server {
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/fingerprint", s.handleFingerprint)
	s.mux.HandleFunc("/agent/poll", s.authenticated(s.handlePoll))
	s.mux.HandleFunc("/agent/result", s.authenticated(s.handleResult))
	s.mux.HandleFunc("/agent/event", s.authenticated(s.handleEvent))
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) handleFingerprint(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, s.cfg.Fingerprint)
}

// authenticated wraps next with Bearer-token authentication. The router
// ID comes from RouterIDHeader -- needed to know which token to check
// against before (and regardless of) parsing any body, since /agent/poll
// has no body at all -- and the token from the Authorization header.
//
// Every failure returns the same bare 401, and a constant-time comparison
// of fixed-length SHA-256 digests runs on every request (against a
// throwaway secret when the router ID is unknown), so neither the
// response body nor the response timing reveals whether a given router ID
// is registered or how long its token is.
func (s *Server) authenticated(next func(w http.ResponseWriter, r *http.Request, routerID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		routerID := r.Header.Get(RouterIDHeader)
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		want, known := s.cfg.Auth.TokenFor(routerID)
		if !known {
			// Compare against a value no real token can equal, so the
			// hashing and comparison below still run for an unknown or
			// missing router ID.
			want = "\x00unregistered\x00"
		}
		gotSum := sha256.Sum256([]byte(got))
		wantSum := sha256.Sum256([]byte(want))
		if routerID == "" || !known || subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, routerID)
	}
}

func (s *Server) handlePoll(w http.ResponseWriter, _ *http.Request, routerID string) {
	cmd, err := s.cfg.Store.Dequeue(routerID)
	if err != nil {
		s.cfg.Logger.Printf("dequeue for %s: %v", routerID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(PollResponse{Command: cmd})
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, routerID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxResultBytes)
	var result Result
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := s.cfg.Store.RecordResult(routerID, result); err != nil {
		s.cfg.Logger.Printf("record result for %s: %v", routerID, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request, routerID string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxResultBytes)
	var ev Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(routerID, ev)
	}
	w.WriteHeader(http.StatusOK)
}

// ListenAndServeTLS runs handler as an HTTPS server on addr using cert
// until ctx is cancelled, at which point it shuts down gracefully (5s
// grace period) and returns ctx.Err().
func ListenAndServeTLS(ctx context.Context, addr string, cert tls.Certificate, handler http.Handler) error {
	srv := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		// The API exchanges only small JSON over a fast path; bounded
		// timeouts keep a slow or idle peer (this is a public endpoint)
		// from tying up a connection indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1) // buffered: the goroutine must never block on a send nobody reads
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	}
}
