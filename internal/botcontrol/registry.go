package botcontrol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// RouterRecord is a registered router's identity: its bearer token and an
// optional human label. Records live in the same store file as the
// command queues, so adding a router through the bot needs neither a
// restart nor a config-file edit.
type RouterRecord struct {
	Token   string    `json:"token"`
	Name    string    `json:"name,omitempty"`
	AddedAt time.Time `json:"added_at"`
}

// RouterInfo is a read-only view of a registered router for listings.
type RouterInfo struct {
	ID           string
	Name         string
	AddedAt      time.Time
	LastPollAt   time.Time // zero if the router has never polled
	Pending      int
	LastStatus   string    // rendered snapshot from the agent's last heartbeat
	LastStatusAt time.Time // when that snapshot arrived
}

// ValidRouterID reports whether id is safe to use as a router identifier:
// non-empty and only ASCII letters, digits, '_' or '-'. It goes into
// bearer-auth lookups, a JSON key, and Telegram command text, so the
// character set is kept deliberately narrow.
func ValidRouterID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating router token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// AddRouter registers routerID with a freshly generated bearer token and
// returns it. It fails if routerID is invalid or already registered.
func (s *Store) AddRouter(routerID, name string) (string, error) {
	if !ValidRouterID(routerID) {
		return "", fmt.Errorf("invalid router id %q", routerID)
	}
	token, err := generateToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Registry[routerID]; exists {
		return "", fmt.Errorf("router %q is already registered", routerID)
	}
	s.state.Registry[routerID] = &RouterRecord{Token: token, Name: name, AddedAt: time.Now()}
	if err := s.saveLocked(); err != nil {
		delete(s.state.Registry, routerID)
		return "", err
	}
	return token, nil
}

// SeedRouter registers routerID with the given token, but only if it is
// not already in the registry. Used once at startup to carry `routers`
// entries over from config.json without clobbering a token the bot may
// have rotated since.
func (s *Store) SeedRouter(routerID, token, name string) error {
	if !ValidRouterID(routerID) {
		return fmt.Errorf("invalid router id %q", routerID)
	}
	if token == "" {
		return fmt.Errorf("router %q has an empty token", routerID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Registry[routerID]; exists {
		return nil
	}
	s.state.Registry[routerID] = &RouterRecord{Token: token, Name: name, AddedAt: time.Now()}
	return s.saveLocked()
}

// RenameRouter changes a registered router's display name (an empty name
// falls back to the id in listings). It fails if routerID is not
// registered.
func (s *Store) RenameRouter(routerID, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.state.Registry[routerID]
	if !ok {
		return fmt.Errorf("router %q is not registered", routerID)
	}
	prev := rec.Name
	rec.Name = name
	if err := s.saveLocked(); err != nil {
		rec.Name = prev
		return err
	}
	return nil
}

// RemoveRouter unregisters routerID and drops its queue and last result.
// It fails if routerID is not registered.
func (s *Store) RemoveRouter(routerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.state.Registry[routerID]; !exists {
		return fmt.Errorf("router %q is not registered", routerID)
	}
	record := s.state.Registry[routerID]
	queue := s.state.Routers[routerID]
	delete(s.state.Registry, routerID)
	delete(s.state.Routers, routerID)
	if err := s.saveLocked(); err != nil {
		s.state.Registry[routerID] = record
		if queue != nil {
			s.state.Routers[routerID] = queue
		}
		return err
	}
	return nil
}

// TokenFor implements RouterAuth against the registry.
func (s *Store) TokenFor(routerID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.state.Registry[routerID]; ok {
		return rec.Token, true
	}
	return "", false
}

// NameFor returns a registered router's human label, or "" if it has
// none or is not registered.
func (s *Store) NameFor(routerID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.state.Registry[routerID]; ok {
		return rec.Name
	}
	return ""
}

// HasRouter reports whether routerID is registered.
func (s *Store) HasRouter(routerID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.state.Registry[routerID]
	return ok
}

// Routers returns every registered router, sorted by ID.
func (s *Store) Routers() []RouterInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RouterInfo, 0, len(s.state.Registry))
	for id, rec := range s.state.Registry {
		info := RouterInfo{ID: id, Name: rec.Name, AddedAt: rec.AddedAt}
		if rs := s.state.Routers[id]; rs != nil {
			info.LastPollAt = rs.LastPollAt
			info.Pending = len(rs.Pending)
			info.LastStatus = rs.LastStatus
			info.LastStatusAt = rs.LastStatusAt
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
