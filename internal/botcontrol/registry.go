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

// maxRouterIDLen bounds ValidRouterID (BOT-04): router IDs get embedded
// directly in Telegram inline-button callback_data, e.g.
// "adnx:"+id+":"+addonID+":router-dns=off" -- the longest composite
// callback this project builds, at 30 fixed bytes plus the ID. Telegram
// rejects callback_data over 64 bytes outright, so every ID this long or
// longer would silently break that button (and, at the old 64-char cap,
// even the bare "router:"+id case: 7+64=71). 32 leaves comfortable
// margin under every composite pattern found (adnx: 30+32=62, dnp:
// 26+32=58) while still being generous for a self-chosen router label.
const maxRouterIDLen = 32

// ValidRouterID reports whether id is safe to use as a router identifier:
// non-empty, no longer than maxRouterIDLen, and only ASCII letters,
// digits, '_' or '-'. It goes into bearer-auth lookups, a JSON key,
// Telegram command text, and inline-button callback_data, so both the
// character set and the length are kept deliberately narrow.
func ValidRouterID(id string) bool {
	if id == "" || len(id) > maxRouterIDLen {
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
// not already in the registry.
func (s *Store) SeedRouter(routerID, token, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed, err := seedRouterLocked(&s.state, routerID, token, name)
	if err != nil {
		return err
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

// seedRouterLocked adds routerID to the registry if it isn't already
// there, reporting whether it made a change. An invalid routerID or
// empty token is an error even if the router already exists, matching
// SeedRouter's original per-call contract. Caller must hold s.mu.
func seedRouterLocked(state *storeState, routerID, token, name string) (bool, error) {
	if !ValidRouterID(routerID) {
		return false, fmt.Errorf("invalid router id %q", routerID)
	}
	if token == "" {
		return false, fmt.Errorf("router %q has an empty token", routerID)
	}
	if _, exists := state.Registry[routerID]; exists {
		return false, nil
	}
	state.Registry[routerID] = &RouterRecord{Token: token, Name: name, AddedAt: time.Now()}
	return true, nil
}

// SeedRoutersFromConfig carries routers pinned in config.json into the
// runtime registry, but only the very first time this Store's state file
// is ever used -- after that, the registry (mutable from the bot with
// /add_router and /remove_router) is the sole source of truth. Without
// the once-only guard, a router removed via the bot came right back on
// every control-server restart as long as config.json still listed it,
// because a plain per-ID SeedRouter call can't tell "never seen" apart
// from "deliberately removed" -- both look like "not currently in the
// registry" (BOT-03).
func (s *Store) SeedRoutersFromConfig(routers map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.ConfigRoutersSeeded {
		return nil
	}
	for id, token := range routers {
		if _, err := seedRouterLocked(&s.state, id, token, ""); err != nil {
			return err
		}
	}
	// Always persist, even with an empty or all-already-present
	// config.Routers: it's the ConfigRoutersSeeded flag itself that must
	// be saved so this doesn't run again next startup.
	s.state.ConfigRoutersSeeded = true
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
