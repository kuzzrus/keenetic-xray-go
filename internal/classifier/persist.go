package classifier

import (
	"encoding/json"
	"os"
	"time"
)

// persistedState is State's on-disk shape. Only Test/OK/Cooldown carry
// over a restart -- Watch is short-lived, SOFT-pass-scoped bookkeeping
// not worth persisting: a missed late-stall confirmation right after a
// restart just means the next SOFT pass starts a fresh watch window,
// costing at most one extra WatchTTL before catching it again. Blocks
// isn't persisted either, for a similar reason: ClrBlockPromote derives
// it fresh from whatever's currently in OK on every pass, so once OK is
// restored a still-qualifying block gets re-promoted on the very first
// post-restart pass -- a redundant (but harmless, ipset "-exist" is
// idempotent) re-add, not a gap.
type persistedState struct {
	Test, OK, Cooldown [2]ttlSet
}

// SaveState writes state's Test/OK/Cooldown sets to path as JSON,
// atomically (temp file + rename, same convention as config.Save) so a
// crash mid-write never leaves a corrupt file.
func SaveState(path string, state *State) error {
	ps := persistedState{Test: state.Test, OK: state.OK, Cooldown: state.Cooldown}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadState reads a previously saved state file into a fresh State.
// Already-expired entries are dropped on load (the file may be old --
// e.g. the router was off a while), same as a live read already treats
// them as absent; this just avoids carrying obviously-dead entries
// forward. A missing file returns an empty State, not an error (first
// run).
func LoadState(path string) (*State, error) {
	state := NewState()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, err
	}
	var ps persistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		return nil, err
	}
	now := time.Now()
	for i := 0; i < 2; i++ {
		copyLive(state.Test[i], ps.Test[i], now)
		copyLive(state.OK[i], ps.OK[i], now)
		copyLive(state.Cooldown[i], ps.Cooldown[i], now)
	}
	return state, nil
}

func copyLive(dst, src ttlSet, now time.Time) {
	for addr, exp := range src {
		if exp.After(now) {
			dst[addr] = exp
		}
	}
}
