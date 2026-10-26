package adaptiveroute

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The operator's own never-route list: IPv4 addresses and networks that
// adaptive routing must not send into the tunnel, whatever the classifier
// thinks of them. It is a plain text file next to config.json, one entry per
// line, '#' starts a comment -- deliberately NOT a field of config.json:
// the bot's handler holds its own in-memory copy of the config and saves the
// whole struct, so a list edited from SSH (or by hand) would be silently
// overwritten by the next unrelated bot setting. A file of its own has one
// writer at a time and nothing to clobber; the classify loop re-reads it by
// mtime, so an edit from anywhere is live within a tick.

const (
	// maxExclusions bounds the list: every classify tick checks each live
	// entry against it.
	maxExclusions = 512
	// minExclusionPrefix refuses a typo like 0.0.0.0/0 or 10.0.0.0/1 that
	// would silently switch the whole feature off.
	minExclusionPrefix = 8
	exclusionsFileName = "adaptive-exclude.txt"
)

// ExclusionsPath is where the never-route list lives for the config at
// configPath.
func ExclusionsPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), exclusionsFileName)
}

// NormalizeExclusion validates one entry -- an IPv4 address or an IPv4
// network in CIDR form -- and returns its canonical text: a bare address
// stays bare (and a /32 becomes one), a network is written with its network
// address ("10.1.2.3/24" -> "10.1.2.0/24").
func NormalizeExclusion(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("пустой адрес")
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("%q — не IPv4-адрес", s)
		}
		return ip.To4().String(), nil
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil || n.IP.To4() == nil {
		return "", fmt.Errorf("%q — не IPv4-сеть вида a.b.c.d/nn", s)
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return "", fmt.Errorf("%q — не IPv4-сеть вида a.b.c.d/nn", s)
	}
	if ones < minExclusionPrefix {
		return "", fmt.Errorf("%q — слишком широкая сеть (минимум /%d)", s, minExclusionPrefix)
	}
	if ones == 32 {
		return n.IP.To4().String(), nil
	}
	return n.String(), nil
}

// Exclusions is a parsed never-route list. The zero value (and nil) is an
// empty list that excludes nothing.
type Exclusions struct {
	entries []string
	nets    []*net.IPNet
	Skipped int // lines in the file that were not a valid entry
}

// Len is the number of entries.
func (e *Exclusions) Len() int {
	if e == nil {
		return 0
	}
	return len(e.entries)
}

// Entries returns the canonical entries, sorted.
func (e *Exclusions) Entries() []string {
	if e == nil {
		return nil
	}
	return append([]string(nil), e.entries...)
}

// Contains reports whether the single address ip falls inside any entry. A
// string that is not a bare IPv4 address is never contained.
func (e *Exclusions) Contains(ip string) bool {
	if e == nil || len(e.nets) == 0 || strings.Contains(ip, "/") {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range e.nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// Overlaps reports whether the address or network cidr shares any address
// with an entry -- the block-level question: a promoted block redirects
// everything inside it, so one excluded address anywhere in it taints the
// whole block.
func (e *Exclusions) Overlaps(cidr string) bool {
	if e == nil || len(e.nets) == 0 {
		return false
	}
	var cand *net.IPNet
	if strings.Contains(cidr, "/") {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return false
		}
		cand = n
	} else {
		ip := net.ParseIP(cidr)
		if ip == nil || ip.To4() == nil {
			return false
		}
		cand = &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
	}
	for _, n := range e.nets {
		if n.Contains(cand.IP) || cand.Contains(n.IP) {
			return true
		}
	}
	return false
}

// parseExclusions reads the file format: one entry per line, '#' comments
// (whole-line or trailing), blank lines ignored. Invalid lines are counted
// in Skipped, not fatal -- a half-valid list the operator edited by hand
// still protects what it can.
func parseExclusions(text string) *Exclusions {
	e := &Exclusions{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		canon, err := NormalizeExclusion(line)
		if err != nil {
			e.Skipped++
			continue
		}
		if seen[canon] || len(e.entries) >= maxExclusions {
			continue
		}
		seen[canon] = true
		e.entries = append(e.entries, canon)
		_, n, _ := net.ParseCIDR(withMask(canon))
		e.nets = append(e.nets, n)
	}
	sort.Strings(e.entries)
	return e
}

func withMask(canon string) string {
	if strings.Contains(canon, "/") {
		return canon
	}
	return canon + "/32"
}

// LoadExclusions reads the list at path. A missing file is an empty list.
func LoadExclusions(path string) (*Exclusions, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Exclusions{}, nil
		}
		return nil, err
	}
	return parseExclusions(string(data)), nil
}

// exclusionsWriteMu serializes AddExclusion / RemoveExclusion within the
// process (the bot handler and the classify loop share one).
var exclusionsWriteMu sync.Mutex

// AddExclusion appends entry to the list at path unless it is already there,
// returning its canonical form. Other lines (comments, entries the operator
// wrote by hand) are kept verbatim.
func AddExclusion(path, entry string) (canonical string, added bool, err error) {
	canonical, err = NormalizeExclusion(entry)
	if err != nil {
		return "", false, err
	}
	exclusionsWriteMu.Lock()
	defer exclusionsWriteMu.Unlock()

	data, rerr := os.ReadFile(path)
	if rerr != nil && !os.IsNotExist(rerr) {
		return "", false, rerr
	}
	cur := parseExclusions(string(data))
	for _, e := range cur.entries {
		if e == canonical {
			return canonical, false, nil
		}
	}
	if cur.Len() >= maxExclusions {
		return "", false, fmt.Errorf("в списке уже %d исключений — это предел", maxExclusions)
	}
	text := string(data)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	text += canonical + "\n"
	return canonical, true, writeFileAtomic(path, text)
}

// RemoveExclusion drops entry from the list at path, returning its canonical
// form and whether it was there. Other lines are kept verbatim.
func RemoveExclusion(path, entry string) (canonical string, removed bool, err error) {
	canonical, err = NormalizeExclusion(entry)
	if err != nil {
		return "", false, err
	}
	exclusionsWriteMu.Lock()
	defer exclusionsWriteMu.Unlock()

	data, rerr := os.ReadFile(path)
	if rerr != nil {
		if os.IsNotExist(rerr) {
			return canonical, false, nil
		}
		return "", false, rerr
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		bare := line
		if i := strings.IndexByte(bare, '#'); i >= 0 {
			bare = bare[:i]
		}
		if c, cerr := NormalizeExclusion(bare); cerr == nil && c == canonical {
			removed = true
			continue
		}
		out = append(out, line)
	}
	if !removed {
		return canonical, false, nil
	}
	text := strings.Join(out, "\n")
	if text != "" {
		text += "\n"
	}
	return canonical, true, writeFileAtomic(path, text)
}

// writeFileAtomic writes via a temp file + rename, creating the directory,
// like config.Save: a crash mid-write never leaves a half-written list.
func writeFileAtomic(path, text string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".adaptive-exclude-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// SweepExcluded takes out of the redirect set setName every member that
// shares an address with the list (an address inside an excluded network, or a
// promoted block that holds an excluded address), and returns what it removed.
// cleanup, when set, runs once per removed member -- the caller's hook for
// tearing down the connections already caught in the redirect.
//
// This is the sweep for entries the classifier does not track -- l7sni
// additions and whatever survived a restart -- and the immediate, in-hand
// version of what the classify loop does on its own the moment it sees the
// list change. It records nothing in the counters: the loop counts what it
// removes, and a second count here would double it.
func SweepExcluded(ctx context.Context, setName string, ex *Exclusions, cleanup func(ctx context.Context, member string)) (removed []string, err error) {
	if ex.Len() == 0 {
		return nil, nil
	}
	members, err := Members(ctx, setName)
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, m := range members {
		if !ex.Overlaps(m) {
			continue
		}
		if err := RemoveIP(ctx, setName, m); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ForgetNote(m)
		if cleanup != nil {
			cleanup(ctx, m)
		}
		removed = append(removed, m)
	}
	return removed, firstErr
}

// ExclusionsWatcher hands the classify loop the current list cheaply: one
// stat per call, a re-read only when the file's mtime or size changed.
type ExclusionsWatcher struct {
	Path string

	mu      sync.Mutex
	started bool
	mtime   time.Time
	size    int64
	ex      *Exclusions
}

// Get returns the current list and whether it differs from what the
// previous Get returned (always true on the first call). A read error keeps
// the previous list: failing to read must never turn the veto off.
func (w *ExclusionsWatcher) Get() (ex *Exclusions, changed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	fi, err := os.Stat(w.Path)
	switch {
	case err != nil && os.IsNotExist(err):
		changed = !w.started || w.ex.Len() > 0
		w.started, w.mtime, w.size, w.ex = true, time.Time{}, 0, &Exclusions{}
		return w.ex, changed
	case err != nil:
		if w.ex == nil {
			w.ex = &Exclusions{}
		}
		return w.ex, false
	}
	if w.started && fi.ModTime().Equal(w.mtime) && fi.Size() == w.size {
		return w.ex, false
	}
	loaded, lerr := LoadExclusions(w.Path)
	if lerr != nil {
		if w.ex == nil {
			w.ex = &Exclusions{}
		}
		return w.ex, false
	}
	w.started, w.mtime, w.size, w.ex = true, fi.ModTime(), fi.Size(), loaded
	return w.ex, true
}
