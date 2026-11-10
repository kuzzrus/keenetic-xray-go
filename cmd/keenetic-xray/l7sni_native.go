package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// The router's own DNS-routing lists as a source of names for the L7 capture.
//
// An operator's real lists usually live on the router, not in config.json: the
// ones set up in its web interface ("Маршрутизация DNS", object-groups named
// domain-listN) are what routes their traffic, and this project's own
// `routes` lists are the exception. The router sends a flow down such a list
// only when its own DNS proxy saw the name resolved -- a client that resolves
// over DoH, or connects to a literal address, is the leak the L7 capture
// exists to catch, and the names it can catch it with are exactly the ones on
// those lists. So the capture reads them: every list routed into our own xray
// (config.Config.L7SNIEgress) is a set of names to redirect, every list routed
// anywhere else a set of names to leave alone.
//
// The lists are read with `show running-config` (keenetic.AllRoutes) every
// l7sniRouterRefreshEvery -- far too heavy for the packet path, nothing the
// packet path needs: an edit of a list taking a couple of minutes to reach the
// capture is irrelevant.

// l7sniRouterRefreshEvery is how often the daemon reads the lists again; a
// failed read is retried after l7sniRouterRetryAfter. Variables so a test can
// shrink them.
var (
	l7sniRouterRefreshEvery = 2 * time.Minute
	l7sniRouterRetryAfter   = 30 * time.Second
)

const (
	l7sniRouterReadTimeout = 30 * time.Second

	// l7sniRouterMaxAge is how old the daemon's copy may be before something
	// that needs it right now (the CLI, the bot) reads the lists itself.
	l7sniRouterMaxAge = 10 * time.Minute

	// l7sniRouterMaxNames bounds the names taken from the router's lists. The
	// firmware itself caps a group at 300 entries and the groups at 256, so
	// this is not a limit an ordinary router reaches; it keeps a pathological
	// one from costing megabytes of a small router's memory.
	l7sniRouterMaxNames = 50000
)

// The points below are the only places this file touches the router, so a test
// can stand in for it.
var (
	l7sniReadRoutes      = keenetic.AllRoutes
	l7sniRouterAvailable = keenetic.Available
)

// l7sniRouterNames is one reading of the router's lists, immutable once built:
// the capture's goroutine reads the sets while the refresher builds the next.
type l7sniRouterNames struct {
	allow     l7sniDomainSet // names of lists routed into our own xray
	veto      l7sniDomainSet // names of lists routed elsewhere
	lists     int            // how many lists routed into our xray hold names
	skipped   []string       // the interfaces of the lists that do not, sorted
	truncated bool           // allow was cut at l7sniRouterMaxNames
	at        time.Time
}

// l7sniRouterCache is the latest reading; nil until the first one.
var l7sniRouterCache atomic.Pointer[l7sniRouterNames]

// l7sniRouterNamesFrom sorts the router's lists into names to act on and names
// to leave alone. Skipped: this project's own groups (the config's lists say the
// same about them, and a group the config has since disabled must not live on
// here), and groups that exist but are not routed anywhere (no effect, so no
// opinion). IP and subnet entries are not names.
func l7sniRouterNamesFrom(routes []keenetic.LiveRoute, cfg *config.Config, now time.Time) *l7sniRouterNames {
	r := &l7sniRouterNames{allow: l7sniDomainSet{}, veto: l7sniDomainSet{}, at: now}
	skipped := map[string]bool{}
	for _, lr := range routes {
		if lr.Iface == "" || strings.HasPrefix(lr.Group, keenetic.RouteGroupPrefix) {
			continue
		}
		if cfg.L7SNIEgress(lr.Iface) {
			if len(r.allow) >= l7sniRouterMaxNames {
				r.truncated = true
				continue
			}
			if addDomains(r.allow, lr.Entries) > 0 {
				r.lists++
			}
			continue
		}
		if addDomains(r.veto, lr.Entries) > 0 {
			skipped[lr.Iface] = true
		}
	}
	for iface := range skipped {
		r.skipped = append(r.skipped, iface)
	}
	sort.Strings(r.skipped)
	return r
}

// summary is the reading in a few words; two readings with the same summary are
// not worth a second log line.
func (r *l7sniRouterNames) summary() string {
	s := fmt.Sprintf("%d имён из %d списков", len(r.allow), r.lists)
	if len(r.skipped) > 0 {
		s += ", не смотрю списки через " + strings.Join(r.skipped, ", ")
	}
	if r.truncated {
		s += fmt.Sprintf(" (обрезано до %d)", l7sniRouterMaxNames)
	}
	return s
}

// l7sniReadRouterNames reads the router's lists now.
func l7sniReadRouterNames(ctx context.Context, cfg *config.Config) (*l7sniRouterNames, error) {
	rctx, cancel := context.WithTimeout(ctx, l7sniRouterReadTimeout)
	defer cancel()
	routes, err := l7sniReadRoutes(rctx)
	if err != nil {
		return nil, err
	}
	return l7sniRouterNamesFrom(routes, cfg, time.Now()), nil
}

// l7sniRefreshRouterNames reads the lists and replaces the cache, saying so in
// the log when what the capture will act on has changed.
func l7sniRefreshRouterNames(ctx context.Context, logf func(string, ...any)) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	next, err := l7sniReadRouterNames(ctx, cfg)
	if err != nil {
		return err
	}
	prev := l7sniRouterCache.Swap(next)
	if prev == nil || prev.summary() != next.summary() {
		logf("l7sni: списки роутера — %s", next.summary())
	}
	return nil
}

// l7sniRouterNamesLoop keeps the cache current for as long as the capture runs.
// A failed read leaves the previous reading in place -- names a few minutes old
// are better than none -- and is said once per distinct reason.
func l7sniRouterNamesLoop(ctx context.Context, logf func(string, ...any)) {
	lastErr := ""
	for {
		wait := l7sniRouterRefreshEvery
		if err := l7sniRefreshRouterNames(ctx, logf); err != nil {
			if ctx.Err() != nil {
				return
			}
			if msg := err.Error(); msg != lastErr {
				logf("l7sni: списки роутера прочитать не удалось: %v (повторю через %s, пока работаю с тем, что есть)", err, l7sniRouterRetryAfter)
				lastErr = msg
			}
			wait = l7sniRouterRetryAfter
		} else {
			lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// l7sniNames is what the capture has to match against, for the places that tell
// an operator: the CLI, the stats, diag, the bot.
type l7sniNames struct {
	Config      int      // domains of this config's lists routed into our xray
	Router      int      // domains of the router's lists routed into it
	RouterLists int      // how many of those lists
	Skipped     []string // interfaces of the lists (either source) that are not ours
	Egress      []string // the interfaces that are
	Truncated   bool
	RouterErr   error // the router's lists could not be read
}

// l7sniNamesFor takes stock. The daemon's copy of the router's lists is used
// while it is fresh; otherwise (the CLI is another process, a daemon whose
// reads keep failing) the lists are read here and now.
func l7sniNamesFor(ctx context.Context, cfg *config.Config) l7sniNames {
	n := l7sniNames{Egress: cfg.L7SNIEgressIfaces()}
	var cfgSkipped []string
	n.Config, cfgSkipped = cfg.L7SNIListSummary()
	skipped := map[string]bool{}
	for _, i := range cfgSkipped {
		skipped[i] = true
	}

	if l7sniRouterAvailable() {
		r := l7sniRouterCache.Load()
		if r == nil || time.Since(r.at) > l7sniRouterMaxAge {
			fresh, err := l7sniReadRouterNames(ctx, cfg)
			if err != nil {
				n.RouterErr = err
			} else {
				r = fresh
				l7sniRouterCache.Store(fresh)
			}
		}
		if r != nil {
			n.Router, n.RouterLists, n.Truncated = len(r.allow), r.lists, r.truncated
			for _, i := range r.skipped {
				skipped[i] = true
			}
		}
	}
	for i := range skipped {
		n.Skipped = append(n.Skipped, i)
	}
	sort.Strings(n.Skipped)
	return n
}

// line is the sentence about it. none reports that there is nothing to match:
// the capture then only counts, which an operator must be told rather than left
// to wonder why a running capture never redirects.
func (n l7sniNames) line() (text string, none bool) {
	total := n.Config + n.Router
	var b strings.Builder
	if total > 0 {
		fmt.Fprintf(&b, "Имена для сравнения: %d (из конфига %d, из списков роутера %d", total, n.Config, n.Router)
		if n.RouterLists > 0 {
			fmt.Fprintf(&b, " в %d списках", n.RouterLists)
		}
		b.WriteString(")")
	} else {
		b.WriteString("Сравнивать не с чем: в списках, ведущих через " + strings.Join(n.Egress, "/") + ", нет ни одного домена — имена только считаются")
	}
	if len(n.Skipped) > 0 {
		b.WriteString("; списки через " + strings.Join(n.Skipped, ", ") + " не смотрю — это не наш выход, их имена защищены от переадресации")
	}
	if n.Truncated {
		fmt.Fprintf(&b, "; списки роутера обрезаны до %d имён", l7sniRouterMaxNames)
	}
	if n.RouterErr != nil {
		b.WriteString("; списки роутера прочитать не удалось: " + n.RouterErr.Error())
	}
	return b.String(), total == 0
}

// l7sniNamesLine is l7sniNamesFor(...).line() for a config that has L7 SNI on;
// empty while it is off, when the question does not arise.
func l7sniNamesLine(ctx context.Context, cfg *config.Config) (text string, none bool) {
	if !cfg.L7SNI.Enabled {
		return "", false
	}
	return l7sniNamesFor(ctx, cfg).line()
}

// l7sniNamesFromDisk is l7sniNamesLine for the config as it is saved -- the
// bot's hook (it holds a copy of its own that a button may be about to
// replace, the file is what the capture reads).
func l7sniNamesFromDisk(ctx context.Context) (string, bool) {
	cfg, err := config.Load(configPath())
	if err != nil {
		return "", false
	}
	return l7sniNamesLine(ctx, cfg)
}
