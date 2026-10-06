// Package depscan finds the other hosts a web page needs and works out
// which of them must go through the tunnel.
//
// A route list names domains. A blocked site is added by its own name,
// and then opens -- without its pictures, or without the login -- because
// the page pulls those from other domains (an image store, an auth host, a
// script CDN) that are blocked too and are in no list. This package reads
// the page the way a browser would up to the first request, collects the
// hosts it points at, and opens each of them both directly and through
// the tunnel: the ones that fail directly but work through the tunnel are
// the ones the page needs routed.
//
// What it does not do: run scripts, crawl further pages, or watch a real
// browsing session. Hosts a script decides to contact at run time and that
// the markup never names are invisible to it (measured on habr.com's feed:
// 11 of the 13 hosts a browser touched were found; the two missed were a
// subdomain of the page itself, which a route entry covers anyway, and a
// host loaded by an analytics script).
package depscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// Class is what the scan concluded about one host.
type Class string

const (
	// ClassNeed: does not open directly, opens through the tunnel, and the
	// page really loads it -- the entries worth adding.
	ClassNeed Class = "need"
	// ClassMaybe: would need the tunnel, but only possibly used (a CSP
	// allow-list entry, an inline-script URL), or an ad/analytics host, or
	// the budget ran out before it was checked.
	ClassMaybe Class = "maybe"
	// ClassDirect: opens directly; routing it would only add traffic.
	ClassDirect Class = "direct"
	// ClassDead: opens neither way.
	ClassDead Class = "dead"
	// ClassCovered: an existing route list already carries it.
	ClassCovered Class = "covered"
)

// Host is one external host found on the page.
type Host struct {
	Name      string
	Class     Class
	Tier      Tier
	Via       []string // sources, sorted (the Via* constants)
	Shared    bool     // a service many unrelated sites use (see sharedSuffixes)
	Tracker   bool     // advertising/analytics (see trackerSuffixes)
	Unchecked bool     // the time budget ran out before it was opened
	CoveredBy string   // name of the list that already routes it
	Direct    Reach
	Tunnel    Reach
}

// Page is what was read for one scanned domain.
type Page struct {
	Seed      string // the domain that was asked about
	FinalHost string // where its page ended up after redirects
	Status    int    // HTTP status of the page
	Direct    Reach  // can the seed itself be opened directly?
	Note      string // why the result may be thin, "" when nothing to say
}

// Result is one scan, or several merged (Merge).
type Result struct {
	Pages   []Page
	Hosts   []Host
	More    int // candidates beyond MaxHosts that were not looked at
	Skipped int // IP-literal / internal / non-ASCII names seen and ignored
}

// Options configures Scan.
type Options struct {
	// Tunnel carries the page fetch and the "through the tunnel" probes:
	// requests whose target name is resolved on the far side. Required.
	Tunnel http.RoundTripper
	// Direct is the "direct" side of the probes; nil -> a plain transport.
	Direct http.RoundTripper
	// Prober replaces both of the above for the probes (tests).
	Prober Prober
	// Covered returns the name of a route list that already routes host,
	// "" if none. nil -> nothing is covered.
	Covered func(host string) string
	// Budget bounds the whole scan; 0 -> DefaultBudget.
	Budget time.Duration
	// MaxHosts caps how many candidates are opened; 0 -> DefaultMaxHosts.
	MaxHosts int
	// Workers is the probe parallelism; 0 -> DefaultWorkers.
	Workers int
}

// Defaults. The budget sits well inside the agent's 60 s command limit and
// the 90 s after which the control server calls a router offline: a scan
// holds the agent's single loop for as long as it runs.
const (
	DefaultBudget   = 35 * time.Second
	DefaultMaxHosts = 30
	DefaultWorkers  = 8

	maxBody       = 2 << 20 // bytes of the page read
	maxRedirects  = 5
	fetchTimeout  = 12 * time.Second
	fallbackLimit = 8 * time.Second
)

// ValidSeed checks that s is a domain the scan may fetch -- a public
// name, not an IP, a subnet or an internal host -- and returns it in
// route-list form.
func ValidSeed(s string) (string, error) {
	kind, norm, err := config.ClassifyRouteEntry(s)
	if err != nil {
		return "", err
	}
	if kind != config.RouteDomain {
		return "", fmt.Errorf("%q: нужен домен, а не IP-адрес или подсеть", s)
	}
	if !publicName(norm) {
		return "", fmt.Errorf("%q: внутреннее имя — сканировать нечего", s)
	}
	return norm, nil
}

// Scan reads the page of seed through the tunnel and classifies the hosts
// it points at. A page that cannot be fetched at all is an error; a page
// that can but says little comes back with a Note.
func Scan(ctx context.Context, seed string, o Options) (*Result, error) {
	name, err := ValidSeed(seed)
	if err != nil {
		return nil, err
	}
	// The page must come through the tunnel -- a nil transport would make
	// net/http fall back to a direct fetch of a stranger's URL from the
	// operator's own connection.
	if o.Tunnel == nil {
		return nil, errors.New("туннель не работает — сканировать нечем")
	}
	budget := o.Budget
	if budget <= 0 {
		budget = DefaultBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	prober := o.Prober
	if prober == nil {
		prober = NewProber(o.Direct, o.Tunnel)
	}

	// Is the seed itself reachable without the tunnel? Learned alongside
	// everything else: it costs no extra time (it is only waited for at the
	// very end) and changes what the screen says ("opens directly anyway").
	var seedDirect Reach
	var seedWG sync.WaitGroup
	seedWG.Add(1)
	go func() {
		defer seedWG.Done()
		seedDirect = prober.Direct(ctx, name)
	}()

	pg, ferr := fetchPage(ctx, o.Tunnel, name)
	if ferr != nil {
		cancel()
		seedWG.Wait()
		return nil, fmt.Errorf("через туннель страница %s не открылась: %w", name, ferr)
	}

	res := &Result{Pages: []Page{{Seed: name, FinalHost: pg.final.Hostname(), Status: pg.status}}}
	page := &res.Pages[0]

	c := newCollector()
	for _, h := range pg.chain {
		c.addHost(h, ViaRedirect, TierLikely)
	}
	// An error page's headers and markup describe the error page (a bot
	// check names its own challenge host), not the site.
	switch {
	case pg.status >= 400:
		page.Note = fmt.Sprintf("сайт ответил кодом %d — читать нечего; возможно, он не пускает запросы с адреса туннеля", pg.status)
	case !looksLikeHTML(pg.ctype, pg.body):
		page.Note = "это не HTML-страница (" + pg.ctype + ") — зависимостей не видно"
	default:
		scanHeaders(pg.header, pg.final, c)
		scanHTML(pg.body, pg.final, c)
	}

	hosts := candidates(c, name, o.Covered)
	res.Skipped = c.skipped
	if len(hosts) == 0 && page.Note == "" {
		page.Note = "ничего внешнего не нашлось: сайт самодостаточен, либо страница строится скриптами"
	}

	// Look at the likeliest first and no more than MaxHosts of them; the
	// rest are counted, not listed. Covered hosts need no probe and do not
	// count against the cap.
	sort.SliceStable(hosts, func(i, j int) bool {
		a, b := hosts[i], hosts[j]
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		if len(a.Via) != len(b.Via) {
			return len(a.Via) > len(b.Via)
		}
		return a.Name < b.Name
	})
	limit := o.MaxHosts
	if limit <= 0 {
		limit = DefaultMaxHosts
	}
	kept := make([]Host, 0, len(hosts))
	probes := 0
	for _, h := range hosts {
		if h.CoveredBy == "" {
			if probes >= limit {
				res.More++
				continue
			}
			probes++
		}
		kept = append(kept, h)
	}
	hosts = kept
	var todo []*Host
	for i := range hosts {
		if hosts[i].CoveredBy == "" {
			todo = append(todo, &hosts[i])
		}
	}
	probeAll(ctx, prober, todo, o.Workers)
	seedWG.Wait()
	page.Direct = seedDirect

	for i := range hosts {
		hosts[i].Class = classify(&hosts[i])
	}
	sortHosts(hosts)
	res.Hosts = hosts
	return res, nil
}

// candidates turns the collector into hosts, dropping the seed's own
// names (a route entry for example.com already covers its subdomains) and
// marking those an existing list carries.
func candidates(c *collector, seed string, covered func(string) string) []Host {
	out := make([]Host, 0, len(c.hosts))
	for name, f := range c.hosts {
		if name == seed || strings.HasSuffix(name, "."+seed) {
			continue
		}
		h := Host{
			Name:    name,
			Tier:    f.tier,
			Shared:  inSuffixes(name, sharedSuffixes),
			Tracker: inSuffixes(name, trackerSuffixes),
		}
		for v := range f.via {
			h.Via = append(h.Via, v)
		}
		sort.Strings(h.Via)
		if covered != nil {
			h.CoveredBy = covered(name)
		}
		out = append(out, h)
	}
	return out
}

// probeAll opens every host in todo both ways it needs, workers at a time,
// until ctx runs out; a host the budget did not reach is marked Unchecked
// rather than reported as unreachable.
func probeAll(ctx context.Context, p Prober, todo []*Host, workers int) {
	if workers <= 0 {
		workers = DefaultWorkers
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, h := range todo {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				h.Unchecked = true
				return
			}
			if ctx.Err() != nil {
				h.Unchecked = true
				return
			}
			h.Direct = p.Direct(ctx, h.Name)
			if ctx.Err() != nil && !h.Direct.OK {
				h.Unchecked = true // the failure is the budget's, not the host's
				return
			}
			// A host that answers directly needs the tunnel only if what it
			// answers is a refusal that might be a regional one.
			if !h.Direct.OK || geoSuspect(h.Direct.Status) {
				h.Tunnel = p.Tunnel(ctx, h.Name)
				if ctx.Err() != nil && !h.Tunnel.OK {
					h.Unchecked = true
				}
			}
		}(h)
	}
	wg.Wait()
}

// geoSuspect reports whether a direct answer may be a regional refusal
// rather than the site's own: a host can complete TLS and still answer
// 403 or 451 to a country it does not serve.
func geoSuspect(status int) bool { return status == 403 || status == 451 }

// classify decides what to tell the operator about h.
func classify(h *Host) Class {
	switch {
	case h.CoveredBy != "":
		return ClassCovered
	case h.Unchecked:
		return ClassMaybe
	case h.Direct.OK && !geoBlocked(h):
		return ClassDirect
	case h.Tunnel.OK:
		if h.Tier == TierLikely && !h.Tracker {
			return ClassNeed
		}
		return ClassMaybe
	}
	return ClassDead
}

// geoBlocked: the host answered directly with a refusal and answered
// differently through the tunnel.
func geoBlocked(h *Host) bool {
	return h.Direct.OK && geoSuspect(h.Direct.Status) && h.Tunnel.OK && h.Tunnel.Status != h.Direct.Status
}

var classOrder = map[Class]int{ClassNeed: 0, ClassMaybe: 1, ClassDirect: 2, ClassDead: 3, ClassCovered: 4}

func sortHosts(hs []Host) {
	sort.SliceStable(hs, func(i, j int) bool {
		a, b := hs[i], hs[j]
		if classOrder[a.Class] != classOrder[b.Class] {
			return classOrder[a.Class] < classOrder[b.Class]
		}
		if a.Tier != b.Tier {
			return a.Tier < b.Tier
		}
		return a.Name < b.Name
	})
}

// Merge combines several scans (one per domain the operator added) into
// one result: a host found by more than one keeps its best class, and a
// host that is itself one of the scanned domains (or under one) is
// dropped -- the operator is adding it anyway.
func Merge(rs ...*Result) *Result {
	out := &Result{}
	byName := map[string]int{}
	for _, r := range rs {
		if r == nil {
			continue
		}
		out.Pages = append(out.Pages, r.Pages...)
		out.More += r.More
		out.Skipped += r.Skipped
		for _, h := range r.Hosts {
			if i, ok := byName[h.Name]; ok {
				if classOrder[h.Class] < classOrder[out.Hosts[i].Class] {
					out.Hosts[i] = h
				}
				continue
			}
			byName[h.Name] = len(out.Hosts)
			out.Hosts = append(out.Hosts, h)
		}
	}
	kept := out.Hosts[:0]
	for _, h := range out.Hosts {
		own := false
		for _, p := range out.Pages {
			if h.Name == p.Seed || strings.HasSuffix(h.Name, "."+p.Seed) {
				own = true
				break
			}
		}
		if !own {
			kept = append(kept, h)
		}
	}
	out.Hosts = kept
	sortHosts(out.Hosts)
	return out
}

// Count returns how many hosts have class c.
func (r *Result) Count(c Class) int {
	n := 0
	for _, h := range r.Hosts {
		if h.Class == c {
			n++
		}
	}
	return n
}

// ---- fetching the page ------------------------------------------------

// redirectError is a redirect the scan refuses to follow; its text is
// shown to the operator as is.
type redirectError struct{ msg string }

func (e *redirectError) Error() string { return e.msg }

type fetched struct {
	status int
	final  *url.URL
	header http.Header
	ctype  string
	body   []byte
	chain  []string // hosts on the redirect chain, final one included
}

// fetchPage gets https://name/ through rt, falling back to the www
// variant when the bare name does not answer at all. Redirects are
// followed by hand-written rules: https/http only, the default ports,
// public names only, a handful of hops -- the page is a stranger's, and
// the request leaves from the operator's own server.
func fetchPage(ctx context.Context, rt http.RoundTripper, name string) (*fetched, error) {
	urls := []string{"https://" + name + "/"}
	if !strings.HasPrefix(name, "www.") {
		urls = append(urls, "https://www."+name+"/")
	}
	var errs []error
	for i, u := range urls {
		limit := fetchTimeout
		if i > 0 {
			limit = fallbackLimit
		}
		pg, err := fetchOne(ctx, rt, u, limit)
		if err == nil {
			return pg, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func fetchOne(ctx context.Context, rt http.RoundTripper, rawURL string, limit time.Duration) (*fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	var chain []string
	client := &http.Client{
		Transport: rt,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return &redirectError{"слишком много редиректов"}
			}
			if s := req.URL.Scheme; s != "https" && s != "http" {
				return &redirectError{fmt.Sprintf("редирект на %s://", s)}
			}
			if p := req.URL.Port(); p != "" && p != "80" && p != "443" {
				return &redirectError{fmt.Sprintf("редирект на порт %s", p)}
			}
			if !publicName(strings.ToLower(req.URL.Hostname())) {
				return &redirectError{fmt.Sprintf("редирект на %q — не публичное имя", req.URL.Hostname())}
			}
			chain = append(chain, strings.ToLower(req.URL.Hostname()))
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru,en;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", req.URL.Hostname(), reason(err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil && len(body) == 0 {
		return nil, fmt.Errorf("%s: %s", req.URL.Hostname(), reason(err))
	}
	ct := resp.Header.Get("Content-Type")
	if mt, _, perr := mime.ParseMediaType(ct); perr == nil {
		ct = mt
	}
	return &fetched{
		status: resp.StatusCode,
		final:  resp.Request.URL,
		header: resp.Header,
		ctype:  ct,
		body:   body,
		chain:  append([]string{req.URL.Hostname()}, chain...),
	}, nil
}

// looksLikeHTML: the declared type says so, or says nothing and the body
// starts like markup.
func looksLikeHTML(ctype string, body []byte) bool {
	switch strings.ToLower(ctype) {
	case "text/html", "application/xhtml+xml":
		return true
	case "", "application/octet-stream", "text/plain":
		head := strings.ToLower(strings.TrimSpace(string(clip(body, 512))))
		return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html") || strings.Contains(head, "<head")
	}
	return false
}
