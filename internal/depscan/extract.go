package depscan

import (
	"bytes"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// Tier says how sure we are that the page really loads a host.
type Tier int

const (
	// TierLikely: the page itself names it where a browser will fetch it
	// -- a script/image/stylesheet/frame tag, a preload or preconnect
	// hint, a Link header, a redirect on the way in.
	TierLikely Tier = iota
	// TierMaybe: mentioned or permitted, not necessarily used -- a
	// Content-Security-Policy allow-list (github.com's names ~77 hosts, a
	// page load touches 3), a URL inside an inline script, a form target.
	TierMaybe
)

// Sources of a found host (Host.Via), most to least specific.
const (
	ViaRedirect = "redirect" // on the redirect chain to the page
	ViaHint     = "hint"     // <link rel=preconnect|dns-prefetch>, same in a Link header
	ViaHTML     = "html"     // a tag attribute or CSS url() the browser will fetch
	ViaCSP      = "csp"      // Content-Security-Policy allow-list
	ViaScript   = "script"   // an absolute URL inside an inline <script>
	ViaForm     = "form"     // <form action>
)

// Bounds on how much of a hostile or enormous page we are willing to
// chew on; the page is untrusted input fetched on a small router.
const (
	maxAttrValue   = 8 << 10   // one attribute value
	maxTagAttrs    = 64        // attributes read from one tag
	maxScriptBytes = 256 << 10 // one inline script
	maxScriptTotal = 1 << 20   // all inline scripts of the page
	maxInlineHosts = 40        // hosts taken from inline scripts
)

// collector gathers hosts from every source of one page.
type collector struct {
	hosts   map[string]*found
	own     string // host:port of the page itself; its references are not dependencies
	skipped int    // IP literals, internal names, IDN: seen, not usable
	inline  int    // hosts taken from inline scripts so far
}

type found struct {
	tier Tier
	via  map[string]struct{}
}

func newCollector() *collector { return &collector{hosts: map[string]*found{}} }

// addHost records one host. A name the route lists could not hold (an IP
// literal, "localhost", a name with a space) is counted as skipped.
func (c *collector) addHost(host, via string, tier Tier) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return
	}
	if !publicName(host) {
		c.skipped++
		return
	}
	f := c.hosts[host]
	if f == nil {
		f = &found{tier: tier, via: map[string]struct{}{}}
		c.hosts[host] = f
	}
	if tier < f.tier {
		f.tier = tier
	}
	f.via[via] = struct{}{}
}

// addURL records the host of ref resolved against base. A relative
// reference has the page's own host and is of no interest.
func (c *collector) addURL(base *url.URL, ref, via string, tier Tier) {
	ref = strings.TrimSpace(ref)
	if ref == "" || len(ref) > maxAttrValue {
		return
	}
	low := strings.ToLower(ref)
	for _, p := range []string{"data:", "javascript:", "mailto:", "tel:", "blob:", "about:", "#"} {
		if strings.HasPrefix(low, p) {
			return
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "ws", "wss":
	default:
		return
	}
	// "Own" is the page's host, not <base>'s: a <base href> pointing at a
	// static host makes every relative reference a dependency on it.
	if c.own != "" && strings.EqualFold(u.Host, c.own) {
		return
	}
	c.addHost(u.Hostname(), via, tier)
}

// addSrcset records every candidate of a srcset ("url 1x, url2 2x").
func (c *collector) addSrcset(base *url.URL, srcset, via string, tier Tier) {
	for _, cand := range strings.Split(srcset, ",") {
		if f := strings.Fields(cand); len(f) > 0 {
			c.addURL(base, f[0], via, tier)
		}
	}
}

// publicName reports whether host is a name the route lists accept as a
// domain and that can exist on the public internet.
func publicName(host string) bool {
	kind, norm, err := config.ClassifyRouteEntry(host)
	if err != nil || kind != config.RouteDomain || norm != host {
		return false
	}
	if i := strings.LastIndexByte(host, '.'); i >= 0 {
		tld := host[i+1:]
		for _, s := range internalSuffixes {
			if tld == s || strings.HasSuffix(host, "."+s) {
				return false
			}
		}
	}
	return true
}

// ---- headers ---------------------------------------------------------

// scanHeaders reads the response headers that name other hosts.
func scanHeaders(h http.Header, base *url.URL, c *collector) {
	if c.own == "" && base != nil {
		c.own = base.Host
	}
	for _, name := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		for _, v := range h.Values(name) {
			scanCSP(v, c)
		}
	}
	for _, v := range h.Values("Link") {
		scanLinkHeader(v, base, c)
	}
}

// cspFetchDirectives are the directives whose sources a page fetches
// from. report-uri, form-action, frame-ancestors and base-uri also list
// hosts but those are not dependencies.
var cspFetchDirectives = map[string]struct{}{
	"default-src": {}, "script-src": {}, "script-src-elem": {}, "style-src": {},
	"style-src-elem": {}, "img-src": {}, "font-src": {}, "connect-src": {},
	"media-src": {}, "frame-src": {}, "child-src": {}, "worker-src": {},
	"manifest-src": {}, "object-src": {}, "prefetch-src": {},
}

func scanCSP(policy string, c *collector) {
	for _, dir := range strings.Split(policy, ";") {
		f := strings.Fields(dir)
		if len(f) < 2 {
			continue
		}
		if _, ok := cspFetchDirectives[strings.ToLower(f[0])]; !ok {
			continue
		}
		for _, tok := range f[1:] {
			if host := cspHost(tok); host != "" {
				c.addHost(host, ViaCSP, TierMaybe)
			}
		}
	}
}

// cspHost extracts the host of one CSP source expression, or "" for a
// keyword ('self'), a bare scheme (data:, https:), "*" or a pattern with a
// wildcard that is not a leading "*." -- for "*.example.com" the base
// domain is returned: the page says it uses some subdomain of it.
func cspHost(tok string) string {
	if tok == "*" || strings.HasPrefix(tok, "'") {
		return ""
	}
	t := tok
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	} else if strings.HasSuffix(t, ":") {
		return "" // a scheme source: data: blob: https:
	}
	if i := strings.IndexAny(t, "/?#"); i >= 0 {
		t = t[:i]
	}
	if i := strings.LastIndexByte(t, ':'); i >= 0 {
		t = t[:i] // port, or ":*"
	}
	t = strings.TrimPrefix(t, "*.")
	if t == "" || strings.Contains(t, "*") {
		return ""
	}
	return t
}

// scanLinkHeader reads `<url>; rel=preload, <url>; rel=preconnect`.
func scanLinkHeader(v string, base *url.URL, c *collector) {
	for len(v) > 0 {
		lt := strings.IndexByte(v, '<')
		if lt < 0 {
			return
		}
		gt := strings.IndexByte(v[lt:], '>')
		if gt < 0 {
			return
		}
		ref := v[lt+1 : lt+gt]
		rest := v[lt+gt+1:]
		end := strings.IndexByte(rest, '<') // the next link starts at the next '<'
		params := rest
		if end >= 0 {
			params, v = rest[:end], rest[end:]
		} else {
			v = ""
		}
		if how := relVia(relOfParams(params)); how != "" {
			c.addURL(base, ref, how, TierLikely)
		}
	}
}

// relOfParams pulls the rel value out of `; rel="preload"; as=script`.
func relOfParams(params string) string {
	low := strings.ToLower(params)
	i := strings.Index(low, "rel=")
	if i < 0 {
		return ""
	}
	v := strings.TrimLeft(low[i+4:], `"' `)
	if j := strings.IndexAny(v, `";,'`); j >= 0 {
		v = v[:j]
	}
	return v
}

// relVia maps a link relation (possibly several, space separated) to the
// source it is reported as, "" when the link is not a fetch of a
// resource (canonical, alternate, next, ...).
func relVia(rel string) string {
	via := ""
	for _, r := range strings.Fields(strings.ToLower(rel)) {
		switch r {
		case "preconnect", "dns-prefetch":
			return ViaHint
		case "stylesheet", "preload", "modulepreload", "prefetch", "icon",
			"apple-touch-icon", "manifest", "mask-icon":
			via = ViaHTML
		}
	}
	return via
}

// ---- HTML ------------------------------------------------------------

var (
	cssURLRe    = regexp.MustCompile(`(?i)url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s"']*))\s*\)`)
	cssImportRe = regexp.MustCompile(`(?i)@import\s+(?:url\(\s*)?(?:"([^"]*)"|'([^']*)')`)
	// An absolute URL in a script: plain, or with JSON-escaped slashes.
	jsURLRe = regexp.MustCompile(`(?i)https?:\\?/\\?/([a-z0-9][a-z0-9.-]*\.[a-z][a-z0-9-]*)`)
)

// scanHTML walks body once, tag by tag, feeding c. It is a scanner, not
// a parser: no tree, no error recovery beyond "skip to the next tag" --
// the only question asked of a page is which hosts its tags point at.
func scanHTML(body []byte, base *url.URL, c *collector) {
	if c.own == "" && base != nil {
		c.own = base.Host
	}
	n := len(body)
	scriptTotal := 0
	for i := 0; i < n; {
		j := bytes.IndexByte(body[i:], '<')
		if j < 0 {
			return
		}
		i += j
		if i+1 >= n {
			return
		}
		ch := body[i+1]
		switch {
		case ch == '!':
			if bytes.HasPrefix(body[i:], []byte("<!--")) {
				k := bytes.Index(body[i+4:], []byte("-->"))
				if k < 0 {
					return
				}
				i += 4 + k + 3
			} else {
				k := bytes.IndexByte(body[i:], '>')
				if k < 0 {
					return
				}
				i += k + 1
			}
		case ch == '/' || ch == '?':
			k := bytes.IndexByte(body[i:], '>')
			if k < 0 {
				return
			}
			i += k + 1
		case isLetter(ch):
			name, attrs, next := parseTag(body, i+1)
			i = next
			if name == "base" {
				if b := attrs["href"]; b != "" {
					if u, err := url.Parse(b); err == nil && u.Host != "" {
						base = u
					}
				}
			}
			handleTag(name, attrs, base, c)
			if name == "script" || name == "style" {
				end := indexCloseTag(body[i:], name)
				text := body[i:]
				if end >= 0 {
					text = body[i : i+end]
				}
				if name == "style" {
					scanCSS(string(clip(text, maxScriptBytes)), base, c)
				} else if attrs["src"] == "" && inlineScriptType(attrs["type"]) && scriptTotal < maxScriptTotal {
					scriptTotal += len(text)
					scanInlineScript(string(clip(text, maxScriptBytes)), c)
				}
				if end < 0 {
					return
				}
				i += end
			}
		default:
			i++
		}
	}
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func clip(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// indexCloseTag finds the "</name" that ends a raw-text element,
// case-insensitively, and returns its offset in b, or -1.
func indexCloseTag(b []byte, name string) int {
	for off := 0; off < len(b); {
		k := bytes.Index(b[off:], []byte("</"))
		if k < 0 {
			return -1
		}
		p := off + k
		if p+2+len(name) <= len(b) && bytes.EqualFold(b[p+2:p+2+len(name)], []byte(name)) {
			return p
		}
		off = p + 2
	}
	return -1
}

// inlineScriptType reports whether an inline <script> of this type holds
// code worth reading URLs out of -- not JSON-LD, an import map or a
// template, which carry schema URLs and markup.
func inlineScriptType(t string) bool {
	t = strings.ToLower(strings.TrimSpace(t))
	switch {
	case t == "", t == "module", strings.Contains(t, "javascript"), strings.Contains(t, "ecmascript"):
		return true
	}
	return false
}

// parseTag reads a start tag whose name begins at body[pos]; it returns
// the lower-cased name, the attributes (lower-cased names, first
// occurrence wins) and the index just past the closing '>'.
func parseTag(body []byte, pos int) (string, map[string]string, int) {
	n := len(body)
	i := pos
	for i < n && !isSpace(body[i]) && body[i] != '/' && body[i] != '>' {
		i++
	}
	name := strings.ToLower(string(body[pos:i]))
	attrs := map[string]string{}
	for i < n {
		for i < n && (isSpace(body[i]) || body[i] == '/') {
			i++
		}
		if i >= n {
			break
		}
		if body[i] == '>' {
			return name, attrs, i + 1
		}
		s := i
		for i < n && !isSpace(body[i]) && body[i] != '=' && body[i] != '>' && body[i] != '/' {
			i++
		}
		key := strings.ToLower(string(body[s:i]))
		for i < n && isSpace(body[i]) {
			i++
		}
		val := ""
		if i < n && body[i] == '=' {
			i++
			for i < n && isSpace(body[i]) {
				i++
			}
			if i < n && (body[i] == '"' || body[i] == '\'') {
				q := body[i]
				i++
				s = i
				for i < n && body[i] != q {
					i++
				}
				val = string(clip(body[s:i], maxAttrValue))
				if i < n {
					i++
				}
			} else {
				s = i
				for i < n && !isSpace(body[i]) && body[i] != '>' {
					i++
				}
				val = string(clip(body[s:i], maxAttrValue))
			}
		}
		if key != "" && len(attrs) < maxTagAttrs {
			if _, dup := attrs[key]; !dup {
				attrs[key] = val
			}
		}
	}
	return name, attrs, n
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' }

// handleTag turns one tag's attributes into hosts.
func handleTag(name string, a map[string]string, base *url.URL, c *collector) {
	if st := a["style"]; strings.Contains(strings.ToLower(st), "url(") {
		scanCSS(st, base, c)
	}
	switch name {
	case "link":
		if via := relVia(a["rel"]); via != "" {
			c.addURL(base, a["href"], via, TierLikely)
			c.addSrcset(base, a["imagesrcset"], via, TierLikely)
		}
	case "script":
		c.addURL(base, a["src"], ViaHTML, TierLikely)
	case "img", "source", "video", "audio", "track", "embed", "iframe", "frame", "input":
		for _, k := range []string{"src", "data-src", "data-lazy-src", "data-original", "poster"} {
			c.addURL(base, a[k], ViaHTML, TierLikely)
		}
		for _, k := range []string{"srcset", "data-srcset"} {
			c.addSrcset(base, a[k], ViaHTML, TierLikely)
		}
	case "object":
		c.addURL(base, a["data"], ViaHTML, TierLikely)
	case "form":
		c.addURL(base, a["action"], ViaForm, TierMaybe)
	case "meta":
		switch strings.ToLower(a["http-equiv"]) {
		case "refresh":
			if i := strings.Index(strings.ToLower(a["content"]), "url="); i >= 0 {
				c.addURL(base, strings.Trim(a["content"][i+4:], `"' `), ViaRedirect, TierLikely)
			}
		case "content-security-policy":
			scanCSP(a["content"], c)
		}
	}
}

// scanCSS reads url(...) and @import references out of CSS text.
func scanCSS(css string, base *url.URL, c *collector) {
	for _, m := range cssURLRe.FindAllStringSubmatch(css, -1) {
		c.addURL(base, firstNonEmpty(m[1:]...), ViaHTML, TierLikely)
	}
	for _, m := range cssImportRe.FindAllStringSubmatch(css, -1) {
		c.addURL(base, firstNonEmpty(m[1:]...), ViaHTML, TierLikely)
	}
}

// scanInlineScript reads absolute URLs out of inline script text. They are
// a weak signal -- API endpoints and analytics, but also links the page
// never follows -- so they are TierMaybe and capped.
func scanInlineScript(js string, c *collector) {
	for _, m := range jsURLRe.FindAllStringSubmatch(js, -1) {
		if c.inline >= maxInlineHosts {
			return
		}
		h := strings.ToLower(strings.TrimSuffix(m[1], "."))
		if inSuffixes(h, ignoredSuffixes) {
			continue
		}
		c.inline++
		c.addHost(h, ViaScript, TierMaybe)
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
