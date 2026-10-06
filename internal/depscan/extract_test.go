package depscan

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// collected renders what a collector holds as "host: tier via,via" lines,
// sorted, for table comparisons.
func collected(c *collector) map[string]string {
	out := map[string]string{}
	for h, f := range c.hosts {
		var via []string
		for v := range f.via {
			via = append(via, v)
		}
		sort.Strings(via)
		tier := "A"
		if f.tier == TierMaybe {
			tier = "B"
		}
		out[h] = tier + " " + strings.Join(via, ",")
	}
	return out
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

const sampleHTML = `<!doctype html><html><head>
<link rel="preconnect" href="https://hint.example-a.net">
<link rel="dns-prefetch" href="//dns.example-b.net">
<link rel="stylesheet" href="https://css.example-c.net/a.css">
<link rel="canonical" href="https://canon.example-z.net/">
<link rel="icon" href="/favicon.ico">
<script src="//js.example-d.net/x.js"></script>
<script async src='https://single.example-e.net/y.js'></script>
<style>@import url("https://imp.example-f.net/f.css"); body{background:url(https://bg.example-g.net/i.png)}</style>
</head><body style="background-image:url('https://inl.example-h.net/p.png')">
<img src="https://img.example-i.net/a.png" srcset="https://s1.example-j.net/a.png 1x, https://s2.example-j.net/a@2x.png 2x">
<img data-src="https://lazy.example-k.net/l.png">
<iframe src="https://frame.example-l.net/e"></iframe>
<video poster="https://poster.example-m.net/p.jpg"><source src="https://vid.example-n.net/v.mp4"></video>
<form action="https://form.example-o.net/post"></form>
<a href="https://nav.example-p.net/">a link, not a dependency</a>
<!-- <img src="https://comment.example-q.net/a.png"> -->
<script type="application/ld+json">{"@context":"https://schema.org","image":"https://ld.example-r.net/i.png"}</script>
<script>fetch("https://api.example-s.net/v1"); var w = "https:\/\/esc.example-t.net\/x"; var ns="http://www.w3.org/2000/svg";</script>
<meta http-equiv="refresh" content="5; url=https://refresh.example-u.net/">
<meta http-equiv="Content-Security-Policy" content="img-src https://metacsp.example-v.net 'self'">
<img src="/relative.png"><img src="data:image/gif;base64,AAAA"><img src="https://example.com/own.png">
</body></html>`

func TestScanHTML_EveryTagKind(t *testing.T) {
	c := newCollector()
	scanHTML([]byte(sampleHTML), mustURL(t, "https://example.com/page"), c)
	want := map[string]string{
		"hint.example-a.net":    "A hint",
		"dns.example-b.net":     "A hint",
		"css.example-c.net":     "A html",
		"js.example-d.net":      "A html", // protocol-relative takes the page's scheme
		"single.example-e.net":  "A html",
		"imp.example-f.net":     "A html",
		"bg.example-g.net":      "A html",
		"inl.example-h.net":     "A html", // a style="" attribute
		"img.example-i.net":     "A html",
		"s1.example-j.net":      "A html",
		"s2.example-j.net":      "A html",
		"lazy.example-k.net":    "A html",
		"frame.example-l.net":   "A html",
		"poster.example-m.net":  "A html",
		"vid.example-n.net":     "A html",
		"form.example-o.net":    "B form",
		"api.example-s.net":     "B script",
		"esc.example-t.net":     "B script", // JSON-escaped slashes
		"refresh.example-u.net": "A redirect",
		"metacsp.example-v.net": "B csp",
	}
	got := collected(c)
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s = %q, want %q", h, got[h], w)
		}
	}
	for _, h := range []string{
		"canon.example-z.net",   // rel=canonical is not a fetch
		"nav.example-p.net",     // <a href> is navigation
		"comment.example-q.net", // inside a comment
		"ld.example-r.net",      // JSON-LD is data, not code
		"www.w3.org",            // an XML namespace, not a server
		"example.com",           // the page's own host
	} {
		if _, ok := got[h]; ok {
			t.Errorf("%s was collected (%q), want it ignored", h, got[h])
		}
	}
	if len(got) != len(want) {
		t.Errorf("collected %d hosts, want %d: %v", len(got), len(want), got)
	}
}

func TestScanHTML_TagTolerance(t *testing.T) {
	cases := []struct{ name, html, host string }{
		{"unquoted value", `<img src=https://unq.example-a.net/a.png>`, "unq.example-a.net"},
		{"upper-case tag and attribute", `<IMG SRC="https://UP.example-b.net/a.png">`, "up.example-b.net"},
		{"self-closing", `<img src="https://sc.example-c.net/a.png"/>`, "sc.example-c.net"},
		{"spaces around =", `<img src = "https://sp.example-d.net/a.png">`, "sp.example-d.net"},
		{"after a stray less-than", `a < b <img src="https://lt.example-e.net/a.png">`, "lt.example-e.net"},
		{"after a script holding a fake tag", `<script>var s = "<img src='https://no.example-f.net/x'>";</script><img src="https://yes.example-f.net/a.png">`, "yes.example-f.net"},
		{"duplicate attribute: the first wins", `<img src="https://first.example-g.net/a.png" src="https://second.example-g.net/a.png">`, "first.example-g.net"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newCollector()
			scanHTML([]byte(tc.html), mustURL(t, "https://example.com/"), c)
			if _, ok := c.hosts[tc.host]; !ok {
				t.Errorf("want %s, got %v", tc.host, collected(c))
			}
		})
	}
}

// The page is a stranger's: whatever it holds, the scan must not panic,
// loop or read past the end.
func TestScanHTML_Malformed(t *testing.T) {
	for _, s := range []string{
		"", "<", "<a", "<a ", "<a b", "<a b=", `<a b="`, `<img src="https://x.example-a.net`,
		"<!--", "<!-- unterminated", "<!doctype", "</", "<?xml", "<script>", "<script>var a=1;",
		"<style>", "<style>@import", `<img src="https://a.example-b.net/` + strings.Repeat("a", 20000) + `">`,
		strings.Repeat("<a ", 5000), strings.Repeat("<", 100000), "<script></script",
		`<link rel="preconnect" href="`, `<meta http-equiv="refresh" content="url=">`,
	} {
		scanHTML([]byte(s), mustURL(t, "https://example.com/"), newCollector())
	}
}

func TestScanHTML_BaseHref(t *testing.T) {
	c := newCollector()
	scanHTML([]byte(`<base href="https://static.example-a.net/"><img src="pic.png"><img src="https://other.example-b.net/x.png">`),
		mustURL(t, "https://example.com/"), c)
	got := collected(c)
	// A relative reference now resolves against <base>, so it names a host.
	if got["static.example-a.net"] != "A html" || got["other.example-b.net"] != "A html" {
		t.Errorf("got %v", got)
	}
}

func TestScanHTML_InlineScriptsAreCapped(t *testing.T) {
	var js strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&js, `fetch("https://h%d.example-a.net/");`, i)
	}
	c := newCollector()
	scanHTML([]byte("<script>"+js.String()+"</script>"), mustURL(t, "https://example.com/"), c)
	if len(c.hosts) != maxInlineHosts {
		t.Errorf("took %d hosts from inline scripts, want the cap %d", len(c.hosts), maxInlineHosts)
	}
}

func TestScanCSP(t *testing.T) {
	c := newCollector()
	scanCSP("default-src 'self'; img-src https://img.example-a.net data: *.cdn.example-b.net; "+
		"connect-src wss://ws.example-c.net:8443/x https://api.example-d.net; "+
		"report-uri https://report.example-e.net/r; form-action https://form.example-f.net; "+
		"frame-ancestors https://embed.example-g.net; script-src 'nonce-abc' https:", c)
	got := collected(c)
	want := map[string]string{
		"img.example-a.net": "B csp",
		"cdn.example-b.net": "B csp", // "*.cdn.example-b.net" -> the base domain
		"ws.example-c.net":  "B csp",
		"api.example-d.net": "B csp",
	}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s = %q, want %q", h, got[h], w)
		}
	}
	// Directives that are not fetches never contribute.
	for _, h := range []string{"report.example-e.net", "form.example-f.net", "embed.example-g.net"} {
		if _, ok := got[h]; ok {
			t.Errorf("%s collected from a non-fetch directive", h)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
}

func TestCSPHost(t *testing.T) {
	for tok, want := range map[string]string{
		"'self'":                           "",
		"'nonce-abc123'":                   "",
		"'unsafe-inline'":                  "",
		"*":                                "",
		"data:":                            "",
		"blob:":                            "",
		"https:":                           "",
		"https://cdn.example.com":          "cdn.example.com",
		"https://cdn.example.com:8443/p/q": "cdn.example.com",
		"cdn.example.com":                  "cdn.example.com",
		"cdn.example.com:*":                "cdn.example.com",
		"*.example.com":                    "example.com",
		"https://*.example.com":            "example.com",
		"wss://ws.example.com":             "ws.example.com",
		"https://*.foo.*.com":              "",
		"":                                 "",
	} {
		if got := cspHost(tok); got != want {
			t.Errorf("cspHost(%q) = %q, want %q", tok, got, want)
		}
	}
}

func TestScanHeaders_LinkAndCSP(t *testing.T) {
	h := http.Header{}
	h.Add("Link", `</a.css>; rel=preload; as=style, <https://fonts.example-a.net>; rel=preconnect; crossorigin, `+
		`<https://next.example-b.net/p2>; rel="next", <https://js.example-c.net/m.js>; rel="modulepreload"`)
	h.Add("Content-Security-Policy-Report-Only", "img-src https://ro.example-d.net")
	c := newCollector()
	scanHeaders(h, mustURL(t, "https://example.com/"), c)
	got := collected(c)
	want := map[string]string{
		"fonts.example-a.net": "A hint",
		"js.example-c.net":    "A html",
		"ro.example-d.net":    "B csp",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s = %q, want %q", k, got[k], w)
		}
	}
	if _, ok := got["next.example-b.net"]; ok {
		t.Error("rel=next is not a fetch, but was collected")
	}
}

func TestPublicName(t *testing.T) {
	for host, want := range map[string]bool{
		"example.com":           true,
		"a.b.example.co.uk":     true,
		"xn--80asehdb.xn--p1ai": true,
		"localhost":             false,
		"printer.local":         false,
		"router.lan":            false,
		"nas.home.arpa":         false,
		"svc.internal":          false,
		"192.168.1.1":           false,
		"1.2.3.4":               false,
		"экзампл.рф":            false, // IDN must come in punycode
		"has space.com":         false,
		"*.example.com":         false,
		"":                      false,
		"nodots":                false,
		"Example.COM":           false, // callers lower-case first
	} {
		if got := publicName(host); got != want {
			t.Errorf("publicName(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestCollector_CountsSkippedNames(t *testing.T) {
	c := newCollector()
	scanHTML([]byte(`<img src="http://192.168.1.5/a.png"><img src="https://localhost/x"><img src="https://real.example-a.net/y">`),
		mustURL(t, "https://example.com/"), c)
	if c.skipped != 2 || len(c.hosts) != 1 {
		t.Errorf("skipped=%d hosts=%v, want 2 skipped and 1 host", c.skipped, collected(c))
	}
}
