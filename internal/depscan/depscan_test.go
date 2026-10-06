package depscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fakes -------------------------------------------------------------

type site struct {
	status int
	header http.Header
	body   string
	err    error
}

// fakeTunnel serves canned pages by full URL; a URL it does not know fails
// like an unresolvable name. It records every URL asked for.
type fakeTunnel struct {
	mu    sync.Mutex
	sites map[string]site
	asked []string
}

func (f *fakeTunnel) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.asked = append(f.asked, req.URL.String())
	f.mu.Unlock()
	s, ok := f.sites[req.URL.String()]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: req.URL.Hostname()}
	}
	if s.err != nil {
		return nil, s.err
	}
	h := http.Header{}
	for k, v := range s.header {
		h[k] = v
	}
	if h.Get("Content-Type") == "" {
		h.Set("Content-Type", "text/html; charset=utf-8")
	}
	return &http.Response{StatusCode: s.status, Header: h, Body: io.NopCloser(strings.NewReader(s.body)), Request: req}, nil
}

func page(body string) site { return site{status: 200, body: body} }

// fakeProber answers from two maps; a host in neither fails with a
// timeout both ways. It tracks how many probes ran at once.
type fakeProber struct {
	direct, tunnel map[string]Reach
	delay          time.Duration
	block          bool // wait for ctx instead of answering

	mu        sync.Mutex
	directed  []string
	tunneled  []string
	cur, peak int32
}

func ok(status int) Reach   { return Reach{Tried: true, OK: true, Status: status} }
func fail(why string) Reach { return Reach{Tried: true, Err: why} }

func (p *fakeProber) run(ctx context.Context) {
	n := atomic.AddInt32(&p.cur, 1)
	for {
		peak := atomic.LoadInt32(&p.peak)
		if n <= peak || atomic.CompareAndSwapInt32(&p.peak, peak, n) {
			break
		}
	}
	defer atomic.AddInt32(&p.cur, -1)
	if p.block {
		<-ctx.Done()
		return
	}
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
		}
	}
}

func (p *fakeProber) Direct(ctx context.Context, host string) Reach {
	p.mu.Lock()
	p.directed = append(p.directed, host)
	p.mu.Unlock()
	p.run(ctx)
	if r, ok := p.direct[host]; ok && !p.block {
		return r
	}
	return fail("таймаут")
}

func (p *fakeProber) Tunnel(ctx context.Context, host string) Reach {
	p.mu.Lock()
	p.tunneled = append(p.tunneled, host)
	p.mu.Unlock()
	p.run(ctx)
	if r, ok := p.tunnel[host]; ok && !p.block {
		return r
	}
	return fail("таймаут")
}

func (p *fakeProber) probedDirect(h string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, x := range p.directed {
		if x == h {
			return true
		}
	}
	return false
}

func scanOpts(t *fakeTunnel, p Prober) Options {
	return Options{Tunnel: t, Prober: p, Budget: 5 * time.Second}
}

func hostByName(r *Result, name string) *Host {
	for i := range r.Hosts {
		if r.Hosts[i].Name == name {
			return &r.Hosts[i]
		}
	}
	return nil
}

// ---- Scan ---------------------------------------------------------------

func TestScan_ClassifiesEveryKind(t *testing.T) {
	html := `<html><head>
<link rel="preconnect" href="https://need.example-a.net">
<script src="https://www.googletagmanager.com/gtm.js"></script>
</head><body>
<img src="https://open.example-b.net/a.png">
<img src="https://gone.example-c.net/a.png">
<img src="https://geo.example-d.net/a.png">
<img src="https://listed.example-e.net/a.png">
<img src="https://static.example.com/own-subdomain.png">
<form action="https://form.example-f.net/post"></form>
<img src="http://10.0.0.7/internal.png">
</body></html>`
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": {
		status: 200, body: html,
		header: http.Header{"Content-Security-Policy": {"img-src https://csp.example-g.net"}},
	}}}
	pr := &fakeProber{
		direct: map[string]Reach{
			"example.com":              ok(200),
			"open.example-b.net":       ok(200),
			"geo.example-d.net":        ok(403),
			"csp.example-g.net":        fail("таймаут"),
			"form.example-f.net":       fail("сброс"),
			"need.example-a.net":       fail("таймаут"),
			"www.googletagmanager.com": fail("таймаут"),
		},
		tunnel: map[string]Reach{
			"need.example-a.net":       ok(200),
			"geo.example-d.net":        ok(200), // refused directly, fine through the tunnel
			"csp.example-g.net":        ok(404),
			"form.example-f.net":       ok(200),
			"www.googletagmanager.com": ok(200),
		},
	}
	opts := scanOpts(tun, pr)
	opts.Covered = func(h string) string {
		if h == "listed.example-e.net" {
			return "mine"
		}
		return ""
	}
	res, err := Scan(context.Background(), "Example.COM", opts)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]Class{
		"need.example-a.net":       ClassNeed,    // preconnect hint, refused directly, open through the tunnel
		"geo.example-d.net":        ClassNeed,    // answers 403 directly, 200 through the tunnel: a regional refusal
		"open.example-b.net":       ClassDirect,  // opens directly
		"gone.example-c.net":       ClassDead,    // opens neither way
		"listed.example-e.net":     ClassCovered, // an existing list has it
		"csp.example-g.net":        ClassMaybe,   // only the CSP allow-list names it
		"form.example-f.net":       ClassMaybe,   // only a form target
		"www.googletagmanager.com": ClassMaybe,   // would need the tunnel, but it is a tracker
	}
	for name, class := range want {
		h := hostByName(res, name)
		if h == nil {
			t.Errorf("%s missing from the result", name)
			continue
		}
		if h.Class != class {
			t.Errorf("%s: class %q, want %q (direct=%+v tunnel=%+v)", name, h.Class, class, h.Direct, h.Tunnel)
		}
	}
	if hostByName(res, "static.example.com") != nil {
		t.Error("a subdomain of the seed was listed; the seed's own entry covers it")
	}
	if len(res.Hosts) != len(want) {
		t.Errorf("%d hosts, want %d: %+v", len(res.Hosts), len(want), res.Hosts)
	}
	if res.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1 (the 10.0.0.7 literal)", res.Skipped)
	}
	if pr.probedDirect("listed.example-e.net") {
		t.Error("a host an existing list covers was probed")
	}
	if !hostByName(res, "www.googletagmanager.com").Tracker {
		t.Error("googletagmanager.com not flagged as a tracker")
	}
	// Order: need first, then maybe, direct, dead, covered.
	var order []Class
	for _, h := range res.Hosts {
		if len(order) == 0 || order[len(order)-1] != h.Class {
			order = append(order, h.Class)
		}
	}
	wantOrder := []Class{ClassNeed, ClassMaybe, ClassDirect, ClassDead, ClassCovered}
	if fmt.Sprint(order) != fmt.Sprint(wantOrder) {
		t.Errorf("class order %v, want %v", order, wantOrder)
	}
	if got := res.NeedNames(); fmt.Sprint(got) != "[geo.example-d.net need.example-a.net]" {
		t.Errorf("NeedNames = %v", got)
	}
	p := res.Pages[0]
	if p.Seed != "example.com" || p.Status != 200 || !p.Direct.OK {
		t.Errorf("page = %+v", p)
	}
}

func TestScan_DirectOKSkipsTheTunnelProbe(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(`<img src="https://fine.example-a.net/a.png">`)}}
	pr := &fakeProber{direct: map[string]Reach{"fine.example-a.net": ok(200), "example.com": ok(200)}}
	if _, err := Scan(context.Background(), "example.com", scanOpts(tun, pr)); err != nil {
		t.Fatal(err)
	}
	if len(pr.tunneled) != 0 {
		t.Errorf("a host that opens directly was also opened through the tunnel: %v", pr.tunneled)
	}
}

func TestScan_WWWFallback(t *testing.T) {
	// The bare name has no address; the www name serves the page.
	tun := &fakeTunnel{sites: map[string]site{"https://www.example.com/": page(`<img src="https://img.example-a.net/a.png">`)}}
	pr := &fakeProber{direct: map[string]Reach{"img.example-a.net": fail("таймаут")}, tunnel: map[string]Reach{"img.example-a.net": ok(200)}}
	res, err := Scan(context.Background(), "example.com", scanOpts(tun, pr))
	if err != nil {
		t.Fatal(err)
	}
	if h := hostByName(res, "img.example-a.net"); h == nil || h.Class != ClassNeed {
		t.Errorf("img.example-a.net = %+v", h)
	}
	if res.Pages[0].FinalHost != "www.example.com" {
		t.Errorf("FinalHost = %q", res.Pages[0].FinalHost)
	}
}

func TestScan_NoWWWFallbackForAWWWSeed(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{}}
	_, err := Scan(context.Background(), "www.example.com", scanOpts(tun, &fakeProber{}))
	if err == nil {
		t.Fatal("want an error: nothing answers")
	}
	for _, u := range tun.asked {
		if strings.Contains(u, "www.www.") {
			t.Errorf("asked %s", u)
		}
	}
}

func TestScan_PageUnreachableIsAnError(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{
		"https://example.com/":     {err: errors.New("socks connect tcp 127.0.0.1:1080->example.com:443: host unreachable")},
		"https://www.example.com/": {err: context.DeadlineExceeded},
	}}
	_, err := Scan(context.Background(), "example.com", scanOpts(tun, &fakeProber{}))
	if err == nil || !strings.Contains(err.Error(), "не открылась") {
		t.Errorf("err = %v", err)
	}
}

func TestScan_RedirectChainHostsAreDependencies(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{
		"https://example.com/":            {status: 301, header: http.Header{"Location": {"https://www.example.com/"}}},
		"https://www.example.com/":        {status: 302, header: http.Header{"Location": {"https://sso.example-a.org/login"}}},
		"https://sso.example-a.org/login": page(`<img src="https://img.example-b.net/a.png">`),
	}}
	pr := &fakeProber{
		direct: map[string]Reach{"sso.example-a.org": fail("сброс")},
		tunnel: map[string]Reach{"sso.example-a.org": ok(200), "img.example-b.net": ok(200)},
	}
	res, err := Scan(context.Background(), "example.com", scanOpts(tun, pr))
	if err != nil {
		t.Fatal(err)
	}
	sso := hostByName(res, "sso.example-a.org")
	if sso == nil || sso.Class != ClassNeed || strings.Join(sso.Via, ",") != ViaRedirect {
		t.Errorf("sso = %+v", sso)
	}
	if hostByName(res, "www.example.com") != nil {
		t.Error("www.example.com listed; the seed entry covers it")
	}
	if res.Pages[0].FinalHost != "sso.example-a.org" {
		t.Errorf("FinalHost = %q", res.Pages[0].FinalHost)
	}
}

func TestScan_RefusesUnsafeRedirects(t *testing.T) {
	for name, loc := range map[string]string{
		"private IP":    "http://192.168.1.1/admin",
		"loopback name": "http://localhost/",
		"odd port":      "https://example-a.net:8443/",
		"other scheme":  "ftp://example-a.net/",
		"internal TLD":  "http://router.lan/",
	} {
		t.Run(name, func(t *testing.T) {
			tun := &fakeTunnel{sites: map[string]site{
				"https://example.com/":     {status: 302, header: http.Header{"Location": {loc}}},
				"https://www.example.com/": {status: 302, header: http.Header{"Location": {loc}}},
			}}
			_, err := Scan(context.Background(), "example.com", scanOpts(tun, &fakeProber{}))
			if err == nil {
				t.Fatalf("followed a redirect to %s", loc)
			}
			for _, u := range tun.asked {
				if u == loc {
					t.Errorf("requested the redirect target %s", loc)
				}
			}
		})
	}
}

func TestScan_TooManyRedirects(t *testing.T) {
	sites := map[string]site{}
	for i := 0; i < 10; i++ {
		sites[fmt.Sprintf("https://r%d.example-a.net/", i)] = site{status: 302, header: http.Header{"Location": {fmt.Sprintf("https://r%d.example-a.net/", i+1)}}}
	}
	sites["https://example.com/"] = site{status: 302, header: http.Header{"Location": {"https://r0.example-a.net/"}}}
	_, err := Scan(context.Background(), "example.com", scanOpts(&fakeTunnel{sites: sites}, &fakeProber{}))
	if err == nil || !strings.Contains(err.Error(), "редиректов") {
		t.Errorf("err = %v", err)
	}
}

func TestScan_ErrorPageIsNotRead(t *testing.T) {
	// A bot-check page lists its own challenge host in a header; it says
	// nothing about the site, so nothing is collected from it.
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": {
		status: 403, body: `<img src="https://challenge.example-a.net/c.png">`,
		header: http.Header{"Content-Security-Policy": {"script-src https://challenges.example-b.net"}},
	}}}
	res, err := Scan(context.Background(), "example.com", scanOpts(tun, &fakeProber{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 0 || !strings.Contains(res.Pages[0].Note, "403") {
		t.Errorf("hosts=%v note=%q", res.Hosts, res.Pages[0].Note)
	}
}

func TestScan_NotHTML(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": {
		status: 200, body: `{"img":"https://x.example-a.net/a.png"}`, header: http.Header{"Content-Type": {"application/json"}},
	}}}
	res, err := Scan(context.Background(), "example.com", scanOpts(tun, &fakeProber{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 0 || !strings.Contains(res.Pages[0].Note, "не HTML") {
		t.Errorf("hosts=%v note=%q", res.Hosts, res.Pages[0].Note)
	}
}

func TestScan_NothingExternalSaysSo(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(`<html><body><script src="/app.js"></script></body></html>`)}}
	res, err := Scan(context.Background(), "example.com", scanOpts(tun, &fakeProber{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 0 || !strings.Contains(res.Pages[0].Note, "ничего внешнего") {
		t.Errorf("hosts=%v note=%q", res.Hosts, res.Pages[0].Note)
	}
}

func TestScan_MaxHostsCapsTheProbes(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&body, `<img src="https://h%02d.example-a.net/a.png">`, i)
	}
	// A covered host does not count against the cap.
	body.WriteString(`<img src="https://listed.example-b.net/a.png">`)
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(body.String())}}
	pr := &fakeProber{}
	opts := scanOpts(tun, pr)
	opts.MaxHosts = 10
	opts.Covered = func(h string) string {
		if h == "listed.example-b.net" {
			return "mine"
		}
		return ""
	}
	res, err := Scan(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.More != 30 || len(res.Hosts) != 11 {
		t.Errorf("More=%d hosts=%d, want 30 and 11 (10 probed + 1 covered)", res.More, len(res.Hosts))
	}
	if n := len(pr.directed); n != 11 { // 10 hosts + the seed itself
		t.Errorf("%d direct probes, want 11", n)
	}
}

func TestScan_TieredProbeOrder(t *testing.T) {
	// With a cap, the hosts the page really loads win over allow-list noise.
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": {
		status: 200, body: `<img src="https://real.example-a.net/a.png">`,
		header: http.Header{"Content-Security-Policy": {"img-src https://aaa.example-b.net https://bbb.example-b.net"}},
	}}}
	opts := scanOpts(tun, &fakeProber{})
	opts.MaxHosts = 1
	res, err := Scan(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hosts) != 1 || res.Hosts[0].Name != "real.example-a.net" || res.More != 2 {
		t.Errorf("hosts=%+v More=%d", res.Hosts, res.More)
	}
}

func TestScan_WorkerCap(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 24; i++ {
		fmt.Fprintf(&body, `<img src="https://h%02d.example-a.net/a.png">`, i)
	}
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(body.String())}}
	pr := &fakeProber{delay: 15 * time.Millisecond}
	opts := scanOpts(tun, pr)
	opts.Workers = 4
	if _, err := Scan(context.Background(), "example.com", opts); err != nil {
		t.Fatal(err)
	}
	// 4 host workers, plus the seed's own direct probe running alongside.
	if peak := atomic.LoadInt32(&pr.peak); peak > 5 {
		t.Errorf("peak concurrency %d with 4 workers", peak)
	}
}

func TestScan_BudgetMarksTheRestUnchecked(t *testing.T) {
	tun := &fakeTunnel{sites: map[string]site{"https://example.com/": page(`<img src="https://a.example-a.net/x.png"><img src="https://b.example-a.net/x.png">`)}}
	pr := &fakeProber{block: true}
	opts := scanOpts(tun, pr)
	opts.Budget = 150 * time.Millisecond
	start := time.Now()
	res, err := Scan(context.Background(), "example.com", opts)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("scan took %v with a 150ms budget", d)
	}
	for _, h := range res.Hosts {
		if !h.Unchecked || h.Class != ClassMaybe {
			t.Errorf("%s: unchecked=%v class=%q; a host the budget never reached is not 'dead'", h.Name, h.Unchecked, h.Class)
		}
	}
	if len(res.Hosts) != 2 {
		t.Errorf("hosts = %+v", res.Hosts)
	}
}

func TestScan_RequiresATunnel(t *testing.T) {
	_, err := Scan(context.Background(), "example.com", Options{Prober: &fakeProber{}})
	if err == nil || !strings.Contains(err.Error(), "туннель") {
		t.Errorf("err = %v", err)
	}
}

func TestScan_ReadsAtMostMaxBody(t *testing.T) {
	var read int64
	big := io.MultiReader(strings.NewReader("<html>"), &countingReader{n: 50 << 20, read: &read})
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(big), Request: req}, nil
	})
	if _, err := Scan(context.Background(), "example.com", Options{Tunnel: rt, Prober: &fakeProber{}, Budget: 5 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt64(&read); got > maxBody+(64<<10) {
		t.Errorf("read %d bytes of a 50 MiB page, want about %d", got, maxBody)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countingReader struct {
	n    int64
	read *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	k := int64(len(p))
	if k > c.n {
		k = c.n
	}
	for i := int64(0); i < k; i++ {
		p[i] = 'x'
	}
	c.n -= k
	atomic.AddInt64(c.read, k)
	return int(k), nil
}

func TestValidSeed(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":     "example.com",
		"example.com.":    "example.com",
		"sub.example.org": "sub.example.org",
	} {
		got, err := ValidSeed(in)
		if err != nil || got != want {
			t.Errorf("ValidSeed(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.2.3.4", "10.0.0.0/8", "localhost", "router.lan", "*.example.com", "экзампл.рф", "not a domain", "nodots"} {
		if got, err := ValidSeed(in); err == nil {
			t.Errorf("ValidSeed(%q) = %q, want an error", in, got)
		}
	}
}

// ---- classify / merge ----------------------------------------------------

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		h    Host
		want Class
	}{
		{"covered wins over everything", Host{CoveredBy: "x", Direct: ok(200)}, ClassCovered},
		{"unchecked is never dead", Host{Unchecked: true, Direct: fail("таймаут")}, ClassMaybe},
		{"opens directly", Host{Direct: ok(200)}, ClassDirect},
		{"direct 404 is still an answer", Host{Direct: ok(404)}, ClassDirect},
		{"direct 403, tunnel same 403: not regional", Host{Direct: ok(403), Tunnel: ok(403)}, ClassDirect},
		{"direct 403, tunnel 200: regional", Host{Direct: ok(403), Tunnel: ok(200)}, ClassNeed},
		{"direct 451, tunnel 200: regional", Host{Direct: ok(451), Tunnel: ok(200)}, ClassNeed},
		{"direct 403, tunnel never tried", Host{Direct: ok(403)}, ClassDirect},
		{"direct 403, tunnel failed", Host{Direct: ok(403), Tunnel: fail("таймаут")}, ClassDirect},
		{"blocked directly, tunnel ok", Host{Direct: fail("сброс"), Tunnel: ok(200)}, ClassNeed},
		{"blocked directly, tunnel ok, only maybe", Host{Tier: TierMaybe, Direct: fail("сброс"), Tunnel: ok(200)}, ClassMaybe},
		{"blocked directly, tunnel ok, a tracker", Host{Tracker: true, Direct: fail("сброс"), Tunnel: ok(200)}, ClassMaybe},
		{"neither way", Host{Direct: fail("DNS"), Tunnel: fail("DNS")}, ClassDead},
	}
	for _, tc := range cases {
		if got := classify(&tc.h); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestMerge(t *testing.T) {
	a := &Result{
		Pages: []Page{{Seed: "a.example.com", Status: 200}},
		Hosts: []Host{
			{Name: "shared.example-x.net", Class: ClassDirect},
			{Name: "b.example.org", Class: ClassNeed}, // is itself the second seed: dropped
			{Name: "only-a.example-x.net", Class: ClassNeed},
		},
		More: 1, Skipped: 2,
	}
	b := &Result{
		Pages: []Page{{Seed: "b.example.org", Status: 200}},
		Hosts: []Host{
			{Name: "shared.example-x.net", Class: ClassNeed}, // a better class for the same host
			{Name: "cdn.b.example.org", Class: ClassNeed},    // under the second seed: dropped
			{Name: "only-b.example-x.net", Class: ClassMaybe},
		},
		More: 2, Skipped: 1,
	}
	m := Merge(a, nil, b)
	var names []string
	for _, h := range m.Hosts {
		names = append(names, h.Name+":"+string(h.Class))
	}
	want := "[only-a.example-x.net:need shared.example-x.net:need only-b.example-x.net:maybe]"
	if fmt.Sprint(names) != want {
		t.Errorf("hosts = %v, want %s", names, want)
	}
	if len(m.Pages) != 2 || m.More != 3 || m.Skipped != 3 {
		t.Errorf("pages=%d more=%d skipped=%d", len(m.Pages), m.More, m.Skipped)
	}
}
