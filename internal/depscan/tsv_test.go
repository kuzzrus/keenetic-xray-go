package depscan

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleResult() *Result {
	return &Result{
		Pages: []Page{
			{Seed: "example.com", FinalHost: "www.example.com", Status: 200, Direct: ok(200), Note: ""},
			{Seed: "other.org", FinalHost: "other.org", Status: 403, Direct: fail("сброс"), Note: "сайт ответил кодом 403\tс табом"},
		},
		Hosts: []Host{
			{Name: "need.example-a.net", Class: ClassNeed, Tier: TierLikely, Via: []string{ViaHTML, ViaHint}, Direct: fail("таймаут"), Tunnel: ok(200)},
			{Name: "gtm.example-b.net", Class: ClassMaybe, Tier: TierMaybe, Via: []string{ViaCSP}, Tracker: true, Shared: true, Direct: fail("DNS"), Tunnel: ok(404)},
			{Name: "slow.example-c.net", Class: ClassMaybe, Tier: TierLikely, Via: []string{ViaHTML}, Unchecked: true},
			{Name: "fine.example-d.net", Class: ClassDirect, Tier: TierLikely, Via: []string{ViaScript}, Direct: ok(200)},
			{Name: "gone.example-e.net", Class: ClassDead, Tier: TierMaybe, Via: []string{ViaForm}, Direct: fail("нет маршрута"), Tunnel: fail("сертификат")},
			{Name: "listed.example-f.net", Class: ClassCovered, Tier: TierLikely, CoveredBy: "my-list"},
		},
		More: 4, Skipped: 2,
	}
}

func TestTSV_RoundTrip(t *testing.T) {
	in := sampleResult()
	out, err := ParseTSV(in.TSV())
	if err != nil {
		t.Fatal(err)
	}
	// The note's tab is flattened on the wire; everything else survives.
	in.Pages[1].Note = "сайт ответил кодом 403 с табом"
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip changed the result:\n in: %+v\nout: %+v", in, out)
	}
}

func TestParseTSV_Tolerance(t *testing.T) {
	good := "#page\texample.com\texample.com\t200\tok:200\t\n" +
		"#future-line\twhatever\n" +
		"a.example-a.net\tneed\tA\t-\thtml\t-\terr:таймаут\tok:200\n" +
		"too\tshort\n" +
		"b.example-b.net\tnonsense-class\tA\t-\thtml\t-\t-\t-\n" +
		"c.example-c.net\tdirect\tA\t-\t-\t-\tok:200\t-\textra\tcolumns\n"
	r, err := ParseTSV(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Hosts) != 2 || r.Hosts[0].Name != "a.example-a.net" || r.Hosts[1].Name != "c.example-c.net" {
		t.Errorf("hosts = %+v", r.Hosts)
	}
	if _, err := ParseTSV(""); err == nil {
		t.Error("an empty answer parsed")
	}
	if _, err := ParseTSV("some other action's output\n"); err == nil {
		t.Error("output without a #page line parsed")
	}
	// A page line with missing trailing columns still parses.
	if r, err := ParseTSV("#page\texample.com"); err != nil || r.Pages[0].Seed != "example.com" {
		t.Errorf("short #page: %v %+v", err, r)
	}
}

func TestTSV_NoRawTabsOrNewlinesInsideCells(t *testing.T) {
	r := &Result{Pages: []Page{{Seed: "x.example.com", Note: "a\nb\tc"}}, Hosts: []Host{{Name: "h.example-a.net", Class: ClassCovered, CoveredBy: "bad\tname\nx"}}}
	for _, line := range strings.Split(strings.TrimRight(r.TSV(), "\n"), "\n") {
		if strings.HasPrefix(line, "#page") && strings.Count(line, "\t") != 7 {
			t.Errorf("page line has %d tabs: %q", strings.Count(line, "\t"), line)
		}
		if strings.HasPrefix(line, "h.") && strings.Count(line, "\t") != 9 {
			t.Errorf("host line has %d tabs: %q", strings.Count(line, "\t"), line)
		}
	}
}

func TestText_GroupsAndNeedNames(t *testing.T) {
	txt := sampleResult().Text()
	for _, want := range []string{
		"example.com → www.example.com", "напрямую тоже открывается",
		"Нужны — напрямую не открываются", "need.example-a.net",
		"Возможно нужны (2)", "[общий сервис, аналитика/реклама]", "не успел проверить",
		"Открываются и напрямую", "Не открылись ни так, ни так", "Уже в ваших списках", "в списке my-list",
		"Ещё 4 хостов не проверял", "Пропущено имён", "сайт ответил кодом 403",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("Text() lacks %q:\n%s", want, txt)
		}
	}
	if got := sampleResult().NeedNames(); fmt.Sprint(got) != "[need.example-a.net]" {
		t.Errorf("NeedNames = %v", got)
	}
	if n := sampleResult().Count(ClassMaybe); n != 2 {
		t.Errorf("Count(maybe) = %d", n)
	}
}

// ---- probes ----------------------------------------------------------------

func TestProbeOnce(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://h.example-a.net/" || req.Header.Get("Range") == "" {
			t.Errorf("probe request = %s %v", req.URL, req.Header)
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied")), Request: req}, nil
	})
	if r := probeOnce(context.Background(), rt, "h.example-a.net", time.Second); !r.Tried || !r.OK || r.Status != 403 {
		t.Errorf("a refusal is still an answer: %+v", r)
	}
	bad := roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.EOF })
	if r := probeOnce(context.Background(), bad, "h.example-a.net", time.Second); r.OK || r.Err != "сброс" {
		t.Errorf("EOF = %+v, want a reset", r)
	}
	// The limit applies to the probe itself.
	slow := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	start := time.Now()
	if r := probeOnce(context.Background(), slow, "h.example-a.net", 50*time.Millisecond); r.OK || r.Err != "таймаут" {
		t.Errorf("slow = %+v", r)
	}
	if time.Since(start) > time.Second {
		t.Error("the probe ignored its own timeout")
	}
}

func TestNetProber_NoTunnel(t *testing.T) {
	p := NewProber(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, io.EOF }), nil)
	if r := p.Tunnel(context.Background(), "h.example-a.net"); r.OK || !strings.Contains(r.Err, "туннел") {
		t.Errorf("Tunnel without a tunnel = %+v", r)
	}
}

func TestReason(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "таймаут"},
		{fmt.Errorf("get: %w", context.DeadlineExceeded), "таймаут"},
		{&net.DNSError{Err: "no such host", Name: "x"}, "DNS"},
		{&net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true}, "таймаут DNS"},
		{x509.HostnameError{Host: "x"}, "сертификат"},
		{x509.UnknownAuthorityError{}, "сертификат"},
		{io.EOF, "сброс"},
		{io.ErrUnexpectedEOF, "сброс"},
		{&redirectError{"редирект на порт 8443"}, "редирект на порт 8443"},
		{errors.New("tls: handshake failure"), "TLS"},
		{errors.New("something odd"), "ошибка"},
	} {
		if got := reason(tc.err); got != tc.want {
			t.Errorf("reason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func TestSocksReason(t *testing.T) {
	for msg, want := range map[string]string{
		`Get "https://x.example/": socks connect tcp 127.0.0.1:1080->x.example:443: unknown error host unreachable`:             "хост недоступен",
		`Get "https://x.example/": socks connect tcp 127.0.0.1:1080->x.example:443: unknown error general SOCKS server failure`: "не соединился",
		`socks connect tcp 127.0.0.1:1080->x.example:443: unknown error connection refused`:                                     "отказ",
		`socks connect tcp 127.0.0.1:1080->x.example:443: unknown error network unreachable`:                                    "нет маршрута",
		`socks connect tcp 127.0.0.1:1080->x.example:443: unknown error TTL expired`:                                            "таймаут",
		`socks connect tcp 127.0.0.1:1080->x.example:443: unknown error connection not allowed by ruleset`:                      "запрещено правилами туннеля",
		`socks connect tcp 127.0.0.1:1080->x.example:443: something new`:                                                        "ошибка туннеля",
	} {
		if got := reason(errors.New(msg)); got != want {
			t.Errorf("reason(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestText_DirectGroupIsCompact(t *testing.T) {
	r := &Result{Pages: []Page{{Seed: "example.com", Status: 200}}}
	for i := 0; i < 30; i++ {
		r.Hosts = append(r.Hosts, Host{Name: fmt.Sprintf("host%02d.example-a.net", i), Class: ClassDirect, Via: []string{ViaCSP}, Direct: ok(404)})
	}
	txt := r.Text()
	if strings.Contains(txt, "отвечает (404)") || strings.Contains(txt, "политика CSP") {
		t.Errorf("direct hosts listed with their answers:\n%s", txt)
	}
	if !strings.Contains(txt, "(30):") || !strings.Contains(txt, "host00.example-a.net,") || !strings.HasSuffix(txt, "host29.example-a.net") {
		t.Errorf("not every direct host is named:\n%s", txt)
	}
	for _, line := range strings.Split(txt, "\n") {
		if len([]rune(line)) > 110 {
			t.Errorf("line of %d columns: %q", len([]rune(line)), line)
		}
	}
}

func TestWrapNames(t *testing.T) {
	if got := wrapNames(nil, "  ", 40); got != "" {
		t.Errorf("empty = %q", got)
	}
	got := wrapNames([]string{"aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc", "dddddddddd"}, "  ", 30)
	if got != "  aaaaaaaaaa, bbbbbbbbbb,\n  cccccccccc, dddddddddd\n" {
		t.Errorf("wrapped = %q", got)
	}
	// A name longer than the width still gets a line of its own.
	if got := wrapNames([]string{strings.Repeat("x", 50), "y"}, "", 20); got != strings.Repeat("x", 50)+",\ny\n" {
		t.Errorf("long name = %q", got)
	}
}

func TestText_AnUnreadPageIsNotCalledOpened(t *testing.T) {
	r := &Result{Pages: []Page{{Seed: "voip.example.com", Note: "страница не открылась", SeedIPs: []string{"1.2.3.4"}}}}
	txt := r.Text()
	if strings.Contains(txt, "страница открылась") || strings.Contains(txt, "код 0") || !strings.Contains(txt, "страница не прочитана") {
		t.Errorf("header of a page that could not be read:\n%s", txt)
	}
}

func TestText_AddressesFoundButNoneToOffer(t *testing.T) {
	r := &Result{Pages: []Page{{Seed: "yandex.ru", FinalHost: "yandex.ru", Status: 200, SeedIPsDropped: 4}}}
	if txt := r.Text(); !strings.Contains(txt, "IP-адреса домена: подходящих нет (ещё 4 отброшено") {
		t.Errorf("all addresses dropped, and the report is silent:\n%s", txt)
	}
	r.Pages[0].SeedIPsDropped = 0
	if txt := r.Text(); strings.Contains(txt, "IP-адреса домена") {
		t.Errorf("a line about addresses though none were found:\n%s", txt)
	}
}
