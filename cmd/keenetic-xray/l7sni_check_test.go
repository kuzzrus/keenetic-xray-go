package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

func mangleRules(iface string, tcp443, tcp80, udp443 uint64) []l7capture.RuleStat {
	return []l7capture.RuleStat{
		{Table: "mangle", Iface: iface, Proto: "tcp", DPort: 443, Packets: tcp443},
		{Table: "mangle", Iface: iface, Proto: "tcp", DPort: 80, Packets: tcp80},
		{Table: "mangle", Iface: iface, Proto: "udp", DPort: 443, Packets: udp443},
	}
}

func checkText(stats []l7capture.RuleStat, err error, wan string, f *l7sniStatsFile) string {
	return strings.Join(renderL7SNICaptureCheck(stats, err, wan, nil, f), "\n")
}

func mustContain(t *testing.T, name, text string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(text, w) {
			t.Errorf("%s: output lacks %q:\n%s", name, w, text)
		}
	}
}

func mustNotContain(t *testing.T, name, text string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(text, n) {
			t.Errorf("%s: output has %q:\n%s", name, n, text)
		}
	}
}

// The case that cost two months: the rules are in, the kernel counts nothing
// under them, and the capture's own numbers are all zero.
func TestRenderL7SNICaptureCheck_NoPacketReachesTheRules(t *testing.T) {
	out := checkText(mangleRules("lte_br0", 0, 0, 0), nil, "lte_br0", nil)
	mustContain(t, "silent rules", out,
		"таблица mangle", "TCP/443", "TCP/80", "UDP/443 (QUIC)", "lte_br0: пакетов 0",
		"Ни один пакет не попал под правила")
	mustNotContain(t, "silent rules", out, "демон не получил")
}

func TestRenderL7SNICaptureCheck_RulesFireButNothingArrives(t *testing.T) {
	f := &l7sniStatsFile{Messages: 0}
	out := checkText(mangleRules("lte_br0", 120, 4, 0), nil, "lte_br0", f)
	mustContain(t, "fires, nothing arrives", out, "пакетов 120", "демон не получил из NFLOG ни одного", "группу 4210")
	mustNotContain(t, "fires, nothing arrives", out, "Ни один пакет не попал")
}

func TestRenderL7SNICaptureCheck_AWorkingCaptureHasNoWarning(t *testing.T) {
	f := &l7sniStatsFile{Messages: 500}
	out := checkText(mangleRules("lte_br0", 120, 4, 7), nil, "lte_br0", f)
	mustContain(t, "working", out, "пакетов 120", "пакетов 7")
	mustNotContain(t, "working", out, "⚠️")
}

func TestRenderL7SNICaptureCheck_RulesOnAnotherInterfaceThanTheDefaultRoute(t *testing.T) {
	out := checkText(mangleRules("eth2.4", 0, 0, 0), nil, "lte_br0", nil)
	mustContain(t, "failover", out, "Правила стоят на eth2.4", "наружу сейчас ведёт lte_br0", "переставит")
}

// An unknown default route (no route at all, the read failed) must not read as
// "the rules are on the wrong interface".
func TestRenderL7SNICaptureCheck_UnknownDefaultRouteIsNotAMismatch(t *testing.T) {
	out := strings.Join(renderL7SNICaptureCheck(mangleRules("eth2.4", 0, 0, 0), nil, "", errors.New("no default route"), nil), "\n")
	mustNotContain(t, "no route", out, "Правила стоят на")
	mustContain(t, "no route", out, "Ни один пакет не попал")
}

func TestRenderL7SNICaptureCheck_NoRulesAtAll(t *testing.T) {
	out := checkText(nil, nil, "lte_br0", nil)
	mustContain(t, "no rules", out, "их нет", "при ближайшей сверке", "logs 100 | grep l7sni")
}

func TestRenderL7SNICaptureCheck_LeftoverFromAnOlderBuild(t *testing.T) {
	stats := append(mangleRules("lte_br0", 3, 0, 0), l7capture.RuleStat{Table: "filter", Iface: "lte_br0", Proto: "tcp", DPort: 443})
	out := checkText(stats, nil, "lte_br0", &l7sniStatsFile{Messages: 3})
	mustContain(t, "leftover", out, "В таблице filter ещё стоят правила прошлой версии")
	// the leftover is not listed as if it were one of the live rules
	if n := strings.Count(out, "TCP/443"); n != 1 {
		t.Errorf("TCP/443 listed %d times, want once (the live rule):\n%s", n, out)
	}
}

func TestRenderL7SNICaptureCheck_OnlyLeftoversMeansNoLiveRules(t *testing.T) {
	out := checkText([]l7capture.RuleStat{{Table: "filter", Iface: "eth1", Proto: "tcp", DPort: 443}}, nil, "eth1", nil)
	mustContain(t, "only leftovers", out, "их нет", "прошлой версии")
}

func TestRenderL7SNICaptureCheck_SilentQUICRuleNextToBusyTCP(t *testing.T) {
	f := &l7sniStatsFile{Messages: 900}
	out := checkText(mangleRules("lte_br0", 800, 100, 0), nil, "lte_br0", f)
	mustContain(t, "silent QUIC", out, "QUIC: правило UDP/443 не сработало ни разу при 900 срабатываниях TCP", "connbytes 0:3")

	quiet := checkText(mangleRules("lte_br0", 10, 5, 0), nil, "lte_br0", &l7sniStatsFile{Messages: 15})
	mustNotContain(t, "little TCP traffic: no verdict yet", quiet, "QUIC: правило")

	tcpOnly := checkText(mangleRules("lte_br0", 800, 100, 0)[:2], nil, "lte_br0", f)
	mustNotContain(t, "no UDP rule installed", tcpOnly, "QUIC: правило")
}

func TestRenderL7SNICaptureCheck_UnreadableCounters(t *testing.T) {
	out := checkText(nil, errors.New("exec: iptables: not found"), "lte_br0", nil)
	mustContain(t, "unreadable", out, "не удалось прочитать счётчики iptables", "not found")
}

// stubL7SNICheck points the three router-touching vars at fakes for one test.
func stubL7SNICheck(t *testing.T, enabled bool, stats []l7capture.RuleStat, wan string) *int {
	t.Helper()
	oe, oc, ow := l7sniCheckEnabled, l7sniRuleCounters, l7sniDefaultRoute
	calls := 0
	l7sniCheckEnabled = func() bool { return enabled }
	l7sniRuleCounters = func(context.Context) ([]l7capture.RuleStat, error) { calls++; return stats, nil }
	l7sniDefaultRoute = func() (string, error) { return wan, nil }
	t.Cleanup(func() { l7sniCheckEnabled, l7sniRuleCounters, l7sniDefaultRoute = oe, oc, ow })
	return &calls
}

// Off a router, or with L7 SNI off, there is nothing to check and iptables is
// never run -- a dev box and every test depend on it.
func TestL7SNICaptureCheck_OnlyOnARouterWithL7SNIOn(t *testing.T) {
	calls := stubL7SNICheck(t, false, mangleRules("lte_br0", 0, 0, 0), "lte_br0")
	if got := l7sniCaptureCheck(nil); got != "" {
		t.Errorf("check with L7 SNI off / off a router = %q, want empty", got)
	}
	if *calls != 0 {
		t.Errorf("iptables was read %d times while there was nothing to check", *calls)
	}

	stubL7SNICheck(t, true, mangleRules("lte_br0", 0, 0, 0), "lte_br0")
	if got := l7sniCaptureCheck(nil); !strings.Contains(got, "Ни один пакет не попал") {
		t.Errorf("check with L7 SNI on = %q", got)
	}
}

// The three places that show the counters all carry the kernel's numbers, and
// the no-statistics-yet answer -- the one a router with a dead capture gives --
// no longer stops at "nothing yet".
func TestCountersShowTheRuleCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	t.Setenv("KEENETIC_XRAY_L7SNI_STATS", path)
	stubL7SNICheck(t, true, mangleRules("lte_br0", 0, 0, 0), "lte_br0")
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

	var cli bytes.Buffer
	if err := printL7SNIStats(&cli, now); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "CLI, no file", cli.String(), "статистики пока нет", "Ни один пакет не попал")

	bot, err := l7sniStatsText(now)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "bot, no file", bot, "статистики пока нет", "Ни один пакет не попал")

	s := newL7SNIStats(now.Add(-time.Hour))
	s.inc(statTLSHello)
	s.seenName("tls", "private-site.example", false)
	if err := writeL7SNIStats(path, s.snapshot(now, "")); err != nil {
		t.Fatal(err)
	}
	cli.Reset()
	if err := printL7SNIStats(&cli, now); err != nil {
		t.Fatal(err)
	}
	mustContain(t, "CLI, with a file", cli.String(), "TLS (TCP/443)", "таблица mangle")
	bot, err = l7sniStatsText(now)
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, "bot, with a file", bot, "TLS (TCP/443)", "таблица mangle")
	mustNotContain(t, "bot, with a file", bot, "private-site.example")
}

// A fresh restart: 105 TCP packets and no QUIC is under a minute of traffic, not
// evidence about the UDP rule -- the remark appeared exactly there on his router.
func TestRenderL7SNICaptureCheck_NoQUICRemarkAfterOnlyAFewPackets(t *testing.T) {
	out := checkText(mangleRules("eth2.4", 90, 15, 0), nil, "eth2.4", &l7sniStatsFile{Messages: 95})
	mustNotContain(t, "105 packets", out, "QUIC: правило")

	enough := checkText(mangleRules("eth2.4", 450, 50, 0), nil, "eth2.4", &l7sniStatsFile{Messages: 500})
	mustContain(t, "500 packets", enough, "QUIC: правило UDP/443 не сработало ни разу при 500")
}
