package main

import (
	"bytes"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func l7sniTestConfig(l7, adaptive bool, quic string) *config.Config {
	c := config.Default()
	c.L7SNI = config.L7SNIConfig{Enabled: l7, QUIC: quic}
	c.AdaptiveRoute.Enabled = adaptive
	return c
}

func TestL7SNIQUICLine(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
		want string // substring
		not  string // substring that must be absent
	}{
		{"off", l7sniTestConfig(true, true, ""), "QUIC (UDP/443): выкл", "—"},
		{"observe", l7sniTestConfig(true, true, "observe"), "наблюдение — разбираем начало соединений", ""},
		{"observe without adaptive routing is still observing", l7sniTestConfig(true, false, "observe"), "наблюдение — разбираем", "выключен"},
		{"act", l7sniTestConfig(true, true, "act"), "действие — имя из списка маршрутов переправляется", ""},
		{"act without adaptive routing says it only observes", l7sniTestConfig(true, false, "act"), "работает как «наблюдение»", ""},
		{"a mode with l7sni off says it does nothing", l7sniTestConfig(false, true, "observe"), "но l7sni выключен", ""},
		{"a typo in the config is off, and says so", l7sniTestConfig(true, true, "Act"), "записано \"Act\", это не off/observe/act", ""},
		{"an explicit off needs no warning", l7sniTestConfig(true, true, "off"), "QUIC (UDP/443): выкл", "не off"},
	}
	for _, tc := range cases {
		got := l7sniQUICLine(tc.cfg)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q does not contain %q", tc.name, got, tc.want)
		}
		if tc.not != "" && strings.Contains(got, tc.not) {
			t.Errorf("%s: %q should not contain %q", tc.name, got, tc.not)
		}
	}
}

func TestL7SNIQUICHints(t *testing.T) {
	if h := l7sniQUICHints(l7sniTestConfig(true, true, "")); len(h) != 0 {
		t.Errorf("hints for a mode that is off: %q", h)
	}
	obs := strings.Join(l7sniQUICHints(l7sniTestConfig(true, true, "observe")), "|")
	if !strings.Contains(obs, "transport l7sni stats") || strings.Contains(obs, "transport l7sni on") {
		t.Errorf("observe, l7sni on: %q", obs)
	}
	off := strings.Join(l7sniQUICHints(l7sniTestConfig(false, true, "observe")), "|")
	if !strings.Contains(off, "transport l7sni on") {
		t.Errorf("observe, l7sni off should point at `l7sni on`: %q", off)
	}

	act := l7sniTestConfig(true, true, "act")
	if h := strings.Join(l7sniQUICHints(act), "|"); !strings.Contains(h, "нет ни одного домена") {
		t.Errorf("act without route-list domains should say there is nothing to redirect: %q", h)
	}
	act.Routing.Lists = []config.RouteList{{Name: "ru-blocked", Entries: []string{"youtube.com"}}}
	if h := strings.Join(l7sniQUICHints(act), "|"); strings.Contains(h, "нет ни одного домена") {
		t.Errorf("act with a domain on a list still warns about an empty list: %q", h)
	}
}

func TestTransportL7SNIQUIC_SavesAndClearsTheMode(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	t.Setenv("KEENETIC_XRAY_PID_FILE", filepath.Join(t.TempDir(), "none.pid")) // no daemon to signal
	cfg := l7sniTestConfig(false, true, "")                                    // l7sni off: no router is touched
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"observe", "act", "OBSERVE", " act "} {
		if err := transportL7SNIQUIC(cfg, []string{mode}); err != nil {
			t.Fatalf("quic %q: %v", mode, err)
		}
		saved, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if want := strings.ToLower(strings.TrimSpace(mode)); saved.L7SNI.QUIC != want {
			t.Errorf("quic %q: saved %q, want %q", mode, saved.L7SNI.QUIC, want)
		}
	}

	if err := transportL7SNIQUIC(cfg, []string{"off"}); err != nil {
		t.Fatal(err)
	}
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.L7SNI.QUIC != "" {
		t.Errorf("quic off saved %q, want the field cleared", saved.L7SNI.QUIC)
	}
}

func TestTransportL7SNIQUIC_RejectsBadArguments(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := l7sniTestConfig(false, true, "observe")
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {}, {"loud"}, {"observe", "act"}, {""}} {
		err := transportL7SNIQUIC(cfg, args)
		if err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("args %q: err = %v, want a usage error", args, err)
		}
	}
	saved, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.L7SNI.QUIC != "observe" {
		t.Errorf("a rejected command changed the mode to %q", saved.L7SNI.QUIC)
	}
}

func TestTransportL7SNI_UnknownActionIsAUsageError(t *testing.T) {
	err := transportL7SNI(l7sniTestConfig(false, false, ""), []string{"frobnicate"})
	if err == nil || !strings.Contains(err.Error(), "quic {off|observe|act}|stats") {
		t.Errorf("err = %v, want the usage string that lists quic and stats", err)
	}
}

func TestPrintL7SNIState(t *testing.T) {
	var b bytes.Buffer
	printL7SNIState(&b, l7sniTestConfig(true, true, "observe"))
	out := b.String()
	for _, want := range []string{"l7sni: вкл", "QUIC (UDP/443): наблюдение", "transport l7sni stats"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestPrintL7SNIStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	t.Setenv("KEENETIC_XRAY_L7SNI_STATS", path)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

	var missing bytes.Buffer
	if err := printL7SNIStats(&missing, now); err != nil {
		t.Fatalf("no file: %v", err)
	}
	if !strings.Contains(missing.String(), "статистики пока нет") {
		t.Errorf("no file: %q", missing.String())
	}

	s := newL7SNIStats(now.Add(-time.Hour))
	s.inc(statQUICDatagram)
	s.inc(statQUICInitial)
	s.seenName("quic", "example.com", false)
	if err := writeL7SNIStats(path, s.snapshot(now, "observe")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := printL7SNIStats(&out, now); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TLS (TCP/443)", "режим «наблюдение»", "example.com"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stats output lacks %q:\n%s", want, out.String())
		}
	}
}

func TestL7SNIQUICHints_ActWarnsAboutAppsWithoutATCPFallback(t *testing.T) {
	h := strings.Join(l7sniQUICHints(l7sniTestConfig(true, true, "act")), "|")
	if !strings.Contains(h, "без запасного пути на TCP") {
		t.Errorf("act hints: %q", h)
	}
	if strings.Contains(strings.Join(l7sniQUICHints(l7sniTestConfig(true, true, "observe")), "|"), "запасного пути") {
		t.Error("observe changes nothing for the client and must not warn about it")
	}
}

func TestWriteDiagL7SNI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	t.Setenv("KEENETIC_XRAY_L7SNI_STATS", path)
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	cfg := l7sniTestConfig(true, true, "observe")

	var none bytes.Buffer
	writeDiagL7SNI(&none, cfg, now)
	if out := none.String(); !strings.Contains(out, "---- l7sni ----") || !strings.Contains(out, "QUIC (UDP/443): наблюдение") || !strings.Contains(out, "статистика:") {
		t.Errorf("without a stats file:\n%s", out)
	}

	s := newL7SNIStats(now.Add(-time.Minute))
	s.inc(statTLSHello)
	s.seenName("tls", "private-site.example", false)
	if err := writeL7SNIStats(path, s.snapshot(now, "observe")); err != nil {
		t.Fatal(err)
	}
	var with bytes.Buffer
	writeDiagL7SNI(&with, cfg, now)
	out := with.String()
	if !strings.Contains(out, "TLS (TCP/443): ClientHello разобрано 1") {
		t.Errorf("with a stats file:\n%s", out)
	}
	// the names clients connected to are their browsing history: counters
	// only in a bundle that gets pasted around
	if strings.Contains(out, "private-site.example") {
		t.Errorf("the diag bundle lists a hostname a LAN client visited:\n%s", out)
	}
}

func TestL7SNIQUICApplyMessage(t *testing.T) {
	if got := l7sniQUICApplyMessage(nil); !strings.Contains(got, "приведено в соответствие") || strings.Contains(got, "предупреждение") {
		t.Errorf("success message: %q", got)
	}
	got := l7sniQUICApplyMessage(errors.New("iptables: boom"))
	if !strings.Contains(got, "предупреждение") || strings.Contains(got, "приведено в соответствие") || !strings.Contains(got, "режим сохранён") {
		t.Errorf("failure message must not claim the rule was applied: %q", got)
	}
}

// TestTransportL7SNIQUIC_ReloadsTheDaemon: the daemon and the bot inside it
// hold their own copy of the config and write it back whole whenever they
// save something else (every bot button that changes a setting does), so the
// new mode must reach them through the usual SIGHUP reload -- otherwise the
// next press of an unrelated button puts the old mode back on disk.
func TestTransportL7SNIQUIC_ReloadsTheDaemon(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGHUP delivery via os.Process.Signal is a Unix-only path -- the daemon only ever runs on Linux")
	}
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := l7sniTestConfig(false, true, "") // l7sni off: no router is touched
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	self := os.Getpid()
	writePIDFile(t, self)
	withProcessName(t, func(pid int) string {
		if pid == self {
			return "keenetic-xray"
		}
		return ""
	})
	got := make(chan os.Signal, 1)
	signal.Notify(got, syscall.SIGHUP) // without a handler the signal would end the test process
	t.Cleanup(func() { signal.Stop(got) })

	if err := transportL7SNIQUIC(cfg, []string{"observe"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no SIGHUP reached the daemon: it and the bot would keep the old mode and write it back")
	}
}
