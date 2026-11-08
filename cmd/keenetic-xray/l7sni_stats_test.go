package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestL7SNIStats_CountsAndTopNames(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := newL7SNIStats(now)
	s.inc(statQUICDatagram)
	s.inc(statQUICDatagram)
	s.inc(statQUICInitial)
	for i := 0; i < 5; i++ {
		s.seenName("quic", "rr1---sn-a.googlevideo.com", false)
	}
	for i := 0; i < 3; i++ {
		s.seenName("quic", "cloudflare-ech.com", true)
	}
	s.seenName("tls", "example.com", false)
	s.seenName("quic", "", true) // no name: not recorded

	f := s.snapshot(now.Add(time.Minute), "observe")
	if f.Counts[statQUICDatagram] != 2 || f.Counts[statQUICInitial] != 1 {
		t.Errorf("counts = %v", f.Counts)
	}
	if f.QUIC != "observe" {
		t.Errorf("QUIC mode = %q", f.QUIC)
	}
	if len(f.Top) != 3 {
		t.Fatalf("top = %+v, want 3 names", f.Top)
	}
	if f.Top[0].Host != "rr1---sn-a.googlevideo.com" || f.Top[0].N != 5 {
		t.Errorf("most seen = %+v", f.Top[0])
	}
	if f.Top[1].Host != "cloudflare-ech.com" || f.Top[1].ECH != 3 {
		t.Errorf("second = %+v, want the ECH-flagged name with ech=3", f.Top[1])
	}
	// the snapshot is a copy: later counting does not change it
	s.inc(statQUICDatagram)
	if f.Counts[statQUICDatagram] != 2 {
		t.Error("the snapshot shares its map with the live counters")
	}
}

// TestL7SNIStats_NameTableStaysBoundedAndKeepsTheBusyOnes: a long tail of
// one-off names (per-session CDN hosts) must not grow the table without
// limit, nor push out a name that is seen all the time.
func TestL7SNIStats_NameTableStaysBoundedAndKeepsTheBusyOnes(t *testing.T) {
	s := newL7SNIStats(time.Now())
	for i := 0; i < 50; i++ {
		s.seenName("tls", "busy.example.com", false)
	}
	for i := 0; i < 5*l7sniNameTable; i++ {
		s.seenName("quic", fmt.Sprintf("rr%d---sn-x.googlevideo.com", i), false)
	}
	s.mu.Lock()
	n := len(s.names)
	_, kept := s.names["tls busy.example.com"]
	s.mu.Unlock()
	if n > l7sniNameTable {
		t.Errorf("name table grew to %d entries, cap is %d", n, l7sniNameTable)
	}
	if !kept {
		t.Error("the busy name was evicted by the long tail")
	}
}

func TestL7SNIStats_TopIsCapped(t *testing.T) {
	s := newL7SNIStats(time.Now())
	for i := 0; i < 100; i++ {
		s.seenName("tls", fmt.Sprintf("h%03d.example.com", i), false)
	}
	if got := len(s.snapshot(time.Now(), "off").Top); got != l7sniTopCount {
		t.Errorf("published %d names, want %d", got, l7sniTopCount)
	}
}

func TestL7SNIStats_PublishAndRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l7sni.json")
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	s := newL7SNIStats(now)

	if wrote, err := s.publishIfDirty(path, now, 10*time.Second, "off"); wrote || err != nil {
		t.Fatalf("nothing counted yet, but publishIfDirty = %v, %v", wrote, err)
	}
	s.inc(statQUICECH)
	s.setBatches(40, 100)
	if wrote, err := s.publishIfDirty(path, now, 10*time.Second, "observe"); !wrote || err != nil {
		t.Fatalf("publishIfDirty = %v, %v, want a write", wrote, err)
	}
	// a change right after is held back by the interval ...
	s.inc(statQUICECH)
	if wrote, _ := s.publishIfDirty(path, now.Add(2*time.Second), 10*time.Second, "observe"); wrote {
		t.Error("a second write inside the minimum interval")
	}
	// ... and goes out once it has passed
	if wrote, _ := s.publishIfDirty(path, now.Add(11*time.Second), 10*time.Second, "observe"); !wrote {
		t.Error("the pending change was never published")
	}

	f, err := readL7SNIStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Counts[statQUICECH] != 2 || f.Reads != 40 || f.Messages != 100 || f.QUIC != "observe" {
		t.Errorf("read back %+v", f)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("mode = %v, want the file private (0600): it lists names LAN clients connected to", info.Mode().Perm())
	}
}

func TestReadL7SNIStats_OtherVersionReadsAsMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l7sni.json")
	if err := os.WriteFile(path, []byte(`{"v":99,"counts":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readL7SNIStats(path); !os.IsNotExist(err) {
		t.Errorf("err = %v, want a not-exist error for a layout of another version", err)
	}
	if _, err := readL7SNIStats(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("a missing file read without error")
	}
}

func TestRenderL7SNIStats(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 30, 0, 0, time.UTC)
	f := &l7sniStatsFile{
		Version: l7sniStatsVersion, Since: now.Add(-90 * time.Minute), At: now.Add(-5 * time.Second), QUIC: "observe",
		Counts: map[string]uint64{
			statQUICDatagram: 120, statQUICInitial: 100, statQUICNotInitial: 15, statQUICAuthFailed: 5,
			statQUICHello: 90, statQUICWaiting: 40, statQUICName: 88, statQUICECH: 9, statQUICMatch: 12,
			statTLSHello: 500, statTLSName: 480, statTLSECH: 20,
		},
		Reads: 200, Messages: 230,
		Top: []l7sniTopName{{Proto: "quic", Host: "www.youtube.com", N: 40}, {Proto: "tls", Host: "cloudflare-ech.com", N: 7, ECH: 7}},
	}
	var buf bytes.Buffer
	renderL7SNIStats(&buf, f, now)
	out := buf.String()
	for _, want := range []string{
		"1.5 ч назад", "5 с назад",
		"режим «наблюдение»",
		"Initial расшифровано 100",
		"ClientHello собрано 90",
		"с ECH-расширением 9",
		"10.0%", // 9 of 90
		"1.15 пакета на чтение",
		"QUIC  www.youtube.com", "(ECH в 7)",
		"совпало со списками 12, переправлено 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	f.QUIC = "off"
	f.Counts[statQUICDatagram] = 0
	buf.Reset()
	renderL7SNIStats(&buf, f, now)
	if !strings.Contains(buf.String(), "QUIC (UDP/443): выкл") || strings.Contains(buf.String(), "датаграмм разобрано") {
		t.Errorf("a QUIC-off file should say so and skip the QUIC details:\n%s", buf.String())
	}
}

func TestShortAge(t *testing.T) {
	cases := map[time.Duration]string{
		-time.Second: "0 с", 5 * time.Second: "5 с", 90 * time.Second: "1 мин",
		59 * time.Minute: "59 мин", 90 * time.Minute: "1.5 ч",
	}
	for d, want := range cases {
		if got := shortAge(d); got != want {
			t.Errorf("shortAge(%v) = %q, want %q", d, got, want)
		}
	}
}
