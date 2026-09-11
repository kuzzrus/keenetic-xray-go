package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/xrayctl"
)

func TestSaveLoad_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "quality.json")
	want := State{
		SweptAt: time.Now().Truncate(time.Second),
		Results: []Result{
			{Key: "aaaa", Remark: "NL-1", OK: true, CheckedAt: time.Now().Truncate(time.Second)},
			{Key: "bbbb", Remark: "DE-2", OK: false, Detail: "не отвечает", CheckedAt: time.Now().Truncate(time.Second)},
		},
	}
	if err := Save(path, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got := Load(path)
	if !got.SweptAt.Equal(want.SweptAt) || len(got.Results) != 2 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Results[1].Detail != "не отвечает" || got.Results[1].OK {
		t.Errorf("result[1] = %+v", got.Results[1])
	}
}

func TestLoad_MissingAndMalformed(t *testing.T) {
	if s := Load(filepath.Join(t.TempDir(), "nope.json")); len(s.Results) != 0 || !s.SweptAt.IsZero() {
		t.Errorf("missing file should give a zero State, got %+v", s)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := Load(bad); len(s.Results) != 0 {
		t.Errorf("malformed file should give a zero State, got %+v", s)
	}
}

func TestStatusLines(t *testing.T) {
	if StatusLines(State{}, time.Now()) != "" {
		t.Error("empty State should render nothing")
	}
	now := time.Now()
	s := State{
		SweptAt: now.Add(-12 * time.Minute),
		Results: []Result{
			{Remark: "NL-1", OK: true},
			{Remark: "FR-3", OK: false, Detail: "нет ответа (таймаут)"},
			{Remark: "DE-2", OK: true},
		},
	}
	out := StatusLines(s, now)
	if !strings.Contains(out, "12 мин назад") {
		t.Errorf("missing age: %q", out)
	}
	// Failures sort first; then OK ones alphabetically.
	lines := strings.Split(out, "\n")
	if len(lines) != 4 || !strings.Contains(lines[1], "FR-3") || !strings.Contains(lines[1], "нет ответа") {
		t.Errorf("failure should be first data line: %q", out)
	}
	if !strings.Contains(lines[2], "DE-2") || !strings.Contains(lines[3], "NL-1") {
		t.Errorf("OK profiles should follow, alphabetical: %q", out)
	}
	if !strings.Contains(lines[1], "⚠️") || !strings.Contains(lines[2], "✅") {
		t.Errorf("marks wrong: %q", out)
	}
}

func TestStatusLines_ShowsLatencyForOK(t *testing.T) {
	now := time.Now()
	s := State{
		SweptAt: now,
		Results: []Result{
			{Remark: "NL-1", OK: true, LatencyMS: 87},
			{Remark: "FR-3", OK: false, Detail: "нет ответа (таймаут)"},
		},
	}
	out := StatusLines(s, now)
	if !strings.Contains(out, "NL-1  87мс") {
		t.Errorf("expected latency next to the OK profile, got: %q", out)
	}
	if strings.Contains(out, "FR-3  87мс") {
		t.Errorf("latency should not leak onto the failed profile: %q", out)
	}
}

// --- SweepOnce ---

func fakeProfile(remark, host string, port int) config.Profile {
	return config.Profile{
		Remark: remark, UUID: "u-" + remark, Address: host, Port: port,
		Network: "tcp", Security: "none", Encryption: "none",
	}
}

func newTestSweeper(t *testing.T, probe func(context.Context, xrayctl.ProbeOptions) error) (*Sweeper, *[]string) {
	t.Helper()
	var started []string
	sw := &Sweeper{
		XrayBinary: "xray", ConfigPath: filepath.Join(t.TempDir(), "scratch.json"), Port: 11081,
		genConfig: func(config.XrayConfigOptions) ([]byte, error) { return []byte("{}"), nil },
		startXray: func(ctx context.Context, cfgPath string) (func(), error) {
			started = append(started, cfgPath)
			return func() {}, nil
		},
		probe: probe,
		sleep: func(context.Context, time.Duration) {},
		now:   func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return sw, &started
}

func TestSweepOnce_DedupAndClassify(t *testing.T) {
	// FR-3 fails; NL-1 appears twice with the same endpoint -> one probe.
	calls := 0
	sw, started := newTestSweeper(t, func(_ context.Context, opts xrayctl.ProbeOptions) error {
		calls++
		if strings.Contains(opts.SOCKSAddr, "11081") && calls == 2 {
			return errors.New("dial tcp: i/o timeout")
		}
		return nil
	})
	profiles := []config.Profile{
		fakeProfile("NL-1", "nl.example.com", 443),
		fakeProfile("FR-3", "fr.example.com", 443),
		fakeProfile("NL-1-renamed", "nl.example.com", 443), // same ImportKey as NL-1
	}
	st := sw.SweepOnce(context.Background(), profiles)

	if len(st.Results) != 2 {
		t.Fatalf("want 2 distinct results (NL deduped), got %d: %+v", len(st.Results), st.Results)
	}
	if len(*started) != 2 {
		t.Errorf("want 2 scratch xray starts, got %d", len(*started))
	}
	byRemark := map[string]Result{}
	for _, r := range st.Results {
		byRemark[r.Remark] = r
	}
	if !byRemark["NL-1"].OK {
		t.Errorf("NL-1 should be OK: %+v", byRemark["NL-1"])
	}
	if fr := byRemark["FR-3"]; fr.OK || fr.Detail != "нет ответа (таймаут)" {
		t.Errorf("FR-3 should be a classified timeout failure: %+v", fr)
	}
	if st.Results[0].CheckedAt.IsZero() {
		t.Error("CheckedAt not stamped")
	}
}

func TestSweepOnce_RecordsLatencyOnSuccess(t *testing.T) {
	sw, _ := newTestSweeper(t, func(context.Context, xrayctl.ProbeOptions) error { return nil })
	var calls int
	sw.now = func() time.Time {
		calls++
		return time.Unix(1_700_000_000, 0).Add(time.Duration(calls) * 40 * time.Millisecond)
	}
	st := sw.SweepOnce(context.Background(), []config.Profile{fakeProfile("A", "a.example.com", 443)})
	if len(st.Results) != 1 || !st.Results[0].OK {
		t.Fatalf("want one OK result, got %+v", st.Results)
	}
	if st.Results[0].LatencyMS <= 0 {
		t.Errorf("LatencyMS = %d, want > 0", st.Results[0].LatencyMS)
	}
}

func TestSweepOnce_ConfigGenFailureIsRecorded(t *testing.T) {
	sw, _ := newTestSweeper(t, func(context.Context, xrayctl.ProbeOptions) error { return nil })
	sw.genConfig = func(config.XrayConfigOptions) ([]byte, error) { return nil, errors.New("boom") }
	st := sw.SweepOnce(context.Background(), []config.Profile{fakeProfile("X", "x.example.com", 443)})
	if len(st.Results) != 1 || st.Results[0].OK || st.Results[0].Detail != "конфиг не собрался" {
		t.Fatalf("gen failure not recorded: %+v", st.Results)
	}
}

func TestSweepOnce_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sw, _ := newTestSweeper(t, func(context.Context, xrayctl.ProbeOptions) error { return nil })
	sw.probe = func(context.Context, xrayctl.ProbeOptions) error { cancel(); return nil }
	profiles := []config.Profile{
		fakeProfile("A", "a.example.com", 443),
		fakeProfile("B", "b.example.com", 443),
		fakeProfile("C", "c.example.com", 443),
	}
	st := sw.SweepOnce(ctx, profiles)
	if len(st.Results) != 1 {
		t.Errorf("cancel after the first probe should stop the sweep, got %d results", len(st.Results))
	}
}
