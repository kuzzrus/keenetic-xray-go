package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL7SNIConfig_QUICModeNormalizes(t *testing.T) {
	cases := map[string]string{
		"":          L7SNIQUICOff,
		"off":       L7SNIQUICOff,
		"observe":   L7SNIQUICObserve,
		"act":       L7SNIQUICAct,
		"ACT":       L7SNIQUICOff, // modes are exact; a mistyped one must not switch the action on
		"on":        L7SNIQUICOff,
		"something": L7SNIQUICOff,
	}
	for in, want := range cases {
		if got := (L7SNIConfig{QUIC: in}).QUICMode(); got != want {
			t.Errorf("QUICMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestL7SNIConfig_QUICRoundTripAndOldConfigs: the mode survives a save and a
// load, and a config written before the field existed (no "quic" key) reads
// as off - not as an error and not as anything switched on.
func TestL7SNIConfig_QUICRoundTripAndOldConfigs(t *testing.T) {
	data, err := json.Marshal(L7SNIConfig{Enabled: true, QUIC: L7SNIQUICObserve})
	if err != nil {
		t.Fatal(err)
	}
	var back L7SNIConfig
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Enabled || back.QUICMode() != L7SNIQUICObserve {
		t.Errorf("round trip lost the setting: %+v", back)
	}

	var old L7SNIConfig
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &old); err != nil {
		t.Fatal(err)
	}
	if !old.Enabled || old.QUICMode() != L7SNIQUICOff {
		t.Errorf("a config without the field read as %+v (mode %q)", old, old.QUICMode())
	}

	off, _ := json.Marshal(L7SNIConfig{Enabled: true})
	if strings.Contains(string(off), "quic") {
		t.Errorf("an unset mode is written out: %s", off)
	}
}

func TestConfig_EffectiveL7SNIQUIC(t *testing.T) {
	mk := func(l7, adaptive bool, quic string) *Config {
		c := Default()
		c.L7SNI = L7SNIConfig{Enabled: l7, QUIC: quic}
		c.AdaptiveRoute.Enabled = adaptive
		return c
	}
	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"l7sni off beats everything", mk(false, true, "act"), L7SNIQUICOff},
		{"unset is off", mk(true, true, ""), L7SNIQUICOff},
		{"observe stands without adaptive routing", mk(true, false, "observe"), L7SNIQUICObserve},
		{"act with adaptive routing", mk(true, true, "act"), L7SNIQUICAct},
		{"act without adaptive routing degrades to observe", mk(true, false, "act"), L7SNIQUICObserve},
		{"a typo is off", mk(true, true, "Act"), L7SNIQUICOff},
	}
	for _, tc := range cases {
		if got := tc.cfg.EffectiveL7SNIQUIC(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
