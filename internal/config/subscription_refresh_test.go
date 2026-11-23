package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionRefreshInterval(t *testing.T) {
	cases := []struct {
		name  string
		hours int
		off   bool
		want  time.Duration
	}{
		{"default is twelve hours", 0, false, 12 * time.Hour},
		{"explicit", 6, false, 6 * time.Hour},
		{"the longest", MaxSubscriptionRefreshHours, false, 168 * time.Hour},
		{"off wins over an interval", 6, true, 0},
		{"off", 0, true, 0},
	}
	for _, c := range cases {
		cfg := Default()
		cfg.SubscriptionRefreshHours, cfg.SubscriptionNoAutoRefresh = c.hours, c.off
		if got := cfg.SubscriptionRefreshInterval(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSetSubscriptionAutoRefresh(t *testing.T) {
	cfg := Default()
	for _, ok := range []struct {
		arg   string
		hours int
		off   bool
	}{
		{"off", 0, true},
		{"6", 6, false},    // a number also switches it on
		{"off", 6, true},   // switching off keeps the interval ...
		{" ON ", 6, false}, // ... which is back when it is switched on
		{"168", 168, false},
		{"1", 1, false},
	} {
		if err := cfg.SetSubscriptionAutoRefresh(ok.arg); err != nil {
			t.Fatalf("%q: %v", ok.arg, err)
		}
		if cfg.SubscriptionRefreshHours != ok.hours || cfg.SubscriptionNoAutoRefresh != ok.off {
			t.Errorf("%q: hours %d off %v, want %d %v", ok.arg, cfg.SubscriptionRefreshHours, cfg.SubscriptionNoAutoRefresh, ok.hours, ok.off)
		}
	}

	before := [2]any{cfg.SubscriptionRefreshHours, cfg.SubscriptionNoAutoRefresh}
	for _, bad := range []string{"", "0", "-3", "169", "1.5", "often", "12h"} {
		if err := cfg.SetSubscriptionAutoRefresh(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if after := [2]any{cfg.SubscriptionRefreshHours, cfg.SubscriptionNoAutoRefresh}; after != before {
		t.Error("a rejected value changed the config")
	}
}

func TestValidate_SubscriptionRefreshHours(t *testing.T) {
	for _, h := range []int{0, 1, 12, 168} {
		cfg := Default()
		cfg.SubscriptionRefreshHours = h
		if err := cfg.Validate(); err != nil {
			t.Errorf("%d hours: %v", h, err)
		}
	}
	for _, h := range []int{-1, 169, 1000} {
		cfg := Default()
		cfg.SubscriptionRefreshHours = h
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "subscription_refresh_hours") {
			t.Errorf("%d hours: err = %v", h, err)
		}
	}
}

// A config that never touched the setting must serialize exactly as before:
// both fields are omitempty.
func TestSubscriptionRefreshFieldsAreOmittedWhenUnset(t *testing.T) {
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "subscription_refresh_hours") || strings.Contains(string(b), "subscription_no_auto_refresh") {
		t.Errorf("unset fields serialized: %s", b)
	}
	cfg := Default()
	cfg.SubscriptionRefreshHours, cfg.SubscriptionNoAutoRefresh = 6, true
	b, _ = json.Marshal(cfg)
	if !strings.Contains(string(b), `"subscription_refresh_hours":6`) || !strings.Contains(string(b), `"subscription_no_auto_refresh":true`) {
		t.Errorf("set fields not serialized: %s", b)
	}
}

func TestRedactURL(t *testing.T) {
	if got := RedactURL("https://panel.example.com/sub/TOKEN?a=b"); got != "https://panel.example.com/<redacted>" {
		t.Errorf("got %q", got)
	}
}
