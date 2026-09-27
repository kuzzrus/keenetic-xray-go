package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestProxy0DisableHealthCheck_JSON pins the on-disk key the CLI help and
// the docs name, and that the default (check on) is what an existing
// config.json -- which has never heard of the field -- decodes to.
func TestProxy0DisableHealthCheck_JSON(t *testing.T) {
	var p Proxy0Config
	if err := json.Unmarshal([]byte(`{"enabled":true}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.DisableHealthCheck {
		t.Error("an existing config without the field must keep the health check on")
	}

	p.DisableHealthCheck = true
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"disable_health_check":true`) {
		t.Errorf("marshalled %s, want the disable_health_check key", b)
	}

	p.DisableHealthCheck = false
	b, _ = json.Marshal(p)
	if strings.Contains(string(b), "disable_health_check") {
		t.Errorf("marshalled %s -- the default must stay out of config.json (omitempty)", b)
	}
}
