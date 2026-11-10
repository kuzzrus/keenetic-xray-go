//go:build linux

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/featuredeps"
)

// The capture's start: a tool that is missing and cannot be installed ends the
// session with the reason in the log and the manual command -- BEFORE the first
// iptables call, which is where it used to die with "executable file not found"
// and no hint.
func TestL7SNIClassifySession_MissingToolIsLoggedAndNothingIsTouched(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = true
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	fakeRouter(t)
	stub := stubDeps(t, nil, requiredFailure("iptables"))

	var logs []string
	started, err := l7SNIClassifySession(context.Background(), func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) })
	if started || err == nil {
		t.Fatalf("started=%v err=%v, want a session that did not start and says why", started, err)
	}
	if len(stub.features) != 1 || stub.features[0] != featuredeps.L7SNI {
		t.Errorf("asked for %v, want the L7 SNI needs", stub.features)
	}
	joined := strings.Join(logs, "\n")
	for _, want := range []string{"l7sni: not starting", "iptables", "Вручную: opkg update && opkg install iptables"} {
		if !strings.Contains(joined, want) {
			t.Errorf("log lacks %q:\n%s", want, joined)
		}
	}
	for _, late := range []string{"installing NFLOG rules", "opening NFLOG capture socket", "WAN interface"} {
		if strings.Contains(joined, late) {
			t.Errorf("the session went on to %q after the tool check failed:\n%s", late, joined)
		}
	}
}

// Over any number of starts of the session (it restarts every few seconds while
// the NFLOG socket keeps failing) only what the capture cannot run without is
// checked, and synchronously: an optional tool never delays the start nor makes
// a restart run `opkg update` again.
func TestL7SNIClassifySession_OnlyRequiredToolsAreChecked(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgPath)
	cfg := config.Default()
	cfg.L7SNI.Enabled = true
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	fakeRouter(t)

	var all, requiredOnly int
	origE, origR, origM := featureEnsure, featureEnsureRequired, featureMissing
	featureEnsure = func(context.Context, featuredeps.Feature) featuredeps.Result {
		all++
		return requiredFailure("iptables")
	}
	featureEnsureRequired = func(context.Context, featuredeps.Feature) featuredeps.Result {
		requiredOnly++
		return requiredFailure("iptables")
	}
	t.Cleanup(func() { featureEnsure, featureEnsureRequired, featureMissing = origE, origR, origM })

	for i := 0; i < 3; i++ {
		_, _ = l7SNIClassifySession(context.Background(), func(string, ...any) {})
	}
	if all != 0 || requiredOnly != 3 {
		t.Errorf("full ensure ran %d times and the required-only one %d times over three starts, want 0 and 3", all, requiredOnly)
	}
}
