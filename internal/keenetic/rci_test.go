package keenetic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rciTestServer serves the two endpoints tryRead uses. runningCfg is
// the CLI text; the server returns it as KeeneticOS does --
// {"message": [<one line per entry>]} from /rci/show/running-config.
func rciTestServer(t *testing.T, runningCfg, versionJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/rci/show/running-config", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{
			"message": strings.Split(strings.TrimRight(runningCfg, "\n"), "\n"),
		})
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/rci/show/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(versionJSON))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// withRCIOff restores RCI state after a test that calls UseRCI.
func withRCIOff(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { _, _ = UseRCI("") })
}

func TestUseRCI_BadURLLeavesModeOff(t *testing.T) {
	withRCIOff(t)
	if _, err := UseRCI("http://127.0.0.1:1"); err == nil {
		t.Fatal("expected an error for an unreachable RCI base")
	}
	if RCIActive() {
		t.Error("RCI must stay off after a failed UseRCI")
	}
}

func TestUseRCI_EmptyClears(t *testing.T) {
	srv := rciTestServer(t, "system\n", `{"release":"5.1.3"}`)
	withRCIOff(t)
	if _, err := UseRCI(srv.URL); err != nil {
		t.Fatalf("UseRCI: %v", err)
	}
	if !RCIActive() {
		t.Fatal("RCI should be active")
	}
	if _, err := UseRCI(""); err != nil {
		t.Fatalf("UseRCI(\"\"): %v", err)
	}
	if RCIActive() {
		t.Error("RCI should be off after UseRCI(\"\")")
	}
}

func TestNdmcRun_RCIServesRunningConfigAndVersion(t *testing.T) {
	const cfgText = "interface Bridge0\n    ip address 192.168.7.1/24\n!\n"
	srv := rciTestServer(t, cfgText, `{"release":"5.1.3","model":"KN-1012"}`)
	withRCIOff(t)

	// ndmcExec must NOT be reached for the two RCI-served reads; make it
	// blow up if it is.
	origExec := ndmcExec
	ndmcExec = func(_ context.Context, cmd string) (string, error) {
		t.Errorf("ndmcExec called for %q -- RCI should have served it", cmd)
		return "", nil
	}
	t.Cleanup(func() { ndmcExec = origExec })

	if _, err := UseRCI(srv.URL); err != nil {
		t.Fatalf("UseRCI: %v", err)
	}
	ctx := context.Background()

	got, err := ndmcRun(ctx, "show running-config")
	if err != nil || got != cfgText {
		t.Fatalf("show running-config via RCI = %q, %v; want %q", got, err, cfgText)
	}

	ver, err := ndmcRun(ctx, "show version")
	if err != nil || ver != "title: 5.1.3\n" {
		t.Fatalf("show version via RCI = %q, %v; want \"title: 5.1.3\\n\"", ver, err)
	}

	// OSVersion runs on top of the same path.
	maj, min, patch, err := OSVersion(ctx)
	if err != nil || maj != 5 || min != 1 || patch != 3 {
		t.Fatalf("OSVersion via RCI = %d.%d.%d, %v; want 5.1.3", maj, min, patch, err)
	}
}

func TestNdmcRun_RCIFallsThroughForOtherCommands(t *testing.T) {
	srv := rciTestServer(t, "system\n", `{"release":"5.1.3"}`)
	withRCIOff(t)

	var seen []string
	origExec := ndmcExec
	ndmcExec = func(_ context.Context, cmd string) (string, error) {
		seen = append(seen, cmd)
		return "exec:" + cmd, nil
	}
	t.Cleanup(func() { ndmcExec = origExec })

	if _, err := UseRCI(srv.URL); err != nil {
		t.Fatalf("UseRCI: %v", err)
	}
	ctx := context.Background()

	for _, cmd := range []string{
		"show interface Wireguard0",
		"dns-proxy tls upstream 9.9.9.9 sni dns.quad9.net",
		"show object-group fqdn keenetic-xray-telegram",
	} {
		out, err := ndmcRun(ctx, cmd)
		if err != nil || out != "exec:"+cmd {
			t.Errorf("%q: got %q, %v; want it to fall through to ndmcExec", cmd, out, err)
		}
	}
	if len(seen) != 3 {
		t.Errorf("ndmcExec saw %v, want all 3 non-RCI commands", seen)
	}
}

func TestVersionTextFromRCI(t *testing.T) {
	cases := []struct {
		name, json, want string
		wantErr          bool
	}{
		{"title key", `{"title":"5.1.3"}`, "title: 5.1.3\n", false},
		{"release key", `{"release":"5.2.0","x":1}`, "title: 5.2.0\n", false},
		{"version key", `{"version":"4.1"}`, "title: 4.1\n", false},
		{"no version field", `{"model":"KN-1012"}`, "", true},
		{"not json", `oops`, "", true},
	}
	for _, c := range cases {
		got, err := versionTextFromRCI([]byte(c.json))
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAvailable_TrueWithRCIEvenWithoutNdmc(t *testing.T) {
	srv := rciTestServer(t, "system\n", `{"release":"5.1.3"}`)
	withRCIOff(t)

	origLook := lookNdmc
	lookNdmc = func() error { return http.ErrNotSupported } // pretend ndmc isn't on PATH
	t.Cleanup(func() { lookNdmc = origLook })

	if Available() {
		t.Fatal("Available() should be false with no ndmc and no RCI")
	}
	if _, err := UseRCI(srv.URL); err != nil {
		t.Fatalf("UseRCI: %v", err)
	}
	if !Available() {
		t.Error("Available() should be true once RCI is active, even without ndmc")
	}
}

func TestRunningConfigFromRCI(t *testing.T) {
	// Array form (the normal KeeneticOS shape).
	arr := `{"message":["system","    hostname X","!"]}`
	got, err := runningConfigFromRCI([]byte(arr))
	if err != nil || got != "system\n    hostname X\n!\n" {
		t.Errorf("array form = %q, %v", got, err)
	}
	// String form (some builds).
	str := `{"message":"system\n    hostname X\n!\n"}`
	got, err = runningConfigFromRCI([]byte(str))
	if err != nil || got != "system\n    hostname X\n!\n" {
		t.Errorf("string form = %q, %v", got, err)
	}
	// Junk.
	if _, err := runningConfigFromRCI([]byte(`not json`)); err == nil {
		t.Error("expected an error for non-JSON")
	}
	if _, err := runningConfigFromRCI([]byte(`{"message":123}`)); err == nil {
		t.Error("expected an error for an unexpected message shape")
	}
}
