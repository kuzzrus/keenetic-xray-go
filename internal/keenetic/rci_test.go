package keenetic

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rciTestServer serves the running-config and version endpoints tryRead
// uses. runningCfg is the CLI text; the server returns it as KeeneticOS
// does -- {"message": [<one line per entry>]} from
// /rci/show/running-config. Extra route registrations (interface,
// object-group) can be passed as `more`.
func rciTestServer(t *testing.T, runningCfg, versionJSON string, more ...func(*http.ServeMux)) *httptest.Server {
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
	for _, fn := range more {
		fn(mux)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// rciJSONRoute registers one RCI endpoint that returns a fixed JSON body.
func rciJSONRoute(path, body string) func(*http.ServeMux) {
	return func(mux *http.ServeMux) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		})
	}
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

// --- phase 2: show interface / show object-group over RCI ---
//
// The two interface fixtures are trimmed copies of real Giga KN-1012
// (KeeneticOS 5.1.x) /rci/show/interface/<name> payloads -- string
// "yes"/"no" for `connected`, a bare `online: true` bool on the peer, a
// large byte counter that must not go scientific.

const rciBridgeJSON = `{
  "id": "Bridge0", "index": 0, "interface-name": "Home", "type": "Bridge",
  "description": "Home network",
  "traits": ["Mac", "Ethernet", "Ip", "Bridge"],
  "link": "up", "connected": "yes", "state": "up",
  "mtu": 1500, "tx-queue-length": 0, "admin-only": false,
  "address": "192.168.1.1", "mask": "255.255.255.0", "uptime": 6155,
  "global": false, "security-level": "private",
  "mac": "50:ff:20:d1:c5:a3", "auth-type": "none"
}`

const rciWGJSON = `{
  "id": "Wireguard4", "index": 4, "interface-name": "Wireguard4",
  "type": "Wireguard", "description": "keenetic-xray-wg",
  "traits": ["Ip", "Ip6", "Wireguard"],
  "link": "up", "connected": "yes", "state": "up",
  "mtu": 1280, "tx-queue-length": 50,
  "address": "172.31.209.2", "mask": "255.255.255.255", "uptime": 6132,
  "wireguard": {
    "public-key": "Qkc8d8iV9mPBcRV+Zl6NsleTl27J5IKSEJf5IpJ9YiA=",
    "listen-port": 44244, "status": "up",
    "peer": [
      { "public-key": "JZUbXGsO58Mex0oHffuZYgZ9hphh25Hc4riMstG9y0Y=",
        "description": "", "local-port": 44244, "remote-port": 41199,
        "via": "Bridge0", "remote-endpoint-address": "192.168.1.1",
        "rxbytes": 4434113272, "txbytes": 106887688,
        "last-handshake": 69, "online": true, "enabled": true }
    ]
  }
}`

func TestNdmcRun_RCIServesInterface(t *testing.T) {
	srv := rciTestServer(t, "system\n", `{"release":"5.1.3"}`,
		rciJSONRoute("/rci/show/interface/Bridge0", rciBridgeJSON),
		rciJSONRoute("/rci/show/interface/Wireguard4", rciWGJSON),
	)
	withRCIOff(t)
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

	if ip := lanIPFromShowInterface(ctx, "Bridge0"); ip != "192.168.1.1" {
		t.Errorf("lanIPFromShowInterface via RCI = %q, want 192.168.1.1", ip)
	}
	if !WGInterfaceUp(ctx, "Wireguard4") {
		t.Error("WGInterfaceUp via RCI = false, want true (state: up)")
	}
	pk, err := WGInterfacePublicKey(ctx, "Wireguard4")
	if err != nil || pk != "Qkc8d8iV9mPBcRV+Zl6NsleTl27J5IKSEJf5IpJ9YiA=" {
		t.Errorf("WGInterfacePublicKey via RCI = %q, %v", pk, err)
	}
	sum, err := ShowWGTransport(ctx, "Wireguard4")
	if err != nil {
		t.Fatalf("ShowWGTransport via RCI: %v", err)
	}
	for _, want := range []string{"состояние: up", "адрес: 172.31.209.2", "mtu: 1280", "last-handshake: 69", "online: yes"} {
		if !strings.Contains(sum, want) {
			t.Errorf("ShowWGTransport summary missing %q:\n%s", want, sum)
		}
	}
}

func TestNdmcRun_RCIInterfaceFetchErrorFallsThrough(t *testing.T) {
	// Server has no /rci/show/interface route -> 404 -> ndmc still gets a shot.
	srv := rciTestServer(t, "system\n", `{"release":"5.1.3"}`)
	withRCIOff(t)
	var seen string
	origExec := ndmcExec
	ndmcExec = func(_ context.Context, cmd string) (string, error) {
		seen = cmd
		return "exec-answer", nil
	}
	t.Cleanup(func() { ndmcExec = origExec })
	if _, err := UseRCI(srv.URL); err != nil {
		t.Fatalf("UseRCI: %v", err)
	}
	out, err := ndmcRun(context.Background(), "show interface Bridge0")
	if err != nil || out != "exec-answer" || seen != "show interface Bridge0" {
		t.Errorf("show interface fetch error should fall through to ndmc: out=%q err=%v seen=%q", out, err, seen)
	}
}

func TestInterfaceTextFromRCI(t *testing.T) {
	txt, err := interfaceTextFromRCI([]byte(rciWGJSON))
	if err != nil {
		t.Fatalf("interfaceTextFromRCI: %v", err)
	}
	// wireguard: must come before the interface public-key, which must
	// come before peer: -- WGInterfacePublicKey relies on that order.
	iWG := strings.Index(txt, "wireguard:")
	iKey := strings.Index(txt, "public-key: Qkc8d8iV")
	iPeer := strings.Index(txt, "peer:")
	if !(iWG >= 0 && iWG < iKey && iKey < iPeer) {
		t.Errorf("block order wrong (wg=%d key=%d peer=%d):\n%s", iWG, iKey, iPeer, txt)
	}
	if !strings.Contains(txt, "online: yes") {
		t.Errorf("peer bool `online:true` should render as `yes`:\n%s", txt)
	}
	if !strings.Contains(txt, "mtu: 1280") {
		t.Errorf("integer mtu should render without a decimal:\n%s", txt)
	}
	if !strings.Contains(txt, "rxbytes: 4434113272") {
		t.Errorf("large byte counter must not go scientific:\n%s", txt)
	}

	// Wrapped form {"Wireguard4": {...}}.
	wrapped := `{"Wireguard4":` + rciWGJSON + `}`
	tw, err := interfaceTextFromRCI([]byte(wrapped))
	if err != nil || !strings.Contains(tw, "state: up") {
		t.Errorf("wrapped form not unwrapped: %v\n%s", err, tw)
	}

	// Unrecognisable object -> error (so ndmcRun surfaces it).
	if _, err := interfaceTextFromRCI([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("expected an error for an object with no state/address/id")
	}
	if _, err := interfaceTextFromRCI([]byte(`not json`)); err == nil {
		t.Error("expected an error for non-JSON")
	}
}

func TestScalarString(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"up"`, "up"},
		{`1500`, "1500"},
		{`1500.0`, "1500"},
		{`3.5`, "3.5"},
		{`true`, "yes"},
		{`false`, "no"},
		{`null`, ""},
		{`{"x":1}`, ""},
		{`[1,2]`, ""},
	}
	for _, c := range cases {
		if got := scalarString([]byte(c.in)); got != c.want {
			t.Errorf("scalarString(%s) = %q, want %q", c.in, got, c.want)
		}
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
