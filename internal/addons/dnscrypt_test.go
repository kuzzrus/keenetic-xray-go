package addons

import (
	"context"
	"strings"
	"testing"
)

func TestDnscrypt_InstallWritesTomlAndStarts(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("dnscrypt")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !contains(f.opkgCalls, "install dnscrypt-proxy2 ca-certificates") {
		t.Errorf("opkg install line: %v", f.opkgCalls)
	}
	toml := string(f.files[dnscryptConf])
	for _, want := range []string{
		"listen_addresses = ['127.0.0.1:65053']",
		"require_dnssec = true",
		"require_nolog = true",
		"[sources.relays]",
		"[anonymized_dns]", // on by default
		unboundManagedMark,
	} {
		if !strings.Contains(toml, want) {
			t.Errorf("toml missing %q:\n%s", want, toml)
		}
	}
	for _, line := range strings.Split(toml, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "listen_addresses") &&
			(strings.Contains(line, ":53'") || strings.Contains(line, ":5353'")) {
			t.Errorf("must not listen on :53 / :5353: %s", line)
		}
	}
	if !contains(f.initCalls, dnscryptInit+" start") {
		t.Errorf("start not called: %v", f.initCalls)
	}
}

func TestDnscrypt_ConfigureAnonAndDnssec(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("dnscrypt")
	f.installed[dnscryptPkg] = "2.1-test"
	f.files[dnscryptConf] = []byte(dnscryptConfBody(false, "", true, true))

	if err := a.Configure(ctx, map[string]string{"anonymized": "off", "dnssec": "off"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	toml := string(f.files[dnscryptConf])
	if strings.Contains(toml, "[anonymized_dns]") {
		t.Errorf("anonymized_dns block should be gone:\n%s", toml)
	}
	if !strings.Contains(toml, "require_dnssec = false") {
		t.Errorf("dnssec not disabled:\n%s", toml)
	}
	if d := dnscryptRead(ctx); d.anonymized || d.dnssec {
		t.Errorf("dnscryptRead = %+v, want anon=false dnssec=false", d)
	}

	if err := a.Configure(ctx, map[string]string{"nope": "1"}); err == nil {
		t.Error("unknown key should fail")
	}
	if err := a.Configure(ctx, map[string]string{"anonymized": "maybe"}); err == nil {
		t.Error("anonymized=maybe should fail")
	}
}

func TestDnscrypt_RouterDNSOnOffAndRemove(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ns := map[string]bool{}
	withUnboundKeeneticSeam(t, true, "192.168.1.1", ns) // shared seam helper
	ctx := context.Background()
	a, _ := Find("dnscrypt")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err != nil {
		t.Fatalf("router-dns=on: %v", err)
	}
	toml := string(f.files[dnscryptConf])
	if !strings.Contains(toml, dnscryptMark) || !strings.Contains(toml, "192.168.1.1:65053") {
		t.Errorf("toml not in router mode:\n%s", toml)
	}
	if !ns["192.168.1.1:65053"] {
		t.Errorf("ip name-server 192.168.1.1:65053 should be added; have %v", ns)
	}
	if d := dnscryptRead(ctx); !d.routerMode || d.routerIP != "192.168.1.1" || d.port != 65053 {
		t.Errorf("dnscryptRead = %+v", d)
	}

	if err := a.Configure(ctx, map[string]string{"router-dns": "off"}); err != nil {
		t.Fatalf("router-dns=off: %v", err)
	}
	if ns["192.168.1.1:65053"] {
		t.Errorf("name-server should be gone; have %v", ns)
	}

	// Remove while in router mode reverts the name-server.
	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ns["192.168.1.1:65053"] {
		t.Error("Remove must drop the name-server entry")
	}
	if _, still := f.installed[dnscryptPkg]; still {
		t.Error("dnscrypt-proxy2 should be removed")
	}
}

func TestParseOnOff(t *testing.T) {
	for _, s := range []string{"on", "yes", "true", "1"} {
		if b, err := parseOnOff(s); err != nil || !b {
			t.Errorf("parseOnOff(%q) = %v,%v", s, b, err)
		}
	}
	for _, s := range []string{"off", "no", "false", "0"} {
		if b, err := parseOnOff(s); err != nil || b {
			t.Errorf("parseOnOff(%q) = %v,%v", s, b, err)
		}
	}
	if _, err := parseOnOff("nope"); err == nil {
		t.Error("parseOnOff(nope) should error")
	}
}
