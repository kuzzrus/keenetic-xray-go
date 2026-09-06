package config

import (
	"path/filepath"
	"testing"
)

func validProfile() Profile {
	return Profile{
		Remark:     "test",
		UUID:       "11111111-2222-3333-4444-555555555555",
		Address:    "example.com",
		Port:       443,
		Encryption: "none",
		Network:    "tcp",
		Security:   "none",
	}
}

func TestProfileValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *Profile)
		wantErr bool
	}{
		{"valid", func(p *Profile) {}, false},
		{"missing uuid", func(p *Profile) { p.UUID = "" }, true},
		{"missing address", func(p *Profile) { p.Address = "" }, true},
		{"port zero", func(p *Profile) { p.Port = 0 }, true},
		{"port too large", func(p *Profile) { p.Port = 70000 }, true},
		{"bad network", func(p *Profile) { p.Network = "kcp" }, true},
		{"xhttp network valid", func(p *Profile) { p.Network = "xhttp" }, false},
		{"http network valid", func(p *Profile) { p.Network = "http" }, false},
		{"h2 network valid (alias)", func(p *Profile) { p.Network = "h2" }, false},
		{"bad security", func(p *Profile) { p.Security = "aes" }, true},
		{"reality without pbk/sid", func(p *Profile) { p.Security = "reality" }, true},
		{"reality without sni", func(p *Profile) {
			p.Security = "reality"
			p.PublicKey = "pk"
			p.ShortID = "sid"
		}, true},
		{"reality with pbk/sid/sni", func(p *Profile) {
			p.Security = "reality"
			p.PublicKey = "pk"
			p.ShortID = "sid"
			p.SNI = "www.example.com"
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validProfile()
			tc.mutate(&p)
			err := p.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestConfigDefault(t *testing.T) {
	c := Default()
	if c.Variant != VariantFull {
		t.Errorf("Default().Variant = %q, want %q", c.Variant, VariantFull)
	}
	if c.PrimaryIndex != -1 || c.BackupIndex != -1 {
		t.Errorf("Default() indices = (%d, %d), want (-1, -1)", c.PrimaryIndex, c.BackupIndex)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Default() should validate cleanly: %v", err)
	}
	if c.Primary() != nil || c.Backup() != nil {
		t.Errorf("Default() should have no primary/backup profile")
	}
}

func TestConfigLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(filepath.Join(dir, "does-not-exist.json"))
	if err != nil {
		t.Fatalf("Load of missing file should not error, got: %v", err)
	}
	if c.Variant != VariantFull || len(c.Profiles) != 0 {
		t.Errorf("Load of missing file should return Default(), got %#v", c)
	}
}

func TestConfigSaveLoad_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	c := Default()
	c.Profiles = []Profile{validProfile(), validProfile()}
	c.Profiles[1].Remark = "backup"
	c.Profiles[1].Address = "backup.example.com"
	c.PrimaryIndex = 0
	c.BackupIndex = 1
	c.Subscription = &Subscription{URL: "https://sub.example.com/feed"}

	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Variant != c.Variant {
		t.Errorf("Variant = %q, want %q", loaded.Variant, c.Variant)
	}
	if len(loaded.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(loaded.Profiles))
	}
	if loaded.Primary().Address != "example.com" {
		t.Errorf("Primary().Address = %q, want %q", loaded.Primary().Address, "example.com")
	}
	if loaded.Backup().Address != "backup.example.com" {
		t.Errorf("Backup().Address = %q, want %q", loaded.Backup().Address, "backup.example.com")
	}
	if loaded.Subscription == nil || loaded.Subscription.URL != "https://sub.example.com/feed" {
		t.Errorf("Subscription = %#v, want URL https://sub.example.com/feed", loaded.Subscription)
	}
}

func TestConfigSave_RefusesInvalid(t *testing.T) {
	dir := t.TempDir()
	c := Default()
	c.PrimaryIndex = 5 // out of range, no profiles configured
	if err := c.Save(filepath.Join(dir, "config.json")); err == nil {
		t.Error("Save should refuse an invalid config, got nil error")
	}
}

func TestConfigValidate_ProfileIndicesOutOfRange(t *testing.T) {
	c := Default()
	c.Profiles = []Profile{validProfile()}

	c.PrimaryIndex = 1 // only index 0 exists
	if err := c.Validate(); err == nil {
		t.Error("expected error for out-of-range primary_index")
	}

	c.PrimaryIndex = 0
	c.BackupIndex = -2 // below the -1 "unset" sentinel
	if err := c.Validate(); err == nil {
		t.Error("expected error for backup_index below the -1 unset sentinel")
	}
}

func TestConfigValidate_Proxy0Protocol(t *testing.T) {
	c := Default()
	for _, ok := range []string{"", "socks5", "http"} {
		c.Proxy0.Protocol = ok
		if err := c.Validate(); err != nil {
			t.Errorf("proxy0.protocol %q: unexpected error %v", ok, err)
		}
	}
	c.Proxy0.Protocol = "ftp"
	if err := c.Validate(); err == nil {
		t.Error("proxy0.protocol \"ftp\": expected an error")
	}
}

func TestConfigValidate_Proxy0MSSClamp(t *testing.T) {
	c := Default()
	for _, ok := range []int{0, -1, 1200, 1360, 1452} {
		c.Proxy0.MSSClamp = ok
		if err := c.Validate(); err != nil {
			t.Errorf("proxy0.mss_clamp %d: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []int{1, 1199, 1453, 9000} {
		c.Proxy0.MSSClamp = bad
		if err := c.Validate(); err == nil {
			t.Errorf("proxy0.mss_clamp %d: expected an error", bad)
		}
	}
}

func TestProxy0MSSClampValueAndText(t *testing.T) {
	cases := []struct {
		raw       int
		wantValue int
		wantText  string
	}{
		{0, DefaultMSSClamp, "авто (1360)"},
		{-1, 0, "выкл"},
		{1400, 1400, "1400"},
	}
	for _, tc := range cases {
		p := Proxy0Config{MSSClamp: tc.raw}
		if got := p.MSSClampValue(); got != tc.wantValue {
			t.Errorf("MSSClampValue(%d) = %d, want %d", tc.raw, got, tc.wantValue)
		}
		if got := p.MSSClampText(); got != tc.wantText {
			t.Errorf("MSSClampText(%d) = %q, want %q", tc.raw, got, tc.wantText)
		}
	}
}

func TestParseMSSClampArg(t *testing.T) {
	ok := map[string]int{
		"auto": 0, "AUTO": 0, "": 0, "default": 0,
		"off": -1, "none": -1, "0": -1,
		"1200": 1200, "1360": 1360, "1452": 1452, " 1400 ": 1400,
	}
	for in, want := range ok {
		got, err := ParseMSSClampArg(in)
		if err != nil || got != want {
			t.Errorf("ParseMSSClampArg(%q) = (%d, %v), want (%d, nil)", in, got, err, want)
		}
	}
	for _, bad := range []string{"1199", "1453", "abc", "1360px", "-5"} {
		if _, err := ParseMSSClampArg(bad); err == nil {
			t.Errorf("ParseMSSClampArg(%q): expected an error", bad)
		}
	}
}

func TestConfigValidate_Proxy0Interface(t *testing.T) {
	c := Default()
	for _, ok := range []string{"", "Proxy0", "Proxy1", "Proxy12"} {
		c.Proxy0.Interface = ok
		if err := c.Validate(); err != nil {
			t.Errorf("proxy0.interface %q: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []string{"proxy0", "Proxy", "Proxy 1", "Proxy0x", "eth0"} {
		c.Proxy0.Interface = bad
		if err := c.Validate(); err == nil {
			t.Errorf("proxy0.interface %q: expected an error", bad)
		}
	}
}

func TestValidProxyIface(t *testing.T) {
	for _, ok := range []string{"", "Proxy0", "Proxy7", "Proxy100"} {
		if !ValidProxyIface(ok) {
			t.Errorf("ValidProxyIface(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"proxy1", "Proxy", "Proxy1 ", " Proxy1", "Prox1"} {
		if ValidProxyIface(bad) {
			t.Errorf("ValidProxyIface(%q) = true, want false", bad)
		}
	}
}

func TestValidXrayCoreTag(t *testing.T) {
	for _, ok := range []string{"", "v26.3.27", "v26.7.28", "v1.0.0"} {
		if !ValidXrayCoreTag(ok) {
			t.Errorf("ValidXrayCoreTag(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"26.3.27", "v26.3", "v26.3.27-rc1", "latest", "v26.3.27 "} {
		if ValidXrayCoreTag(bad) {
			t.Errorf("ValidXrayCoreTag(%q) = true, want false", bad)
		}
	}
}

func TestConfigValidate_XrayCoreTag(t *testing.T) {
	c := Default()
	c.XrayCoreTag = "v26.7.28"
	if err := c.Validate(); err != nil {
		t.Errorf("xray_core_tag v26.7.28: unexpected error %v", err)
	}
	c.XrayCoreTag = "nightly"
	if err := c.Validate(); err == nil {
		t.Error("xray_core_tag \"nightly\": expected an error")
	}
}

func TestConfigValidate_XHTTPMode(t *testing.T) {
	c := Default()
	for _, ok := range []string{"", "auto", "packet-up", "stream-up", "stream-one"} {
		c.XHTTPMode = ok
		if err := c.Validate(); err != nil {
			t.Errorf("xhttp_mode %q: unexpected error %v", ok, err)
		}
	}
	c.XHTTPMode = "turbo"
	if err := c.Validate(); err == nil {
		t.Error("xhttp_mode \"turbo\": expected an error")
	}
}

func TestProfileValidate_XHTTPExtra(t *testing.T) {
	p := validProfile()
	p.XHTTPExtra = []byte(`{"xmux":{"maxConcurrency":"16-32"}}`)
	if err := p.Validate(); err != nil {
		t.Errorf("valid xhttp_extra rejected: %v", err)
	}
	p.XHTTPExtra = []byte(`["not","an","object"]`)
	if err := p.Validate(); err == nil {
		t.Error("xhttp_extra that isn't a JSON object should be rejected")
	}
	p.XHTTPExtra = []byte(`{broken`)
	if err := p.Validate(); err == nil {
		t.Error("invalid-JSON xhttp_extra should be rejected")
	}
}

func TestConfigSave_CreatesConfigDir(t *testing.T) {
	// Save on a fresh box, before postinst-setup has made the dir.
	path := filepath.Join(t.TempDir(), "etc", "keenetic-xray", "config.json")
	if err := Default().Save(path); err != nil {
		t.Fatalf("Save into a missing dir: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load back: %v", err)
	}
}

func TestClassifyRouteEntry(t *testing.T) {
	okCases := []struct {
		in   string
		kind RouteEntryKind
		norm string
	}{
		{"youtube.com", RouteDomain, "youtube.com"},
		{"  WWW.Example.CO.UK. ", RouteDomain, "www.example.co.uk"},
		{"sub-domain.a.io", RouteDomain, "sub-domain.a.io"},
		{"8.8.8.8", RouteSubnet, "8.8.8.8"},
		{"1.2.3.0/24", RouteSubnet, "1.2.3.0/24"},
		{"1.2.3.4/24", RouteSubnet, "1.2.3.0/24"}, // canonicalized
		{"203.0.113.7/32", RouteSubnet, "203.0.113.7"},
	}
	for _, c := range okCases {
		k, n, err := ClassifyRouteEntry(c.in)
		if err != nil {
			t.Errorf("ClassifyRouteEntry(%q): unexpected error %v", c.in, err)
			continue
		}
		if k != c.kind || n != c.norm {
			t.Errorf("ClassifyRouteEntry(%q) = (%v, %q), want (%v, %q)", c.in, k, n, c.kind, c.norm)
		}
	}

	badCases := []string{
		"", "   ", "*.youtube.com", "youtube.*",
		"2001:db8::1", "::/0", "[::1]",
		"0.0.0.0/0", "10.0.0.0/8", "192.168.1.0/24", "172.20.0.0/16",
		"127.0.0.1", "169.254.1.1", "224.0.0.1",
		"пример.рф", "not a domain", "1.2.3", "1.2.3.4.5",
	}
	for _, c := range badCases {
		if _, _, err := ClassifyRouteEntry(c); err == nil {
			t.Errorf("ClassifyRouteEntry(%q): expected an error", c)
		}
	}
}

func TestSanitizeRouteListName(t *testing.T) {
	cases := map[string]string{
		"youtube":                                "youtube",
		"  My List!  ":                           "my-list",
		"соцсети":                                "",
		"a__b--c":                                "a-b-c",
		"----":                                   "",
		"VeryLongNameThatExceedsTwentyFourChars": "verylongnamethatexceedst",
	}
	for in, want := range cases {
		if got := SanitizeRouteListName(in); got != want {
			t.Errorf("SanitizeRouteListName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRoutingConfig_Validate(t *testing.T) {
	ok := RoutingConfig{Lists: []RouteList{
		{Name: "youtube", Entries: []string{"youtube.com", "1.2.3.0/24"}},
		{Name: "work", Entries: []string{"corp.example"}, Interface: "Proxy1", Disabled: true},
	}}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid routing config rejected: %v", err)
	}

	bad := []RoutingConfig{
		{Lists: []RouteList{{Name: "соцсети", Entries: nil}}},                                // unusable name
		{Lists: []RouteList{{Name: "a"}, {Name: "A"}}},                                       // collide to "a"
		{Lists: []RouteList{{Name: "x", Entries: []string{"192.168.0.0/16"}}}},               // private subnet
		{Lists: []RouteList{{Name: "x", Interface: "eth0", Entries: []string{"a.io"}}}},      // bad iface
		{Lists: []RouteList{{Name: "x", Entries: make([]string, MaxRouteEntriesPerList+1)}}}, // too many
	}
	for i, rc := range bad {
		if err := rc.Validate(); err == nil {
			t.Errorf("bad routing config %d accepted", i)
		}
	}
}

func TestConfig_Proxy0Port(t *testing.T) {
	c := Default() // SOCKSPort 1080, HTTPPort 1081 from DefaultFailoverConfig
	if got := c.Proxy0Port(); got != c.Failover.SOCKSPort {
		t.Errorf("Proxy0Port() default = %d, want SOCKS port %d", got, c.Failover.SOCKSPort)
	}
	c.Proxy0.Protocol = "http"
	if got := c.Proxy0Port(); got != c.Failover.HTTPPort {
		t.Errorf("Proxy0Port() http = %d, want HTTP port %d", got, c.Failover.HTTPPort)
	}
}
