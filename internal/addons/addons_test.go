package addons

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/naivecore"
)

// fakeSys is an in-memory stand-in for every system call sys.go makes,
// wired in by withFakeSys. opkg/init.d responses are scripted; file ops
// hit the `files` map.
type fakeSys struct {
	installed map[string]string // pkg -> version ("" absent from map = not installed)
	initOK    map[string]bool   // "S51nfqws2 status" -> ok?
	procMatch map[string]bool   // substring -> present
	ports     map[int]bool      // port -> listening
	files     map[string][]byte // path -> content
	opkgCalls []string          // recorded "install nfqws2-keenetic", "remove …", "update"
	initCalls []string          // recorded "S51nfqws2 start"
}

func newFakeSys() *fakeSys {
	return &fakeSys{
		installed: map[string]string{},
		initOK:    map[string]bool{},
		procMatch: map[string]bool{},
		ports:     map[int]bool{},
		files:     map[string][]byte{},
	}
}

func withFakeSys(t *testing.T, f *fakeSys) {
	t.Helper()
	save := struct {
		opkgRun        func(context.Context, ...string) (string, error)
		initdRun       func(context.Context, string, string) (string, error)
		processMatches func(context.Context, string) bool
		portListening  func(context.Context, int) bool
		readFile       func(string) ([]byte, error)
		writeFile      func(string, []byte, os.FileMode) error
		removeFile     func(string) error
	}{opkgRun, initdRun, processMatches, portListening, readFile, writeFile, removeFile}
	t.Cleanup(func() {
		opkgRun, initdRun, processMatches, portListening = save.opkgRun, save.initdRun, save.processMatches, save.portListening
		readFile, writeFile, removeFile = save.readFile, save.writeFile, save.removeFile
	})

	opkgRun = func(_ context.Context, args ...string) (string, error) {
		f.opkgCalls = append(f.opkgCalls, strings.Join(args, " "))
		switch {
		case len(args) >= 2 && args[0] == "list-installed":
			if v, ok := f.installed[args[1]]; ok {
				return args[1] + " - " + v + "\n", nil
			}
			return "", nil
		case len(args) >= 2 && args[0] == "install":
			for _, p := range args[1:] {
				if _, done := f.installed[p]; !done {
					f.installed[p] = "1.0-test"
				}
			}
			return "", nil
		case len(args) >= 2 && args[0] == "remove":
			for _, p := range args[1:] {
				delete(f.installed, p)
			}
			return "", nil
		}
		return "", nil
	}
	initdRun = func(_ context.Context, script, action string) (string, error) {
		f.initCalls = append(f.initCalls, script+" "+action)
		if action == "status" && !f.initOK[script+" status"] {
			return "", os.ErrProcessDone
		}
		return "", nil
	}
	processMatches = func(_ context.Context, p string) bool { return f.procMatch[p] }
	portListening = func(_ context.Context, p int) bool { return f.ports[p] }
	readFile = func(path string) ([]byte, error) {
		if b, ok := f.files[path]; ok {
			return b, nil
		}
		return nil, os.ErrNotExist
	}
	writeFile = func(path string, b []byte, _ os.FileMode) error {
		f.files[path] = append([]byte(nil), b...)
		return nil
	}
	removeFile = func(path string) error { delete(f.files, path); return nil }
}

func TestAll_OrderAndFind(t *testing.T) {
	got := All()
	if len(got) != 6 {
		t.Fatalf("All() len = %d, want 6", len(got))
	}
	// naive-core isn't in the fixed `order` list, so it sorts after the
	// ones that are -- there being only one such addon right now, that
	// just means last.
	want := []string{"unbound", "dnscrypt", "nfqws2", "conntrack", "cron", "naive-core"}
	for i, id := range want {
		if got[i].ID() != id {
			t.Errorf("All()[%d] = %q, want %q", i, got[i].ID(), id)
		}
	}
	if _, ok := Find("nfqws2"); !ok {
		t.Error("Find(nfqws2) not found")
	}
	if _, ok := Find("nope"); ok {
		t.Error("Find(nope) should not be found")
	}
}

func TestParseKV(t *testing.T) {
	kv, err := ParseKV([]string{"a=1", "b=x=y", "c="})
	if err != nil {
		t.Fatalf("ParseKV: %v", err)
	}
	if kv["a"] != "1" || kv["b"] != "x=y" || kv["c"] != "" {
		t.Errorf("kv = %#v", kv)
	}
	if _, err := ParseKV([]string{"noequals"}); err == nil {
		t.Error("expected an error for an argument without '='")
	}
}

func TestConntrack_Lifecycle(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("conntrack")

	if a.Detect(ctx).Installed {
		t.Fatal("conntrack should start not installed")
	}
	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !a.Detect(ctx).Installed {
		t.Error("conntrack should be installed after Install")
	}
	if err := a.Configure(ctx, map[string]string{"x": "1"}); err == nil {
		t.Error("conntrack Configure should reject any key")
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if a.Detect(ctx).Installed {
		t.Error("conntrack should be gone after Remove")
	}
}

// withFakeNaivecore swaps naiveEnsure/naiveVersion for fakes driven by a
// simple installed bool -- naive-core doesn't touch opkg/init.d, just
// internal/naivecore's Ensure/Version, so it needs its own tiny seam
// alongside withFakeSys rather than reusing fakeSys's fields.
func withFakeNaivecore(t *testing.T) *bool {
	t.Helper()
	saveEnsure, saveVersion := naiveEnsure, naiveVersion
	t.Cleanup(func() { naiveEnsure, naiveVersion = saveEnsure, saveVersion })

	installed := new(bool)
	naiveEnsure = func(ctx context.Context, opts naivecore.Options) (string, error) {
		if opts.Dest != naiveCoreBinary {
			t.Errorf("Install: Dest = %q, want %q", opts.Dest, naiveCoreBinary)
		}
		*installed = true
		return "vendored", nil
	}
	naiveVersion = func(bin string) (string, error) {
		if bin != naiveCoreBinary {
			t.Errorf("Detect/Status: binary = %q, want %q", bin, naiveCoreBinary)
		}
		if !*installed {
			return "", errors.New("exec: not found")
		}
		return "naive 150.0.7871.63", nil
	}
	return installed
}

func TestNaiveCore_Lifecycle(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	installed := withFakeNaivecore(t)
	ctx := context.Background()

	a, ok := Find("naive-core")
	if !ok {
		t.Fatal(`Find("naive-core") not found`)
	}

	if a.Detect(ctx).Installed {
		t.Fatal("naive-core should start not installed")
	}
	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if st := a.Detect(ctx); !st.Installed || st.Version != "naive 150.0.7871.63" {
		t.Errorf("Detect after Install = %+v", st)
	}
	if err := a.Configure(ctx, map[string]string{"x": "1"}); err == nil {
		t.Error("naive-core Configure should reject any key")
	}
	if s, err := a.Status(ctx); err != nil || !strings.Contains(s, "150.0.7871.63") {
		t.Errorf("Status = %q, %v", s, err)
	}

	*installed = false // Remove() doesn't reach into naiveVersion's fake state itself
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if a.Detect(ctx).Installed {
		t.Error("naive-core should be gone after Remove")
	}
}

func TestNaiveCore_RemoveIsIdempotent(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	withFakeNaivecore(t)
	removeFile = func(string) error { return os.ErrNotExist }

	a, _ := Find("naive-core")
	if err := a.Remove(context.Background()); err != nil {
		t.Errorf("Remove on an already-absent binary should not error, got %v", err)
	}
}

func TestNfqws2_InstallAddsFeedAndStarts(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("nfqws2")

	// A stale legacy feed file (wrong name/URL) from an old build.
	f.files[nfqwsLegacyFeedFile] = []byte("src/gz nfqws2 https://nfqws.github.io/nfqws2-keenetic/all\n")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	feed, ok := f.files[nfqwsFeedFile]
	if !ok || !strings.Contains(string(feed), nfqwsFeedURL) || !strings.Contains(string(feed), "src/gz nfqws2-keenetic ") {
		t.Errorf("feed file not written correctly: %q (want the src/gz nfqws2-keenetic line with %s)", feed, nfqwsFeedURL)
	}
	if _, ok := f.files[nfqwsLegacyFeedFile]; ok {
		t.Error("Install should delete the legacy feed file")
	}
	// opkg's non-SSL wget is swapped for wget-ssl before the https feed.
	if !contains(f.opkgCalls, "install ca-certificates wget-ssl") || !contains(f.opkgCalls, "remove wget-nossl") {
		t.Errorf("wget-ssl swap not done: %v", f.opkgCalls)
	}
	if !contains(f.opkgCalls, "install "+nfqwsPkg) {
		t.Errorf("opkg install not called: %v", f.opkgCalls)
	}
	if !contains(f.initCalls, nfqwsInit+" start") {
		t.Errorf("init start not called: %v", f.initCalls)
	}

	// Remove drops the package and both feed files.
	f.files[nfqwsLegacyFeedFile] = []byte("stale\n")
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := f.files[nfqwsFeedFile]; ok {
		t.Error("feed file should be removed on Remove")
	}
	if _, ok := f.files[nfqwsLegacyFeedFile]; ok {
		t.Error("legacy feed file should be removed on Remove")
	}
}

func TestNfqws2_Configure(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	f.installed[nfqwsPkg] = "2.0-test"
	f.files[nfqwsConf] = []byte("ISP_INTERFACE=\"\"\nTCP_PORTS=\"443\"\n")
	a, _ := Find("nfqws2")

	if err := a.Configure(ctx, map[string]string{"mode": "list", "tcp_ports": "443,80", "domain": "example.com"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	conf := string(f.files[nfqwsConf])
	if !strings.Contains(conf, `TCP_PORTS="443,80"`) {
		t.Errorf("TCP_PORTS not updated: %q", conf)
	}
	if !strings.Contains(conf, `NFQWS_EXTRA_ARGS="list"`) {
		t.Errorf("mode (NFQWS_EXTRA_ARGS) not appended: %q", conf)
	}
	if !strings.Contains(conf, `ISP_INTERFACE=""`) {
		t.Errorf("untouched key lost: %q", conf)
	}
	if got := string(f.files[nfqwsUserList]); !strings.Contains(got, "example.com") {
		t.Errorf("user.list not updated: %q", got)
	}
	if !contains(f.initCalls, nfqwsInit+" restart") {
		t.Errorf("restart not called: %v", f.initCalls)
	}

	// bad values
	if err := a.Configure(ctx, map[string]string{"mode": "bogus"}); err == nil {
		t.Error("mode=bogus should fail")
	}
	if err := a.Configure(ctx, map[string]string{"tcp_ports": "99999"}); err == nil {
		t.Error("tcp_ports=99999 should fail")
	}
	if err := a.Configure(ctx, map[string]string{"nope": "1"}); err == nil {
		t.Error("unknown key should fail")
	}
}

func TestUnbound_InstallWritesConfAndStarts(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("unbound")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	conf := string(f.files[unboundConf])
	if !strings.Contains(conf, "port: 5335") || !strings.Contains(conf, "interface: 127.0.0.1") {
		t.Errorf("unbound.conf not sane: %q", conf)
	}
	// Entware-daemon essentials -- without these S61unbound can't track it
	// and the stock conf's chroot/username assumptions bite.
	for _, want := range []string{`username: ""`, `chroot: ""`, "pidfile:", "use-syslog: yes"} {
		if !strings.Contains(conf, want) {
			t.Errorf("unbound.conf missing %q:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "port: 53\n") || strings.Contains(conf, "port: 5353") {
		t.Errorf("must not use :53 (dns-proxy) or :5353 (mDNS): %q", conf)
	}
	if strings.Contains(conf, unboundRtrMark) {
		t.Errorf("fresh install should be local mode, not router: %q", conf)
	}
	if !contains(f.initCalls, unboundInit+" start") {
		t.Errorf("unbound start not called: %v", f.initCalls)
	}

	// Configure: disable dnssec, bump cache.
	if err := a.Configure(ctx, map[string]string{"dnssec": "off", "cache": "16"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	conf = string(f.files[unboundConf])
	if !strings.Contains(conf, "val-permissive-mode: yes") {
		t.Errorf("dnssec not disabled: %q", conf)
	}
	if !strings.Contains(conf, "msg-cache-size: 16777216") {
		t.Errorf("cache size not 16MB: %q", conf)
	}
	if u := unboundRead(ctx); u.dnssec || u.cacheMB != 16 || u.routerMode {
		t.Errorf("unboundRead = %+v, want dnssec off, cache 16, local", u)
	}

	if err := a.Configure(ctx, map[string]string{"cache": "999"}); err == nil {
		t.Error("cache=999 should fail")
	}
	if err := a.Configure(ctx, map[string]string{"nope": "1"}); err == nil {
		t.Error("unknown key should fail")
	}
}

// withUnboundKeeneticSeam fakes the internal/keenetic calls unbound's
// router-dns mode makes. `nameservers` records the ip:port entries
// currently added.
func withUnboundKeeneticSeam(t *testing.T, available bool, lanIP string, nameservers map[string]bool) {
	t.Helper()
	oa, os, ol, oi := keeneticAvailable, setLocalNameServer, localNameServerActive, keeneticLANIP
	keeneticAvailable = func() bool { return available }
	setLocalNameServer = func(_ context.Context, ip string, port int, on bool) error {
		k := fmt.Sprintf("%s:%d", ip, port)
		if on {
			nameservers[k] = true
		} else {
			delete(nameservers, k)
		}
		return nil
	}
	localNameServerActive = func(_ context.Context, ip string, port int) (bool, error) {
		return nameservers[fmt.Sprintf("%s:%d", ip, port)], nil
	}
	keeneticLANIP = func(_ context.Context, _ string) (string, error) { return lanIP, nil }
	t.Cleanup(func() {
		keeneticAvailable, setLocalNameServer, localNameServerActive, keeneticLANIP = oa, os, ol, oi
	})
}

func TestUnbound_RouterDNSOnOffAndRemoveReverts(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ns := map[string]bool{}
	withUnboundKeeneticSeam(t, true, "192.168.1.1", ns)
	ctx := context.Background()
	a, _ := Find("unbound")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// router-dns=on: conf binds the LAN IP + marker, name-server added.
	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err != nil {
		t.Fatalf("router-dns=on: %v", err)
	}
	conf := string(f.files[unboundConf])
	if !strings.Contains(conf, unboundRtrMark) || !strings.Contains(conf, "interface: 192.168.1.1") {
		t.Errorf("conf not in router mode: %q", conf)
	}
	if !ns["192.168.1.1:5335"] {
		t.Errorf("ip name-server 192.168.1.1:5335 should be added; have %v", ns)
	}
	if u := unboundRead(ctx); !u.routerMode || u.routerIP != "192.168.1.1" {
		t.Errorf("unboundRead = %+v, want routerMode, routerIP 192.168.1.1", u)
	}

	// router-dns=off: name-server removed, marker gone.
	if err := a.Configure(ctx, map[string]string{"router-dns": "off"}); err != nil {
		t.Fatalf("router-dns=off: %v", err)
	}
	if ns["192.168.1.1:5335"] {
		t.Errorf("name-server should be removed after off; have %v", ns)
	}
	if strings.Contains(string(f.files[unboundConf]), unboundRtrMark) {
		t.Errorf("conf still router mode after off")
	}

	// Remove while in router mode reverts the name-server first.
	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err != nil {
		t.Fatal(err)
	}
	if !ns["192.168.1.1:5335"] {
		t.Fatal("precondition: name-server should be set")
	}
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if ns["192.168.1.1:5335"] {
		t.Error("Remove must drop the ip name-server entry")
	}
	if _, still := f.installed[unboundPkg]; still {
		t.Error("unbound-daemon should be removed")
	}
}

func TestUnbound_RouterDNSRequiresKeenetic(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ns := map[string]bool{}
	withUnboundKeeneticSeam(t, false, "", ns) // no ndmc
	ctx := context.Background()
	a, _ := Find("unbound")
	f.installed[unboundPkg] = "1.19-test"
	f.files[unboundConf] = []byte(unboundConfBody(8, true, false, ""))

	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err == nil {
		t.Error("router-dns=on should fail without a Keenetic")
	}
	if len(ns) != 0 {
		t.Errorf("no name-server should be touched without Keenetic: %v", ns)
	}
}

// Regression: a stock unbound package conf carries `interface: ::0`.
// That must NOT be mistaken for the router's LAN IP (the bug that sent
// `ip name-server ::0:5353` to ndmc).
func TestUnbound_StockConfInterfaceNotTreatedAsRouterIP(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ns := map[string]bool{}
	withUnboundKeeneticSeam(t, true, "192.168.1.1", ns)
	ctx := context.Background()
	a, _ := Find("unbound")

	// Simulate the stock package conf already on disk (no managed marker,
	// listens on ::0).
	f.installed[unboundPkg] = "1.19-test"
	f.files[unboundConf] = []byte("server:\n    interface: ::0\n    port: 53\n")

	// Install must replace it with ours.
	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !strings.Contains(string(f.files[unboundConf]), unboundManagedMark) {
		t.Fatalf("Install left the stock conf in place: %q", f.files[unboundConf])
	}
	if u := unboundRead(ctx); u.routerIP != "" {
		t.Errorf("routerIP = %q, want empty (::0 must not be read as the LAN IP)", u.routerIP)
	}

	// router-dns=on must resolve via ndmc (192.168.1.1), never ::0.
	if err := a.Configure(ctx, map[string]string{"router-dns": "on"}); err != nil {
		t.Fatalf("router-dns=on: %v", err)
	}
	if !ns["192.168.1.1:5335"] {
		t.Errorf("want ip name-server 192.168.1.1:5335; have %v", ns)
	}
	for k := range ns {
		if strings.HasPrefix(k, "::") {
			t.Errorf("an IPv6-any name-server slipped through: %q", k)
		}
	}
}

// Recovery: a conf stuck in router mode with a junk interface line (the
// bad state the bug produced) can still be switched back to local.
func TestUnbound_RouterDNSOffRecoversFromJunkIP(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ns := map[string]bool{}
	withUnboundKeeneticSeam(t, true, "192.168.1.1", ns)
	ctx := context.Background()
	a, _ := Find("unbound")
	f.installed[unboundPkg] = "1.19-test"
	f.files[unboundConf] = []byte("# " + unboundManagedMark + "\n" + unboundRtrMark + "\nserver:\n    interface: ::0\n    port: 5335\n")

	if err := a.Configure(ctx, map[string]string{"router-dns": "off"}); err != nil {
		t.Fatalf("router-dns=off from junk state: %v", err)
	}
	if strings.Contains(string(f.files[unboundConf]), unboundRtrMark) {
		t.Errorf("conf still in router mode: %q", f.files[unboundConf])
	}
}

func TestPrivateV4(t *testing.T) {
	for _, s := range []string{"192.168.1.1", "10.0.0.1", "172.16.5.4"} {
		if !privateV4(s) {
			t.Errorf("privateV4(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"::0", "::", "0.0.0.0", "8.8.8.8", "127.0.0.1", "", "not-an-ip", "192.168.1.1:5335"} {
		if privateV4(s) {
			t.Errorf("privateV4(%q) = true, want false", s)
		}
	}
}

func TestShellConfSet(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	f.files["/c"] = []byte("# comment\nA=\"1\"\nB=2\n")
	if err := shellConfSet("/c", map[string]string{"A": "9", "C": "new"}); err != nil {
		t.Fatalf("shellConfSet: %v", err)
	}
	got := string(f.files["/c"])
	if !strings.Contains(got, `A="9"`) || strings.Contains(got, `A="1"`) {
		t.Errorf("A not replaced: %q", got)
	}
	if !strings.Contains(got, "B=2") || !strings.Contains(got, "# comment") {
		t.Errorf("other lines not preserved: %q", got)
	}
	if !strings.Contains(got, `C="new"`) {
		t.Errorf("missing key not appended: %q", got)
	}
}

func TestNfqwsAddDomain_Dedupe(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	if err := nfqwsAddDomain("Example.com"); err != nil {
		t.Fatal(err)
	}
	if err := nfqwsAddDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	got := string(f.files[nfqwsUserList])
	if strings.Count(got, "example.com") != 1 {
		t.Errorf("expected one entry, got %q", got)
	}
	if err := nfqwsAddDomain("http://x.com/y"); err == nil {
		t.Error("a URL should be rejected")
	}
}

func TestOpkgInstalledVersion(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	f.installed["foo"] = "1.2.3"
	if v := opkgInstalledVersion(context.Background(), "foo"); v != "1.2.3" {
		t.Errorf("version = %q, want 1.2.3", v)
	}
	if v := opkgInstalledVersion(context.Background(), "bar"); v != "" {
		t.Errorf("version = %q, want empty", v)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
