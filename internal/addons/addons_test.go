package addons

import (
	"context"
	"os"
	"strings"
	"testing"
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
	if len(got) != 4 {
		t.Fatalf("All() len = %d, want 4", len(got))
	}
	want := []string{"unbound", "nfqws2", "conntrack", "cron"}
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

func TestNfqws2_InstallAddsFeedAndStarts(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	ctx := context.Background()
	a, _ := Find("nfqws2")

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	feed, ok := f.files[nfqwsFeedFile]
	if !ok || !strings.Contains(string(feed), nfqwsFeedURL()) || !strings.Contains(string(feed), "src/gz nfqws2-keenetic ") {
		t.Errorf("feed file not written correctly: %q (want the src/gz nfqws2-keenetic line with %s)", feed, nfqwsFeedURL())
	}
	if !contains(f.opkgCalls, "install "+nfqwsPkg) {
		t.Errorf("opkg install not called: %v", f.opkgCalls)
	}
	if !contains(f.initCalls, nfqwsInit+" start") {
		t.Errorf("init start not called: %v", f.initCalls)
	}

	// Remove drops the package and the feed file.
	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := f.files[nfqwsFeedFile]; ok {
		t.Error("feed file should be removed on Remove")
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
	if !strings.Contains(conf, "port: 5353") || !strings.Contains(conf, "interface: 127.0.0.1") {
		t.Errorf("unbound.conf not sane: %q", conf)
	}
	if !contains(f.initCalls, unboundInit+" start") {
		t.Errorf("unbound start not called: %v", f.initCalls)
	}

	// Configure changes port + disables dnssec.
	if err := a.Configure(ctx, map[string]string{"port": "5300", "dnssec": "off", "cache": "16"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	conf = string(f.files[unboundConf])
	if !strings.Contains(conf, "port: 5300") {
		t.Errorf("port not changed: %q", conf)
	}
	if !strings.Contains(conf, "val-permissive-mode: yes") {
		t.Errorf("dnssec not disabled: %q", conf)
	}
	if !strings.Contains(conf, "msg-cache-size: 16777216") {
		t.Errorf("cache size not 16MB: %q", conf)
	}
	if unboundConfiguredPort(ctx) != 5300 {
		t.Errorf("unboundConfiguredPort = %d, want 5300", unboundConfiguredPort(ctx))
	}

	if err := a.Configure(ctx, map[string]string{"port": "0"}); err == nil {
		t.Error("port=0 should fail")
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
