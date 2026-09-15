package l7capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// installFakeKmodEnv swaps insmodRun/unameRelease/statFile for
// in-memory fakes and returns a handle to inspect what got called --
// same "fake exec layer via the package's own injectable vars" approach
// this package's own rules_test.go already uses.
type fakeKmodEnv struct {
	insmodCalls []string
	insmodErr   error
	release     string
	releaseErr  error
	statErr     error
}

func installFakeKmodEnv(t *testing.T, env *fakeKmodEnv) {
	t.Helper()
	origInsmod, origUname, origStat := insmodRun, unameRelease, statFile
	insmodRun = func(_ context.Context, path string) error {
		env.insmodCalls = append(env.insmodCalls, path)
		return env.insmodErr
	}
	unameRelease = func(context.Context) (string, error) {
		return env.release, env.releaseErr
	}
	statFile = func(string) error {
		return env.statErr
	}
	t.Cleanup(func() { insmodRun, unameRelease, statFile = origInsmod, origUname, origStat })
}

func writeProcModules(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "modules")
	body := ""
	for _, l := range lines {
		body += l + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestEnsureNFLOGModule_SkipsAlreadyLoaded(t *testing.T) {
	procModules := writeProcModules(t,
		"nfnetlink_log 12288 0 - Live 0x00000000",
		"xt_NFLOG 4096 1 - Live 0x00000000",
		"xt_connbytes 4096 1 - Live 0x00000000",
		"xt_length 4096 1 - Live 0x00000000",
	)
	env := &fakeKmodEnv{}
	installFakeKmodEnv(t, env)

	if err := ensureNFLOGModule(context.Background(), procModules); err != nil {
		t.Fatalf("ensureNFLOGModule: %v", err)
	}
	if len(env.insmodCalls) != 0 {
		t.Errorf("insmod called %v, want no calls -- both modules already loaded", env.insmodCalls)
	}
}

func TestEnsureNFLOGModule_LoadsWhenPresentOnDisk(t *testing.T) {
	procModules := writeProcModules(t, "some_other_module 100 0 - Live 0x0")
	env := &fakeKmodEnv{release: "5.15.0-keenetic"}
	installFakeKmodEnv(t, env)

	if err := ensureNFLOGModule(context.Background(), procModules); err != nil {
		t.Fatalf("ensureNFLOGModule: %v", err)
	}
	want := []string{
		"/lib/modules/5.15.0-keenetic/nfnetlink_log.ko",
		"/lib/modules/5.15.0-keenetic/xt_NFLOG.ko",
		"/lib/modules/5.15.0-keenetic/xt_connbytes.ko",
		"/lib/modules/5.15.0-keenetic/xt_length.ko",
	}
	if len(env.insmodCalls) != len(want) {
		t.Fatalf("insmod called %v, want %v", env.insmodCalls, want)
	}
	for i, w := range want {
		if env.insmodCalls[i] != w {
			t.Errorf("insmod call %d = %q, want %q", i, env.insmodCalls[i], w)
		}
	}
}

func TestEnsureNFLOGModule_SkipsWhenNoFileOnDisk(t *testing.T) {
	procModules := writeProcModules(t)
	env := &fakeKmodEnv{release: "5.15.0-keenetic", statErr: fmt.Errorf("no such file")}
	installFakeKmodEnv(t, env)

	if err := ensureNFLOGModule(context.Background(), procModules); err != nil {
		t.Fatalf("ensureNFLOGModule: want nil (no .ko on this kernel is not an error), got %v", err)
	}
	if len(env.insmodCalls) != 0 {
		t.Errorf("insmod called %v, want no calls -- no .ko file present", env.insmodCalls)
	}
}

func TestEnsureNFLOGModule_SurfacesGenuineInsmodFailure(t *testing.T) {
	procModules := writeProcModules(t)
	env := &fakeKmodEnv{release: "5.15.0-keenetic", insmodErr: fmt.Errorf("invalid module format")}
	installFakeKmodEnv(t, env)

	err := ensureNFLOGModule(context.Background(), procModules)
	if err == nil {
		t.Fatal("ensureNFLOGModule: want an error when insmod genuinely fails")
	}
}

func TestEnsureNFLOGModule_SurfacesKernelReleaseFailure(t *testing.T) {
	procModules := writeProcModules(t)
	env := &fakeKmodEnv{releaseErr: fmt.Errorf("uname not found")}
	installFakeKmodEnv(t, env)

	if err := ensureNFLOGModule(context.Background(), procModules); err == nil {
		t.Fatal("ensureNFLOGModule: want an error when the kernel release can't be determined")
	}
}

func TestKmodLoaded(t *testing.T) {
	procModules := writeProcModules(t,
		"xt_NFLOG 4096 1 - Live 0x00000000",
		"nf_conntrack 143360 5 xt_NFLOG,nf_nat, - Live 0x0000000",
	)
	if !kmodLoaded("xt_NFLOG", procModules) {
		t.Error("kmodLoaded(xt_NFLOG): want true")
	}
	if kmodLoaded("xt_NFLO", procModules) {
		t.Error("kmodLoaded(xt_NFLO): want false -- must match the whole module name, not a prefix")
	}
	if kmodLoaded("nfnetlink_log", procModules) {
		t.Error("kmodLoaded(nfnetlink_log): want false -- not in the fixture")
	}
}

func TestKmodLoaded_MissingFile(t *testing.T) {
	if kmodLoaded("xt_NFLOG", filepath.Join(t.TempDir(), "missing")) {
		t.Error("kmodLoaded on a missing /proc/modules: want false, not a panic")
	}
}
