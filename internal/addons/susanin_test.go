package addons

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/susanincore"
)

// withFakeSusanincore swaps susaninEnsure/susaninVersion/runScript for
// fakes driven by a simple installed bool plus a recorded call log --
// susanin's lifecycle is upstream's own install.sh/susanin.sh/uninstall.sh
// (invoked via runScript), not opkg/init.d, so it needs its own tiny seam
// alongside withFakeSys, same reasoning as withFakeNaivecore.
func withFakeSusanincore(t *testing.T) (installed *bool, calls *[]string) {
	t.Helper()
	saveEnsure, saveVersion, saveRun, saveRunEnv := susaninEnsure, susaninVersion, runScript, runScriptEnv
	t.Cleanup(func() {
		susaninEnsure, susaninVersion, runScript, runScriptEnv = saveEnsure, saveVersion, saveRun, saveRunEnv
	})

	installed = new(bool)
	var log []string
	calls = &log

	susaninEnsure = func(ctx context.Context, opts susanincore.Options) (string, error) {
		return t.TempDir(), nil // Install only needs *a* path to hand to runScript
	}
	susaninVersion = func(bin string) (string, error) {
		if bin != susaninBin {
			t.Errorf("Detect/Status/Remove: binary = %q, want %q", bin, susaninBin)
		}
		if !*installed {
			return "", errors.New("exec: not found")
		}
		return "0.3.6", nil
	}
	runScript = func(ctx context.Context, path string, args ...string) (string, error) {
		*calls = append(*calls, strings.TrimSpace(path+" "+strings.Join(args, " ")))
		// "uninstall.sh" itself ends with "install.sh", so this must be
		// an exact basename match, not a suffix check.
		switch filepath.Base(path) {
		case "install.sh":
			*installed = true
			// The real install.sh writes susanin.conf from its own
			// config.example.conf template (see docs/HANDOFF-susanin.md);
			// mirror that here so shellConfSet (called by susaninApply,
			// including Install's own best-effort auto-configure) has a
			// file to edit, same as production has by the time this runs
			// for real. Only if a test hasn't already seeded one itself.
			if _, err := readFile(susaninConf); err != nil {
				_ = writeFile(susaninConf, []byte("egress_interface=\nlan_interfaces=\n"), 0o644)
			}
		case "uninstall.sh":
			*installed = false
		}
		return "", nil
	}
	runScriptEnv = func(ctx context.Context, path string, extraEnv []string, args ...string) (string, error) {
		return runScript(ctx, path, args...)
	}
	return installed, calls
}

// withFakeWGTransport swaps activeWGIface/interfaceOSName so resolveEgress
// can be exercised without a real Keenetic. ndmName == "" simulates
// WG-transport never having been enabled (the common case on a fresh
// router); non-empty simulates it already being active.
func withFakeWGTransport(t *testing.T, ndmName, osName string) {
	t.Helper()
	saveActive, saveOSName := activeWGIface, interfaceOSName
	t.Cleanup(func() { activeWGIface, interfaceOSName = saveActive, saveOSName })

	activeWGIface = func(ctx context.Context) (string, error) {
		if ndmName == "" {
			return "", nil
		}
		return ndmName, nil
	}
	interfaceOSName = func(ctx context.Context, iface string) (string, error) {
		if iface != ndmName {
			t.Errorf("interfaceOSName called with %q, want %q", iface, ndmName)
		}
		return osName, nil
	}
}

func TestSusanin_Install_AutoConfiguresWhenWGTransportActive(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	_, calls := withFakeSusanincore(t)
	withFakeWGTransport(t, "Wireguard4", "nwg0")

	a, _ := Find("susanin")
	if err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}

	conf := string(f.files[susaninConf])
	if !strings.Contains(conf, `egress_interface="nwg0"`) {
		t.Errorf("conf missing auto-resolved egress_interface: %s", conf)
	}
	var sawInstall, sawRestart bool
	for _, c := range *calls {
		if strings.Contains(c, "susanin.sh install") {
			sawInstall = true
		}
		if strings.Contains(c, "susanin.sh restart") {
			sawRestart = true
		}
	}
	if !sawInstall || !sawRestart {
		t.Errorf("expected susanin.sh install and restart after auto-configure, calls = %v", *calls)
	}
	if st := a.Detect(context.Background()); !strings.Contains(st.Detail, "nwg0") {
		t.Errorf("Detect.Detail = %q, want it to show the auto-resolved egress", st.Detail)
	}
}

func TestSusanin_Configure_EgressAuto(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	_, calls := withFakeSusanincore(t)
	withFakeWGTransport(t, "Wireguard3", "nwg0")
	f.files[susaninConf] = []byte("egress_interface=\nlan_interfaces=\n")

	a, _ := Find("susanin")
	if err := a.Configure(context.Background(), map[string]string{"egress": "auto"}); err != nil {
		t.Fatalf("Configure(egress=auto): %v", err)
	}
	if got := susaninConfValue("egress_interface"); got != "nwg0" {
		t.Errorf("egress_interface = %q, want the auto-resolved nwg0", got)
	}
	found := false
	for _, c := range *calls {
		if strings.Contains(c, "susanin.sh install") {
			found = true
		}
	}
	if !found {
		t.Errorf("egress=auto should still bring the data plane up, calls = %v", *calls)
	}
}

func TestSusanin_Configure_EgressAuto_FailsWhenUnresolvable(t *testing.T) {
	withFakeSys(t, newFakeSys())
	withFakeSusanincore(t)
	withFakeWGTransport(t, "", "") // WG-transport not active

	a, _ := Find("susanin")
	if err := a.Configure(context.Background(), map[string]string{"egress": "auto"}); err == nil {
		t.Error("egress=auto should fail clearly when nothing resolves, not silently do nothing")
	}
}

func TestSusanin_Configure_AcceptsNDMStyleEgress(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	withFakeSusanincore(t)
	f.files[susaninConf] = []byte("egress_interface=\n")

	// A prior version rejected any egress value shaped like an NDM name
	// (PascalCase, e.g. "Wireguard3"), on the assumption the OS-level
	// kernel device name always differs from it -- confirmed wrong on real
	// hardware (see the Configure comment above this case). A manual value
	// must be accepted verbatim; only susanin.sh's own bring-up can judge
	// whether it actually resolves to a usable device.
	a, _ := Find("susanin")
	if err := a.Configure(context.Background(), map[string]string{"egress": "Wireguard3"}); err != nil {
		t.Fatalf("Configure(egress=Wireguard3): %v", err)
	}
	if got := susaninConfValue("egress_interface"); got != "Wireguard3" {
		t.Errorf("egress_interface = %q, want Wireguard3", got)
	}
}

func TestSusanin_Configure_SetsEgressEnvForDatapath(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	withFakeSusanincore(t)
	f.files[susaninConf] = []byte("egress_interface=\n")

	// The actual live bug: upstream's tools/susanin.sh `install` case runs
	// `sh "$TOOLS/datapath.sh" up; "$BIN" setup` -- two commands, and only
	// the *second* (backend.c's set_env, via the agent binary) exports
	// SUSANIN_EGRESS/SUSANIN_LAN from the loaded config. The first, bare
	// `datapath.sh up` call sees neither and silently falls back to
	// datapath.sh's own hardcoded default (egress "nwg0"). Under
	// susanin.sh's own `set -eu`, if that first call fails -- which it did
	// live, because the configured egress wasn't nwg0 and nwg0 itself
	// wasn't up -- susanin.sh aborts before ever reaching the second
	// command that would have gotten it right. A shell child inherits its
	// parent's environment, so setting these in *our* runScriptEnv call
	// fixes it without patching upstream's script.
	var gotEnv []string
	orig := runScriptEnv
	runScriptEnv = func(ctx context.Context, path string, extraEnv []string, args ...string) (string, error) {
		if filepath.Base(path) == "susanin.sh" && len(args) > 0 && args[0] == "install" {
			gotEnv = extraEnv
		}
		return orig(ctx, path, extraEnv, args...)
	}
	t.Cleanup(func() { runScriptEnv = orig })

	a, _ := Find("susanin")
	if err := a.Configure(context.Background(), map[string]string{"egress": "nwg3", "lan": "br0,br1"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	wantEgress, wantLan := false, false
	for _, e := range gotEnv {
		if e == "SUSANIN_EGRESS=nwg3" {
			wantEgress = true
		}
		if e == "SUSANIN_LAN=br0,br1" {
			wantLan = true
		}
	}
	if !wantEgress || !wantLan {
		t.Errorf("susanin.sh install env = %v, want SUSANIN_EGRESS=nwg3 and SUSANIN_LAN=br0,br1", gotEnv)
	}
}

func TestSusanin_Install_LeavesUnconfiguredWhenWGTransportInactive(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	_, calls := withFakeSusanincore(t)
	withFakeWGTransport(t, "", "") // no marked interface -- WG-transport never enabled

	a, _ := Find("susanin")
	if err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	// install.sh's own config.example.conf template exists either way
	// (see withFakeSusanincore) -- what must NOT have happened is
	// anything trying to *use* it (susaninApply, and by extension
	// susanin.sh) when there's no egress to point it at yet.
	if got := susaninConfValue("egress_interface"); got != "" {
		t.Errorf("egress_interface = %q, want empty -- auto-configure must not have run", got)
	}
	for _, c := range *calls {
		if strings.Contains(c, "susanin.sh") {
			t.Errorf("no susanin.sh call expected when WG-transport isn't active, got %v", *calls)
		}
	}
	if st := a.Detect(context.Background()); !strings.Contains(st.Detail, "не настроен") {
		t.Errorf("Detect.Detail = %q, want the manual-configure fallback message", st.Detail)
	}
}

func TestEnsureSusaninRunning_NotInstalled(t *testing.T) {
	withFakeSys(t, newFakeSys())
	_, calls := withFakeSusanincore(t) // installed=false by default

	acted, err := EnsureSusaninRunning(context.Background())
	if err != nil || acted {
		t.Fatalf("EnsureSusaninRunning = (%v, %v), want (false, nil) when never installed", acted, err)
	}
	if len(*calls) != 0 {
		t.Errorf("should not shell out when never installed, calls = %v", *calls)
	}
}

func TestEnsureSusaninRunning_NotConfigured(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	installed, calls := withFakeSusanincore(t)
	*installed = true
	f.files[susaninConf] = []byte("egress_interface=\n")

	acted, err := EnsureSusaninRunning(context.Background())
	if err != nil || acted {
		t.Fatalf("EnsureSusaninRunning = (%v, %v), want (false, nil) when never configured", acted, err)
	}
	if len(*calls) != 0 {
		t.Errorf("should not shell out when never configured, calls = %v", *calls)
	}
}

func TestEnsureSusaninRunning_AlreadyRunning(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	installed, calls := withFakeSusanincore(t)
	*installed = true
	f.files[susaninConf] = []byte("egress_interface=nwg3\n")
	f.procMatch["susanin-agent"] = true

	acted, err := EnsureSusaninRunning(context.Background())
	if err != nil || acted {
		t.Fatalf("EnsureSusaninRunning = (%v, %v), want (false, nil) when already running", acted, err)
	}
	if len(*calls) != 0 {
		t.Errorf("should not shell out when already running, calls = %v", *calls)
	}
}

func TestEnsureSusaninRunning_StartsWhenStopped(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	installed, calls := withFakeSusanincore(t)
	*installed = true
	f.files[susaninConf] = []byte("egress_interface=nwg3\nlan_interfaces=br0\n")
	f.procMatch["susanin-agent"] = false

	acted, err := EnsureSusaninRunning(context.Background())
	if err != nil {
		t.Fatalf("EnsureSusaninRunning: %v", err)
	}
	if !acted {
		t.Fatal("EnsureSusaninRunning should report acted=true when it had to start the daemon")
	}
	found := false
	for _, c := range *calls {
		if strings.Contains(c, "susanin.sh") && strings.Contains(c, "start") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a susanin.sh start call, got %v", *calls)
	}
}

func TestSusanin_Lifecycle(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	installed, calls := withFakeSusanincore(t)
	ctx := context.Background()

	a, ok := Find("susanin")
	if !ok {
		t.Fatal(`Find("susanin") not found`)
	}

	if a.Detect(ctx).Installed {
		t.Fatal("susanin should start not installed")
	}

	if err := a.Install(ctx); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !*installed {
		t.Fatal("Install should have run install.sh")
	}
	if len(*calls) != 1 {
		t.Fatalf("calls after Install = %v, want exactly one (install.sh)", *calls)
	}
	// Upstream's install.sh parses args as a plain `case "$1" in --prefix)
	// PREFIX="$2"; shift ;; ...` -- it has no GNU-style --flag=value
	// support, so "--prefix=X" as one combined arg hits its `*) die
	// "unknown arg"` fallback. Must be passed as two separate args.
	installCall := (*calls)[0]
	for _, want := range []string{"install.sh", "--yes", "--no-start", "--prefix " + susaninPrefix} {
		if !strings.Contains(installCall, want) {
			t.Errorf("install.sh call = %q, missing %q", installCall, want)
		}
	}
	if strings.Contains(installCall, "--prefix=") {
		t.Errorf("install.sh call = %q, upstream doesn't understand --prefix=X (space-separated only)", installCall)
	}

	st := a.Detect(ctx)
	if !st.Installed || st.Version != "0.3.6" {
		t.Fatalf("Detect after Install = %+v", st)
	}
	if !strings.Contains(st.Detail, "не настроен") {
		t.Errorf("Detail should flag the missing egress before Configure: %q", st.Detail)
	}

	// Not configured yet -> Status says so without shelling out to susanin.sh.
	if s, err := a.Status(ctx); err != nil || !strings.Contains(s, "не настроен") {
		t.Errorf("Status before configure = %q, %v", s, err)
	}
	if len(*calls) != 1 {
		t.Errorf("Status before configure should not call any script, got %v", *calls)
	}

	// In production, install.sh writes susanin.conf from its own
	// config.example.conf template (confirmed by reading install.sh --
	// see docs/HANDOFF-susanin.md); the fake runScript above doesn't
	// simulate that file-writing side effect, so seed it directly here,
	// same as TestNfqws2_Configure pre-seeds nfqwsConf rather than faking
	// opkg's postinst writing it.
	f.files[susaninConf] = []byte("egress_interface=\nlan_interfaces=\nhealth_probe=\"1.1.1.1,8.8.8.8\"\n")

	if err := a.Configure(ctx, map[string]string{"egress": "wireguard4", "lan": "br0,br1"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	conf := string(f.files[susaninConf])
	if !strings.Contains(conf, `egress_interface="wireguard4"`) {
		t.Errorf("conf missing egress_interface: %s", conf)
	}
	if !strings.Contains(conf, `lan_interfaces="br0,br1"`) {
		t.Errorf("conf missing lan_interfaces: %s", conf)
	}
	// Configure must bring up the data plane (susanin.sh install ->
	// datapath.sh up + $BIN setup), not just the daemon process -- restart
	// alone leaves the iptables chain/ip rules/ipsets never created.
	installCall, restartCall := (*calls)[len(*calls)-2], (*calls)[len(*calls)-1]
	if !strings.Contains(installCall, "susanin.sh") || !strings.Contains(installCall, "install") {
		t.Errorf("Configure should run susanin.sh install before restart, got %q", installCall)
	}
	if !strings.Contains(restartCall, "susanin.sh") || !strings.Contains(restartCall, "restart") {
		t.Errorf("Configure should end with a susanin.sh restart, last call = %q", restartCall)
	}

	if got := a.Detect(ctx).Detail; !strings.Contains(got, "wireguard4") {
		t.Errorf("Detail after configure = %q, want it to name the egress", got)
	}

	if err := a.Configure(ctx, map[string]string{"nope": "1"}); err == nil {
		t.Error("unknown key should fail")
	}
	if err := a.Configure(ctx, map[string]string{"egress": ""}); err == nil {
		t.Error("empty egress should fail")
	}
	if err := a.Configure(ctx, map[string]string{}); err == nil {
		t.Error("Configure with no keys should fail")
	}

	if err := a.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	// Remove must plant the S94susanin placeholder before calling
	// uninstall.sh -- upstream's script aborts under set -e if that file
	// is missing, before it ever reaches its own file-removal step.
	if _, ok := f.files[susaninInitd]; !ok {
		t.Error("Remove should touch susaninInitd before running uninstall.sh")
	}
	if *installed {
		t.Error("Remove should have flipped installed back to false")
	}
	if a.Detect(ctx).Installed {
		t.Error("susanin should be gone after Remove")
	}
	last := (*calls)[len(*calls)-1]
	if !strings.Contains(last, "uninstall.sh") {
		t.Errorf("Remove should have run uninstall.sh, last call = %q", last)
	}
}

func TestSusanin_RemoveIsIdempotentWhenNeverInstalled(t *testing.T) {
	f := newFakeSys()
	withFakeSys(t, f)
	_, calls := withFakeSusanincore(t)

	a, _ := Find("susanin")
	if err := a.Remove(context.Background()); err != nil {
		t.Errorf("Remove on a never-installed susanin should not error, got %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("Remove on a never-installed susanin should not shell out, got %v", *calls)
	}
}

func TestSusanin_InstallPropagatesEnsureFailure(t *testing.T) {
	withFakeSys(t, newFakeSys())
	saveEnsure := susaninEnsure
	t.Cleanup(func() { susaninEnsure = saveEnsure })
	susaninEnsure = func(context.Context, susanincore.Options) (string, error) {
		return "", errors.New("checksum mismatch")
	}

	a, _ := Find("susanin")
	if err := a.Install(context.Background()); err == nil {
		t.Error("Install should propagate a failed Ensure")
	}
}

func TestSusanin_InstallCleansUpExtractedDir(t *testing.T) {
	withFakeSys(t, newFakeSys())
	saveEnsure, saveRun := susaninEnsure, runScript
	t.Cleanup(func() { susaninEnsure, runScript = saveEnsure, saveRun })

	dir := t.TempDir()
	marker := dir + "/susanin-agent"
	if err := os.WriteFile(marker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	susaninEnsure = func(context.Context, susanincore.Options) (string, error) { return dir, nil }
	runScript = func(context.Context, string, ...string) (string, error) { return "", nil }

	a, _ := Find("susanin")
	if err := a.Install(context.Background()); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("Install should remove the extracted staging dir, %s still exists", dir)
	}
}
