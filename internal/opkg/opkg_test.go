package opkg

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// fakeOpkg records the commands and answers each `opkg <verb>` from a table.
type fakeOpkg struct {
	calls   [][]string
	answers map[string]struct {
		out string
		err error
	}
}

func installFake(t *testing.T) *fakeOpkg {
	t.Helper()
	f := &fakeOpkg{answers: map[string]struct {
		out string
		err error
	}{}}
	orig := run
	run = func(_ context.Context, args ...string) ([]byte, error) {
		f.calls = append(f.calls, append([]string(nil), args...))
		a := f.answers[args[0]]
		return []byte(a.out), a.err
	}
	t.Cleanup(func() { run = orig })
	return f
}

func (f *fakeOpkg) answer(verb, out string, err error) {
	f.answers[verb] = struct {
		out string
		err error
	}{out, err}
}

func TestInstall_UpdatesThenInstalls(t *testing.T) {
	f := installFake(t)
	if err := Install(context.Background(), "ipset", "conntrack"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 || f.calls[0][0] != "update" || strings.Join(f.calls[1], " ") != "install ipset conntrack" {
		t.Errorf("calls = %v, want update then one install of both packages", f.calls)
	}
}

func TestInstallNoUpdate_SkipsTheUpdate(t *testing.T) {
	f := installFake(t)
	if err := InstallNoUpdate(context.Background(), "ipset"); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0][0] != "install" {
		t.Errorf("calls = %v, want only the install", f.calls)
	}
}

func TestInstall_NothingToDo(t *testing.T) {
	f := installFake(t)
	if err := Install(context.Background()); err != nil || len(f.calls) != 0 {
		t.Errorf("no packages: err=%v calls=%v", err, f.calls)
	}
}

// A failed `opkg update` is not a failure by itself (the index may be fresh)...
func TestInstall_FailedUpdateDoesNotFailTheInstall(t *testing.T) {
	f := installFake(t)
	f.answer("update", "Failed to download Packages", errors.New("exit status 1"))
	if err := Install(context.Background(), "ipset"); err != nil {
		t.Errorf("install succeeded but Install returned %v", err)
	}
}

// ...but when the install then fails, the update's output is the real reason:
// without it a dead network reads as "Unknown package".
func TestInstall_UpdateOutputExplainsTheInstallFailure(t *testing.T) {
	f := installFake(t)
	f.answer("update", "Downloading http://bin.entware.net/x/Packages.gz\nwget: bad address 'bin.entware.net'\nCollected errors:\n * opkg_download: Failed to download", errors.New("exit status 1"))
	f.answer("install", "Unknown package 'ipset'.\nCollected errors:\n * opkg_install_cmd: Cannot install package ipset.", errors.New("exit status 255"))

	err := Install(context.Background(), "ipset")
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if !strings.Contains(oe.Reason, "нет связи с репозиторием") {
		t.Errorf("reason = %q, want the network, not the 'Unknown package' the install printed", oe.Reason)
	}
	if !strings.Contains(oe.Error(), "opkg install ipset") || !strings.Contains(oe.Error(), "Cannot install package ipset") {
		t.Errorf("error text = %q, want the command and the tail of opkg's output", oe.Error())
	}
}

func TestInstall_ErrorWrapsTheExecError(t *testing.T) {
	f := installFake(t)
	cause := errors.New("exit status 255")
	f.answer("install", "", cause)
	err := Install(context.Background(), "ipset")
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false for %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 255") {
		t.Errorf("an unexplained failure must still show the exec error: %q", err)
	}
}

func TestInstall_ContextDeadlineIsSaid(t *testing.T) {
	f := installFake(t)
	f.answer("install", "", errors.New("signal: killed"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Install(ctx, "ipset")
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
}

func TestExplain(t *testing.T) {
	cases := []struct {
		name   string
		output string
		err    error
		want   string // substring of the reason, "" for no known cause
	}{
		{"no opkg at all", "", exec.ErrNotFound, "Entware не установлен"},
		{"lock", "Could not lock /opt/var/lock/opkg.lock: Resource temporarily unavailable", errors.New("x"), "занят другим процессом"},
		{"space", "gzip: write error: No space left on device", errors.New("x"), "нет свободного места"},
		{"no https", "wget: not an http or ftp url: https://bin.entware.net/Packages.gz", errors.New("x"), "не умеет HTTPS"},
		{"ssl", "wget: SSL support not available, please install one of the libustream-.*[ssl|tls] packages", errors.New("x"), "не умеет HTTPS"},
		{"dns", "wget: bad address 'bin.entware.net'", errors.New("x"), "нет связи с репозиторием"},
		{"download", " * opkg_download: Failed to download http://bin.entware.net/Packages.gz, wget returned 1.", errors.New("x"), "нет связи с репозиторием"},
		{"timeout", "wget: download timed out\nOperation timed out", errors.New("x"), "нет связи с репозиторием"},
		{"unknown package", "Unknown package 'conntrack'.", errors.New("x"), "нет в репозитории Entware"},
		{"deps", " * satisfy_dependencies_for: Cannot satisfy the following dependencies for ipset:", errors.New("x"), "не хватает пакетов"},
		{"deadline", "", context.DeadlineExceeded, "не уложился во время"},
		{"nothing known", "something odd happened", errors.New("exit status 2"), ""},
	}
	for _, tc := range cases {
		got := Explain(tc.output, tc.err)
		if tc.want == "" {
			if got != "" {
				t.Errorf("%s: reason %q for an unknown failure, want none", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s: reason %q lacks %q", tc.name, got, tc.want)
		}
	}
}

// A dead network is told apart from a missing package even though both can
// print "Unknown package" -- the network check runs first.
func TestExplain_NetworkBeatsUnknownPackage(t *testing.T) {
	out := "wget: bad address 'bin.entware.net'\nUnknown package 'ipset'."
	if got := Explain(out, errors.New("x")); !strings.Contains(got, "нет связи") {
		t.Errorf("reason = %q", got)
	}
}

func TestTail(t *testing.T) {
	if got := tail("a\n\n  b  \r\nc\nd\ne\n"); got != "c | d | e" {
		t.Errorf("tail = %q, want the last three non-empty lines", got)
	}
	long := strings.Repeat("x", 1000)
	if got := tail(long); len(got) > 310 || !strings.HasPrefix(got, "…") {
		t.Errorf("a long tail is cut to the end (%d bytes): %q", len(got), got[:20])
	}
	if got := tail(""); got != "" {
		t.Errorf("tail of nothing = %q", got)
	}
}

// No opkg at all: both commands fail with nothing printed, and the message must
// not carry an empty "[opkg update failed:]" tail.
func TestInstall_NoOpkgAtAllHasNoNoiseInTheTail(t *testing.T) {
	f := installFake(t)
	f.answer("update", "", exec.ErrNotFound)
	f.answer("install", "", exec.ErrNotFound)
	err := Install(context.Background(), "ipset")
	var oe *Error
	if !errors.As(err, &oe) {
		t.Fatalf("err = %v", err)
	}
	if oe.Output != "" || strings.Contains(oe.Error(), "[") {
		t.Errorf("output %q in %q, want none", oe.Output, oe.Error())
	}
	if !strings.Contains(oe.Reason, "Entware не установлен") {
		t.Errorf("reason = %q", oe.Reason)
	}
}
