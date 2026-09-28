package keenetic

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestTransient(t *testing.T) {
	// A real *exec.ExitError with a normal exit status: the test binary
	// itself, refusing an unknown flag (exit 2) -- the shape of ndmc
	// answering a command with an error.
	exitErr := exec.Command(os.Args[0], "-test.no-such-flag").Run()
	var ee *exec.ExitError
	if !errors.As(exitErr, &ee) {
		t.Fatalf("setup: got %v, want an *exec.ExitError", exitErr)
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"save failed", fmt.Errorf("%w: busy", ErrNotSaved), true},
		{"deadline", fmt.Errorf("ndmc %q: %w", "show ping-check", context.DeadlineExceeded), true},
		{"router refused", fmt.Errorf("ndmc %q: %w", "ping-check profile kxray mode tls", exitErr), false},
		{"fork failed", &fs.PathError{Op: "fork/exec", Path: "/opt/sbin/ndmc", Err: syscall.ENOMEM}, true},
		{"rci unreachable", &url.Error{Op: "Get", URL: "http://127.0.0.1:79/rci/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}, true},
		{"no ndmc at all", &exec.Error{Name: "ndmc", Err: exec.ErrNotFound}, false},
		{"reads back wrong", errors.New("kxray reads back as mode=\"icmp\""), false},
	}
	for _, tc := range cases {
		if got := Transient(tc.err); got != tc.want {
			t.Errorf("%s: Transient(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}
