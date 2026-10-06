package xrayctl

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestCheckTunSupport(t *testing.T) {
	// The stand-in xray ignores its arguments, so what is under test is the
	// plumbing: a probe config is written, handed over, and the verdict and
	// xray's own words come back.
	t.Setenv("XRAYCTL_TEST_HELPER", "1")
	t.Setenv("XRAYCTL_TEST_BEHAVIOR", "test-ok")
	if err := CheckTunSupport(context.Background(), os.Args[0], 1280); err != nil {
		t.Fatalf("a core that knows tun was refused: %v", err)
	}
	t.Setenv("XRAYCTL_TEST_BEHAVIOR", "test-fail")
	err := CheckTunSupport(context.Background(), os.Args[0], 1280)
	if err == nil || !strings.Contains(err.Error(), `unknown protocol "tun"`) {
		t.Fatalf("err = %v, want xray's own refusal", err)
	}
	if err := CheckTunSupport(context.Background(), os.Args[0], 70000); err == nil {
		t.Error("an out-of-range MTU produced a config xray was asked to test")
	}
}

// The probe's temp file must not outlive the call.
func TestCheckTunSupport_RemovesItsTempFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	t.Setenv("XRAYCTL_TEST_HELPER", "1")
	t.Setenv("XRAYCTL_TEST_BEHAVIOR", "test-ok")
	if err := CheckTunSupport(context.Background(), os.Args[0], 1280); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Errorf("temp files left behind: %v", left)
	}
}
