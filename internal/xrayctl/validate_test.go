package xrayctl

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateConfig_OK(t *testing.T) {
	if err := ValidateConfig(context.Background(), os.Args[0], "unused.json", helperEnv("test-ok")); err != nil {
		t.Fatalf("ValidateConfig on a good config: %v", err)
	}
}

func TestValidateConfig_Fails(t *testing.T) {
	err := ValidateConfig(context.Background(), os.Args[0], "unused.json", helperEnv("test-fail"))
	if err == nil {
		t.Fatal("ValidateConfig = nil, want the failure")
	}
	// The reason xray gave must reach the operator, not just an exit status.
	if !strings.Contains(err.Error(), `unknown protocol "tun"`) {
		t.Errorf("error lacks xray's own message: %v", err)
	}
}

func TestValidateConfig_MissingBinary(t *testing.T) {
	if err := ValidateConfig(context.Background(), "/nonexistent/xray", "unused.json", nil); err == nil {
		t.Fatal("ValidateConfig = nil for a binary that does not exist")
	}
}

func TestValidateConfig_ContextBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := ValidateConfig(ctx, os.Args[0], "unused.json", helperEnv("sleep"))
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("ValidateConfig on a hung xray = %v after %v, want a prompt error", err, time.Since(start))
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("error does not say the deadline ran out: %v", err)
	}
}

func TestTailLines(t *testing.T) {
	if got := tailLines("a\n\n  b  \nc\nd\n", 2); got != "c | d" {
		t.Errorf("tailLines = %q, want %q", got, "c | d")
	}
	if got := tailLines("only", 3); got != "only" {
		t.Errorf("tailLines = %q", got)
	}
	if got := tailLines("", 3); got != "" {
		t.Errorf("tailLines(empty) = %q", got)
	}
}
