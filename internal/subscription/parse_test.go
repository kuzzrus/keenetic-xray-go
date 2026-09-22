package subscription

import (
	"strings"
	"testing"
)

func TestParse_MixedValidAndInvalid(t *testing.T) {
	input := []byte(`vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#primary
vmess://someBase64Blob#should-be-skipped
vless://22222222-3333-4444-5555-666666666666@example.org:8443?type=ws&security=tls&sni=cdn.example.org#backup

not-a-uri-at-all
vless://@bad:443?type=tcp&security=none#missing-uuid`)

	profiles, warnings := Parse(input)

	if len(profiles) != 2 {
		t.Fatalf("len(profiles) = %d, want 2; profiles=%#v warnings=%v", len(profiles), profiles, warnings)
	}
	if profiles[0].Remark != "primary" || profiles[1].Remark != "backup" {
		t.Errorf("profiles = %#v, want remarks [primary backup]", profiles)
	}
	if len(warnings) != 3 {
		t.Errorf("len(warnings) = %d, want 3 (vmess line, non-uri line, missing-uuid line); got %v", len(warnings), warnings)
	}
}

func TestParse_Empty(t *testing.T) {
	profiles, warnings := Parse([]byte(""))
	if len(profiles) != 0 || len(warnings) != 0 {
		t.Errorf("Parse(empty) = (%v, %v), want (nil, nil)", profiles, warnings)
	}
}

func TestParse_BlankLinesIgnored(t *testing.T) {
	input := []byte("\n\n   \nvless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#a\n\n")
	profiles, warnings := Parse(input)
	if len(profiles) != 1 {
		t.Fatalf("len(profiles) = %d, want 1", len(profiles))
	}
	if len(warnings) != 0 {
		t.Errorf("warnings = %v, want none", warnings)
	}
}

// TestParse_LineOverDefaultScannerLimitDoesNotTruncateSubscription is
// SUB-01's core regression test: bufio.Scanner's default 64KB max token
// size fails closed -- once a line exceeds it, Scan() returns false as
// if EOF had been reached, silently discarding every line after it. A
// valid entry placed after the over-long line must still come through.
func TestParse_LineOverDefaultScannerLimitDoesNotTruncateSubscription(t *testing.T) {
	longLine := "not-a-uri-" + strings.Repeat("x", 70*1024) // > the old 64KB default, well under MaxBodyBytes
	input := []byte("vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#before\n" +
		longLine + "\n" +
		"vless://22222222-3333-4444-5555-666666666666@example.org:8443?type=ws&security=tls&sni=cdn.example.org#after\n")

	profiles, warnings := Parse(input)

	if len(profiles) != 2 {
		t.Fatalf("len(profiles) = %d, want 2 (before AND after the long line); profiles=%#v warnings=%v", len(profiles), profiles, warnings)
	}
	if profiles[0].Remark != "before" || profiles[1].Remark != "after" {
		t.Errorf("profiles = %#v, want remarks [before after]", profiles)
	}
}

// TestParse_LineOverScannerBufferSurfacesAsWarning confirms the other
// half of the fix: even a line past the raised MaxBodyBytes ceiling
// (unreachable through the real fetch pipeline, which already caps the
// whole response at MaxBodyBytes -- but Parse is tested standalone here)
// surfaces scanner.Err() as a warning instead of returning silently as
// if the subscription were simply empty/short.
func TestParse_LineOverScannerBufferSurfacesAsWarning(t *testing.T) {
	tooLong := strings.Repeat("x", MaxBodyBytes+1024)
	profiles, warnings := Parse([]byte(tooLong))
	if len(profiles) != 0 {
		t.Errorf("profiles = %#v, want none", profiles)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "truncated") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one mentioning truncation", warnings)
	}
}
