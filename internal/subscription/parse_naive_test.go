package subscription

import "testing"

// A separate file from parse_test.go on purpose -- keeps the naive
// addition out of a file this Windows checkout has a recurring
// line-ending-artifact history with.
func TestParse_MixedVlessAndNaive(t *testing.T) {
	input := []byte(`vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#primary
naive+https://alice:s3cret@n.example.com:443#naive-backup
vmess://skip-me#unsupported`)

	profiles, warnings := Parse(input)

	if len(profiles) != 2 {
		t.Fatalf("len(profiles) = %d, want 2; profiles=%#v warnings=%v", len(profiles), profiles, warnings)
	}
	if profiles[0].Protocol != "" || profiles[0].Remark != "primary" {
		t.Errorf("profiles[0] = %+v, want the vless entry", profiles[0])
	}
	if profiles[1].Protocol != "naive" || profiles[1].Remark != "naive-backup" || profiles[1].User != "alice" {
		t.Errorf("profiles[1] = %+v, want the naive entry", profiles[1])
	}
	if len(warnings) != 1 {
		t.Errorf("warnings = %v, want 1 (the vmess line)", warnings)
	}
}
