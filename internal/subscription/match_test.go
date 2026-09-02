package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

func TestMatchByRemark(t *testing.T) {
	profiles := []config.Profile{
		{Remark: "primary"},
		{Remark: "backup"},
		{Remark: "duplicate"},
		{Remark: "duplicate"},
	}

	cases := []struct {
		name       string
		remark     string
		wantIndex  int
		wantResult MatchResult
	}{
		{"unique match", "primary", 0, MatchUnique},
		{"unique match second", "backup", 1, MatchUnique},
		{"not found", "missing", -1, MatchNotFound},
		{"empty remark", "", -1, MatchNotFound},
		{"ambiguous", "duplicate", -1, MatchAmbiguous},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx, result := MatchByRemark(profiles, tc.remark)
			if idx != tc.wantIndex || result != tc.wantResult {
				t.Errorf("MatchByRemark(%q) = (%d, %v), want (%d, %v)", tc.remark, idx, result, tc.wantIndex, tc.wantResult)
			}
		})
	}
}

func subscriptionServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const twoProfileSubscription = `vless://11111111-2222-3333-4444-555555555555@example.com:443?type=tcp&security=none#primary
vless://22222222-3333-4444-5555-666666666666@example.org:8443?type=ws&security=tls&sni=cdn.example.org#backup`

func TestRefresh_UniqueMatch(t *testing.T) {
	srv := subscriptionServer(t, twoProfileSubscription)

	result, err := Refresh(context.Background(), srv.URL, "primary", "backup")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(result.Profiles) != 2 {
		t.Fatalf("len(Profiles) = %d, want 2", len(result.Profiles))
	}
	if result.PrimaryStatus != MatchUnique || result.PrimaryIndex != 0 {
		t.Errorf("primary = (%d, %v), want (0, MatchUnique)", result.PrimaryIndex, result.PrimaryStatus)
	}
	if result.BackupStatus != MatchUnique || result.BackupIndex != 1 {
		t.Errorf("backup = (%d, %v), want (1, MatchUnique)", result.BackupIndex, result.BackupStatus)
	}
}

func TestRefresh_RenamedRemarkDoesNotGuess(t *testing.T) {
	srv := subscriptionServer(t, twoProfileSubscription)

	result, err := Refresh(context.Background(), srv.URL, "old-primary-name", "backup")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if result.PrimaryStatus != MatchNotFound || result.PrimaryIndex != -1 {
		t.Errorf("primary = (%d, %v), want (-1, MatchNotFound) -- must not guess a replacement", result.PrimaryIndex, result.PrimaryStatus)
	}
	if result.BackupStatus != MatchUnique || result.BackupIndex != 1 {
		t.Errorf("backup = (%d, %v), want (1, MatchUnique)", result.BackupIndex, result.BackupStatus)
	}
}

func TestRefresh_NoUsableProfiles(t *testing.T) {
	srv := subscriptionServer(t, "vmess://not-supported#x")

	if _, err := Refresh(context.Background(), srv.URL, "primary", "backup"); err == nil {
		t.Error("expected error when subscription has no usable vless:// entries")
	}
}
