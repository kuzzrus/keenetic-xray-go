package botcontrol

import (
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
)

func TestMsField(t *testing.T) {
	if got := msField(dnsupstream.Timing{OK: true, Latency: 45 * time.Millisecond}); got != "45" {
		t.Errorf("msField(ok, 45ms) = %q, want %q", got, "45")
	}
	if got := msField(dnsupstream.Timing{OK: false, Err: "timeout"}); got != "" {
		t.Errorf("msField(not ok) = %q, want empty", got)
	}
}

func TestParseDNSTestTop(t *testing.T) {
	out := "cloudflare\tCloudflare\t45\t52\n" +
		"quad9\tQuad9\t-\t80\n" +
		"dead\tDead Provider\t-\t-\n"
	rows := parseDNSTestTop(out)
	if len(rows) != 3 {
		t.Fatalf("len(rows) = %d, want 3: %+v", len(rows), rows)
	}
	if rows[0] != (dnsTestTopRow{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"}) {
		t.Errorf("rows[0] = %+v", rows[0])
	}
	if rows[1].DoTMs != "" || rows[1].DoHMs != "80" {
		t.Errorf("rows[1] = %+v, want DoT unavailable (dash undone), DoH 80", rows[1])
	}
	if rows[2].DoTMs != "" || rows[2].DoHMs != "" {
		t.Errorf("rows[2] = %+v, want both unavailable", rows[2])
	}
}

func TestParseDNSTestTop_DropsMalformedLines(t *testing.T) {
	out := "cloudflare\tCloudflare\t45\t52\n" +
		"too\tfew\tfields\n" +
		"quad9\tQuad9\t60\t65\n"
	rows := parseDNSTestTop(out)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2 (malformed line dropped): %+v", len(rows), rows)
	}
	if rows[0].ID != "cloudflare" || rows[1].ID != "quad9" {
		t.Errorf("rows = %+v, want cloudflare then quad9 (the bad line skipped, not shifting the rest)", rows)
	}
}

func TestParseDNSTestTop_Empty(t *testing.T) {
	if rows := parseDNSTestTop(""); len(rows) != 0 {
		t.Errorf("parseDNSTestTop(\"\") = %+v, want empty", rows)
	}
}

func TestMsLabel(t *testing.T) {
	if got := msLabel("45"); got != "45 мс" {
		t.Errorf("msLabel(45) = %q", got)
	}
	if got := msLabel(""); got != "—" {
		t.Errorf("msLabel(\"\") = %q, want the em-dash placeholder", got)
	}
}

func TestDNSTestTopKB_OneApplyButtonPerRowPlusBack(t *testing.T) {
	rows := []dnsTestTopRow{
		{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"},
		{ID: "quad9", Name: "Quad9", DoTMs: "", DoHMs: "80"},
	}
	kb := dnsTestTopKB("r1", rows)
	if len(kb.InlineKeyboard) != len(rows)+1 {
		t.Fatalf("len(rows) = %d, want %d (one per result + back)", len(kb.InlineKeyboard), len(rows)+1)
	}
	if cb := kb.InlineKeyboard[0][0].CallbackData; cb != "dna:r1:cloudflare:both" {
		t.Errorf("first apply button callback = %q, want dna:r1:cloudflare:both", cb)
	}
	if cb := kb.InlineKeyboard[1][0].CallbackData; cb != "dna:r1:quad9:both" {
		t.Errorf("second apply button callback = %q, want dna:r1:quad9:both", cb)
	}
	last := kb.InlineKeyboard[len(kb.InlineKeyboard)-1][0]
	if last.CallbackData != "dnsm:r1" {
		t.Errorf("last row = %+v, want the dnsm: back button", last)
	}
}

func TestDNSTestTopText_MentionsEveryProviderAndLatency(t *testing.T) {
	rows := []dnsTestTopRow{
		{ID: "cloudflare", Name: "Cloudflare", DoTMs: "45", DoHMs: "52"},
		{ID: "quad9", Name: "Quad9", DoTMs: "", DoHMs: "80"},
	}
	text := dnsTestTopText("r1", rows)
	for _, want := range []string{"Cloudflare", "45 мс", "52 мс", "Quad9", "80 мс", "—"} {
		if !strings.Contains(text, want) {
			t.Errorf("dnsTestTopText output missing %q:\n%s", want, text)
		}
	}
}
