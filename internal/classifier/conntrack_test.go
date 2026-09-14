package classifier

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConntrackLine_TCP(t *testing.T) {
	// Real nf_conntrack shape: <nfproto> <nfproto_num> tcp 6 <timeout>
	// <state> src=... dst=... sport=... dport=... [reply tuple] mark=...
	line := "ipv4     2 tcp      6 108 ESTABLISHED src=192.168.1.5 dst=1.2.3.4 " +
		"sport=54321 dport=443 src=1.2.3.4 dst=192.168.1.5 sport=443 dport=54321 " +
		"[ASSURED] mark=0 use=1"
	f, ok := ParseConntrackLine(line)
	if !ok {
		t.Fatal("expected a valid parse")
	}
	if f.L4Proto != 6 || f.Proto != "tcp" {
		t.Errorf("proto = %d/%q, want 6/tcp", f.L4Proto, f.Proto)
	}
	if f.TCPState != "ESTABLISHED" {
		t.Errorf("TCPState = %q, want ESTABLISHED", f.TCPState)
	}
	if f.Src != "192.168.1.5" || f.Dst != "1.2.3.4" {
		t.Errorf("src/dst = %q/%q, want the ORIGINAL-direction tuple only", f.Src, f.Dst)
	}
	if f.SPort != 54321 || f.DPort != 443 {
		t.Errorf("sport/dport = %d/%d, want 54321/443", f.SPort, f.DPort)
	}
	if f.RSPort != 443 || f.RDPort != 54321 {
		t.Errorf("reply sport/dport = %d/%d, want 443/54321 (the second occurrence)", f.RSPort, f.RDPort)
	}
	if f.CTMark != 0 {
		t.Errorf("CTMark = %d, want 0", f.CTMark)
	}
}

func TestParseConntrackLine_UDP(t *testing.T) {
	line := "ipv4     2 udp      17 29 src=192.168.1.5 dst=8.8.8.8 sport=1111 dport=443 " +
		"src=8.8.8.8 dst=192.168.1.5 sport=443 dport=1111 packets=5 bytes=600 " +
		"packets=3 bytes=400 mark=0x10000000 use=1"
	f, ok := ParseConntrackLine(line)
	if !ok {
		t.Fatal("expected a valid parse")
	}
	if f.L4Proto != 17 || f.TCPState != "" {
		t.Errorf("l4proto/state = %d/%q, want 17/empty (udp has no state field)", f.L4Proto, f.TCPState)
	}
	if f.OP != 5 || f.OB != 600 || f.RP != 3 || f.RB != 400 {
		t.Errorf("op/ob/rp/rb = %d/%d/%d/%d, want 5/600/3/400", f.OP, f.OB, f.RP, f.RB)
	}
	if !f.HasReply {
		t.Error("HasReply should be true when rp > 0")
	}
	if f.CTMark != 0x10000000 {
		t.Errorf("CTMark = %#x, want 0x10000000 (hex mark= parsing)", f.CTMark)
	}
}

func TestParseConntrackLine_FastNAT(t *testing.T) {
	line := "ipv4     2 tcp      6 108 ESTABLISHED src=192.168.1.5 dst=1.2.3.4 " +
		"sport=1 dport=443 [FASTNAT] mark=0"
	f, ok := ParseConntrackLine(line)
	if !ok {
		t.Fatal("expected a valid parse")
	}
	if !f.FastNAT {
		t.Error("FastNAT should be true when a token contains FASTNAT")
	}
}

func TestParseConntrackLine_Invalid(t *testing.T) {
	for _, line := range []string{
		"",
		"garbage without any recognizable fields",
		"ipv4 2 tcp 6 108 ESTABLISHED sport=1 dport=2", // no src=/dst=
	} {
		if _, ok := ParseConntrackLine(line); ok {
			t.Errorf("line %q: expected an invalid parse", line)
		}
	}
}

func TestScanConntrack(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nf_conntrack")
	content := "ipv4     2 tcp      6 108 SYN_SENT src=192.168.1.5 dst=1.2.3.4 sport=1 dport=443 mark=0\n" +
		"this line has no src/dst and should be skipped\n" +
		"ipv4     2 udp      17 29 src=192.168.1.5 dst=8.8.8.8 sport=2 dport=53 mark=0\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	flows, err := ScanConntrack(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("flows = %v, want 2 (the invalid line must be skipped)", flows)
	}
	if flows[0].Dst != "1.2.3.4" || flows[1].Dst != "8.8.8.8" {
		t.Errorf("flows = %+v", flows)
	}
}

func TestScanConntrack_MissingFile(t *testing.T) {
	if _, err := ScanConntrack(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
