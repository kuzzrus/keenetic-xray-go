package classifier

import (
	"net"
	"testing"
	"time"
)

func testLANConfig() *Config {
	cfg := DefaultConfig()
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	cfg.LANSubnets = []*net.IPNet{n}
	return &cfg
}

func TestFromLAN(t *testing.T) {
	cfg := testLANConfig()
	if !fromLAN(cfg, "192.168.1.5") {
		t.Error("192.168.1.5 should be in 192.168.1.0/24")
	}
	if fromLAN(cfg, "10.0.0.5") {
		t.Error("10.0.0.5 should not be in 192.168.1.0/24")
	}
	if fromLAN(cfg, "not-an-ip") {
		t.Error("an unparseable src should never match")
	}
}

func TestIsPrivateDst(t *testing.T) {
	for _, ip := range []string{"10.1.2.3", "192.168.5.5", "127.0.0.1", "169.254.1.1"} {
		if !isPrivateDst(ip) {
			t.Errorf("%s should be private", ip)
		}
	}
	for _, ip := range []string{"1.2.3.4", "8.8.8.8"} {
		if isPrivateDst(ip) {
			t.Errorf("%s should not be private", ip)
		}
	}
	if isPrivateDst("not-an-ip") {
		t.Error("an unparseable dst should not be treated as private, matching upstream's ip_in_cidr on a failed parse")
	}
}

func TestCandidateOK(t *testing.T) {
	now := time.Now()
	state := NewState()
	if !candidateOK(state, false, "1.2.3.4", now) {
		t.Fatal("a destination with no state at all should be a candidate")
	}
	state.OK[0].add("1.2.3.4", now, time.Hour)
	if candidateOK(state, false, "1.2.3.4", now) {
		t.Error("a destination already in ok should not be a candidate")
	}
	state.OK[0].remove("1.2.3.4")

	state.Test[0].add("1.2.3.4", now, time.Hour)
	if candidateOK(state, false, "1.2.3.4", now) {
		t.Error("a destination already in test should not be a candidate")
	}
	state.Test[0].remove("1.2.3.4")

	state.Cooldown[0].add("1.2.3.4", now, time.Hour)
	if candidateOK(state, false, "1.2.3.4", now) {
		t.Error("a destination in cooldown should not be a candidate")
	}

	// A separate protocol's state must not interfere.
	if !candidateOK(state, true, "1.2.3.4", now) {
		t.Error("tcp cooldown should not block the same address as a udp candidate")
	}
}
