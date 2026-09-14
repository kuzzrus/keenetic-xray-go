package classifier

import (
	"net"
	"time"
)

// Config holds the detection thresholds this port actually uses.
// Upstream's susanin_config (src/config.h) has more fields --
// routing_table/mark_*/ip_rule_priority_start (its own mark+policy-
// routing dataplane, which this port replaces with plain REDIRECT+ipset,
// see internal/adaptiveroute) and health_*/vpn_always_*/vpn_never_*
// (upstream's own health-check and static list handling, which this
// project's own xrayctl.Probe and routes/presets already cover
// differently, see docs/HANDOFF-susanin.md) -- none of which this port
// carries over.
type Config struct {
	// LANSubnets gates every classification: a flow's source must fall
	// in one of these for it to be considered at all (mirrors upstream's
	// from_lan against lan_subnets). Parsed once by the caller building
	// Config from the router's actual LAN config, not by this package.
	LANSubnets []*net.IPNet

	FastSynMinOp int // ClrFast: minimum orig packets on a silent SYN_SENT before it's suspicious

	TestTTL         time.Duration // how long a "test" (provisional) promotion lasts before ClrJudge decides
	OKTTL           time.Duration // how long a confirmed-ok destination stays routed without a healthy re-check
	OKRefreshBelow  time.Duration // refresh ok's TTL once less than this remains
	CooldownTTL     time.Duration // after a failed test: don't re-promote for this long
	CooldownOKTTL   time.Duration // after a previously-ok destination stops working: shorter cooldown
	WatchTTL        time.Duration // ClrSoft's late-stall watch window
	WatchRetryBelow time.Duration // confirm a late-stall once the watch window has this long or less left
}

// DefaultConfig mirrors config_set_defaults' thresholds (src/config.c)
// for the fields Config keeps -- LANSubnets is left nil, always set
// explicitly from the router's real LAN config.
func DefaultConfig() Config {
	return Config{
		FastSynMinOp:    2,
		TestTTL:         60 * time.Second,
		OKTTL:           6 * time.Hour,
		OKRefreshBelow:  3 * time.Hour,
		CooldownTTL:     5 * time.Minute,
		CooldownOKTTL:   30 * time.Second,
		WatchTTL:        8 * time.Second,
		WatchRetryBelow: 4 * time.Second,
	}
}

// privateDstNets are the ranges ClrFast/ClrSoft never classify a
// destination into, same list as upstream's is_private_dst.
var privateDstNets = mustParseCIDRs(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"224.0.0.0/4", "240.0.0.0/4",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("classifier: bad built-in CIDR " + c + ": " + err.Error())
		}
		nets[i] = n
	}
	return nets
}

// isPrivateDst reports whether dst is a reserved/private-use address.
// An unparseable dst (shouldn't happen -- Flow.Dst always comes from the
// kernel's own conntrack table) is treated as NOT private, matching
// upstream's ip_in_cidr returning false on a failed inet_pton rather
// than erroring.
func isPrivateDst(dst string) bool {
	ip := net.ParseIP(dst)
	if ip == nil {
		return false
	}
	for _, n := range privateDstNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// fromLAN reports whether src falls in one of cfg's LAN subnets.
func fromLAN(cfg *Config, src string) bool {
	ip := net.ParseIP(src)
	if ip == nil {
		return false
	}
	for _, n := range cfg.LANSubnets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// candidateOK reports whether dst is free to be freshly classified --
// not already in the ok, test, or cooldown state for this protocol.
// Mirrors upstream's candidate_ok exactly (src/classifier.c).
func candidateOK(state *State, udp bool, dst string, now time.Time) bool {
	i := protoIndex(udp)
	return !state.OK[i].has(dst, now) &&
		!state.Test[i].has(dst, now) &&
		!state.Cooldown[i].has(dst, now)
}
