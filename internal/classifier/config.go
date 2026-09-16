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

	// ClrBlockPromote: once at least BlockThreshold distinct addresses
	// inside the same BlockCIDRBits-bit network are individually
	// confirmed (state.OK, not just provisional state.Test) as needing
	// the tunnel, redirect that whole network instead of waiting for
	// every one of its other addresses to each earn its own promotion.
	// Exists for large, fast-rotating CDNs (Instagram/Facebook, Netflix,
	// ...) where a single page load fans out to dozens of addresses in
	// the same /24 and per-IP reactive detection structurally can't keep
	// up -- see docs/HANDOFF-susanin.md. BlockThreshold <= 0 disables
	// this pass entirely.
	BlockCIDRBits  int
	BlockThreshold int
	BlockTTL       time.Duration

	// KnownRangeLookup, when set, lets ClrBlockPromote check a
	// newly-threshold-crossing block against a table of publicly known
	// infrastructure ranges (internal/knownranges, sourced from lord-
	// alfred/ipranges) before falling back to the blind BlockCIDRBits
	// guess. A large provider's real allocation is often much wider than
	// one /24 -- when the lookup finds a match, that wider, real
	// boundary is what gets promoted and recorded instead. Kept as an
	// injected pure function rather than a direct dependency so this
	// package stays free of any I/O of its own (see the package doc
	// comment): the caller owns fetching/caching/refreshing the table
	// and just hands over its Lookup method. nil -> always use the
	// blind guess, the original behavior every existing test exercises.
	KnownRangeLookup func(ip string) (cidr string, ok bool)

	// KnownRangeMinPrefixBits caps how wide a KnownRangeLookup match is
	// allowed to widen a promotion: a match whose prefix is *shorter*
	// than this (a wider network) is ignored, same as no match at all --
	// falls back to the naive BlockCIDRBits guess. <= 0 disables the cap
	// (any match, however wide, is accepted).
	//
	// Exists because "a known range" and "entirely dedicated to the one
	// service that tripped the promotion" are not the same claim. A
	// huge, multi-service provider publishes CIDR blocks covering its
	// *entire* edge network -- search, mail, ads embedded on every other
	// site, countless unrelated APIs -- not just the one CDN edge that
	// was actually blocked. Confirmed live on hardware (2026-09-15):
	// Google's own /15-/16 ranges got swept in by one promoted block,
	// and multiple unrelated services (YouTube *and* Instagram) broke
	// within the same minute -- the tunnel saturated with previously-
	// fine-going-DIRECT traffic that this feature was never meant to
	// touch. A single-purpose service's own published range (Telegram's
	// /20, Meta's specific edge /18) doesn't carry that risk -- the
	// whole thing really is the one thing that tripped the promotion --
	// so the default here is deliberately narrow enough to keep those
	// while rejecting a sprawling generic provider's own /15s and /16s.
	KnownRangeMinPrefixBits int

	// ExcludedRangeLookup, when set, vetoes a destination from ever
	// becoming a classification candidate at all -- checked in ClrFast/
	// ClrSoft right alongside isPrivateDst, before any Test/OK state
	// entry is created for it. Unlike KnownRangeLookup (which only
	// *widens* an already-decided ClrBlockPromote promotion),
	// this is a hard gate: a destination that matches is never
	// classified, full stop. Exists for internal/georanges (Russian-
	// registered IP space) -- the adaptive-route feature exists to route
	// around *foreign* DPI blocks, so a Russian-hosted false positive
	// (a LAN health-check probing an unrelated protocol, a transient
	// stall, ...) should never have been eligible in the first place;
	// see the russia-ip-exclusion-plan memory for the incident that
	// prompted this. Kept as an injected pure function for the same
	// reason as KnownRangeLookup: this package stays free of any I/O of
	// its own, the caller owns fetching/caching/refreshing the table.
	// nil -> no additional exclusion, the original behavior every
	// existing test exercises. cidr is unused by the caller today, kept
	// only so georanges.Lookup's existing signature (shared with
	// KnownRangeLookup) can be wired in directly with no adapter.
	ExcludedRangeLookup func(ip string) (cidr string, ok bool)
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

		BlockCIDRBits:  24,
		BlockThreshold: 4,
		BlockTTL:       30 * time.Minute,

		// 18: comfortably narrower than BlockCIDRBits (24) so a genuine
		// widening still happens (Telegram's /20, Meta's specific edge
		// /18 both pass), but excludes the /15s and /16s a sprawling
		// generic provider (Google, confirmed live) publishes for its
		// entire edge network -- see KnownRangeMinPrefixBits' own doc
		// comment for the incident that set this default.
		KnownRangeMinPrefixBits: 18,
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

// isExcludedDst reports whether cfg.ExcludedRangeLookup (when set) flags
// dst as never-classify. Mirrors isPrivateDst's own boolean-gate shape;
// see ExcludedRangeLookup's doc comment for why this is a separate field
// rather than folded into isPrivateDst's static list.
func isExcludedDst(cfg *Config, dst string) bool {
	if cfg.ExcludedRangeLookup == nil {
		return false
	}
	_, ok := cfg.ExcludedRangeLookup(dst)
	return ok
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
