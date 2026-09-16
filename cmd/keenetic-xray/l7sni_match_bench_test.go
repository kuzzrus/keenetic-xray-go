package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// benchRouteListSize is just under config's own 256-entries-per-list
// cap -- the point of these benchmarks is the per-captured-packet cost
// at a realistic list size, not a worst case.
const benchRouteListSize = 250

func benchConfig() *config.Config {
	entries := make([]string, 0, benchRouteListSize)
	for i := 0; i < benchRouteListSize-1; i++ {
		entries = append(entries, fmt.Sprintf("service%03d.example", i))
	}
	entries = append(entries, "instagram.com")
	return &config.Config{Routing: config.RoutingConfig{Lists: []config.RouteList{
		{Name: "bench", Entries: entries},
	}}}
}

// l7sniMatchesRoutesPerPacket is the pre-2026-09-16 hot path, kept here
// only so the benchmarks below compare against something real: it
// re-classified every entry of every list on every captured packet.
func l7sniMatchesRoutesPerPacket(cfg *config.Config, host string) bool {
	for _, rl := range cfg.Routing.Lists {
		if rl.Disabled {
			continue
		}
		for _, e := range rl.Entries {
			kind, domain, err := config.ClassifyRouteEntry(e)
			if err != nil || kind != config.RouteDomain {
				continue
			}
			if host == domain || strings.HasSuffix(host, "."+domain) {
				return true
			}
		}
	}
	return false
}

// BenchmarkL7SNIMatch_PerPacketClassify measures the old per-packet
// matching cost (ClassifyRouteEntry over every entry), on a miss --
// the common case, since most captured hostnames match nothing.
func BenchmarkL7SNIMatch_PerPacketClassify(b *testing.B) {
	cfg := benchConfig()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if l7sniMatchesRoutesPerPacket(cfg, "www.unrelated-service.example.org") {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkL7SNIMatch_PrebuiltSet measures the same miss against the
// prebuilt set the capture loop now carries.
func BenchmarkL7SNIMatch_PrebuiltSet(b *testing.B) {
	set := l7sniDomainsFrom(benchConfig())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if set.matches("www.unrelated-service.example.org") {
			b.Fatal("unexpected match")
		}
	}
}

// BenchmarkL7SNIConfigLoad measures what used to happen *in addition*
// to the matching above, once per captured packet carrying a hostname:
// a full read and JSON unmarshal of the router's config.
func BenchmarkL7SNIConfigLoad(b *testing.B) {
	path := filepath.Join(b.TempDir(), "config.json")
	cfg := config.Default()
	cfg.Routing = benchConfig().Routing
	if err := cfg.Save(path); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := config.Load(path); err != nil {
			b.Fatal(err)
		}
	}
}
