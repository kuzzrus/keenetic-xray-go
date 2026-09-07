package addons

import (
	"context"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/dnsupstream"
)

// probeResolver checks that a locally-installed resolver actually
// answers a query (not just that the port is open). Injectable for
// tests.
var probeResolver = dnsupstream.ProbePlain

// ResolverStat is one DNS component's live health.
type ResolverStat struct {
	ID       string // "unbound" | "dnscrypt"
	Port     int
	Resolves bool
	Detail   string // "" on success, else why not
}

// ResolverHealth probes every installed local DNS resolver (unbound,
// dnscrypt) on 127.0.0.1:<its port> and reports whether it resolves.
// Skips components that aren't installed. Used by `keenetic-xray
// doctor` and the components' own Status().
func ResolverHealth(ctx context.Context) []ResolverStat {
	var out []ResolverStat
	if u := unboundRead(ctx); u.installed {
		out = append(out, resolverStat(ctx, "unbound", u.port))
	}
	if d := dnscryptRead(ctx); d.installed {
		out = append(out, resolverStat(ctx, "dnscrypt", d.port))
	}
	return out
}

func resolverStat(ctx context.Context, id string, port int) ResolverStat {
	st := ResolverStat{ID: id, Port: port}
	if err := probeResolver(ctx, fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		st.Detail = shortResolverErr(err)
		return st
	}
	st.Resolves = true
	return st
}

func shortResolverErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "порт закрыт"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"), strings.Contains(s, "i/o"):
		return "нет ответа (таймаут)"
	case strings.Contains(s, "RCODE"):
		return "резолвер ответил ошибкой (" + s + ")"
	}
	if len(s) > 48 {
		s = s[:48] + "…"
	}
	return s
}
