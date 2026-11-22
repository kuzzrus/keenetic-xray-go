package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/classifier"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// explainTestEnv is a router whose WG transport (Wireguard0) ends in our own
// xray, adaptive routing on, nothing resolvable and nothing listed.
func explainTestEnv() explainEnv {
	cfg := config.Default()
	cfg.WGTransport.Enabled = true
	cfg.WGTransport.Iface = "Wireguard0"
	cfg.AdaptiveRoute.Enabled = true
	cfg.L7SNI.Enabled = true
	return explainEnv{
		cfg:     cfg,
		resolve: func(context.Context, string) ([]string, error) { return nil, errors.New("нет резолвера") },
		routes:  func(context.Context) ([]keenetic.LiveRoute, error) { return nil, nil },
		members: func(context.Context) ([]adaptiveroute.Member, error) { return nil, nil },
	}
}

func resolvesTo(ips ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return ips, nil }
}

func explainText(t *testing.T, env explainEnv, query string) string {
	t.Helper()
	rep, err := buildExplain(context.Background(), env, query)
	if err != nil {
		t.Fatalf("explain %q: %v", query, err)
	}
	return renderExplain(rep)
}

func mustHave(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%q not in:\n%s", w, out)
		}
	}
}

func mustNotHave(t *testing.T, out string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(out, n) {
			t.Errorf("%q should not be in:\n%s", n, out)
		}
	}
}

func TestParseExplainQuery(t *testing.T) {
	good := []struct{ in, name, ip string }{
		{"example.com", "example.com", ""},
		{"  WWW.Example.COM. ", "www.example.com", ""},
		{"https://www.example.com/path?q=1", "www.example.com", ""},
		{"example.com:443", "example.com", ""},
		{"example.com/path", "example.com", ""},
		{"1.2.3.4", "", "1.2.3.4"},
		{"1.2.3.4:443", "", "1.2.3.4"},
		{"http://1.2.3.4/x", "", "1.2.3.4"},
	}
	for _, g := range good {
		name, ip, err := parseExplainQuery(g.in)
		if err != nil {
			t.Errorf("%q: %v", g.in, err)
			continue
		}
		if name != g.name || (g.ip == "") != (ip == nil) || (ip != nil && ip.String() != g.ip) {
			t.Errorf("%q -> name %q ip %v, want name %q ip %q", g.in, name, ip, g.name, g.ip)
		}
	}
	for _, bad := range []string{"", "   ", "::1", "1.2.3.0/24", "*.example.com", "not a name", "localhost", "https://"} {
		if _, _, err := parseExplainQuery(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}

func TestExplain_BadQueryIsAnError(t *testing.T) {
	if _, err := buildExplain(context.Background(), explainTestEnv(), "1.2.3.0/24"); err == nil {
		t.Fatal("a subnet is not a name or an address: want an error")
	}
}

func TestExplain_ListRoutedIntoOurXrayCoversNameAndParents(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("157.240.1.60")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"whatsapp.com", "1.1.1.1"}}}, nil
	}
	out := explainText(t, env, "web.whatsapp.com")
	mustHave(t, out,
		"Имя → 157.240.1.60",
		"Списки (роутер)",
		"«domain-list3» → Wireguard0 (в наш xray): whatsapp.com",
		"L7 (по имени): увидит имя (ClientHello, HTTP Host)",
		"Итог: в туннель по списку «domain-list3» → Wireguard0",
		"DNS-маршрут работает, пока клиент спрашивает имя у DNS роутера")
	mustNotHave(t, out, "Сайт не открывается?")

	// A parent domain only counts on a '.' boundary.
	out = explainText(t, env, "notwhatsapp.com")
	mustHave(t, out, "имя не входит ни в один список")
	mustNotHave(t, out, "domain-list3")
}

func TestExplain_ListRoutedElsewhereIsNotTheTunnel(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list9", Iface: "UsbLte0", Entries: []string{"example.org"}}}, nil
	}
	out := explainText(t, env, "example.org")
	mustHave(t, out,
		"«domain-list9» → UsbLte0 (не в наш xray): example.org",
		"L7 (по имени): не трогает — имя в списке «domain-list9» через UsbLte0",
		"Итог: не в туннель: список «domain-list9» ведёт через UsbLte0")
}

func TestExplain_ListOfOursIsMarkedByItsGroup(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: keenetic.RouteGroupPrefix + "tg", Iface: "Proxy0", Reject: true, Entries: []string{"t.me"}}}, nil
	}
	out := explainText(t, env, "t.me")
	mustHave(t, out, "«keenetic-xray-tg» → Proxy0 (в наш xray), строгий режим: t.me")
}

func TestExplain_GroupThatIsNotRoutedHasNoEffect(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list1", Iface: "", Entries: []string{"example.org"}}}, nil
	}
	out := explainText(t, env, "example.org")
	mustHave(t, out, "имя не входит ни в один список")
}

func TestExplain_SubnetAndSingleAddressEntriesCoverAResolvedAddress(t *testing.T) {
	env := explainTestEnv()
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list2", Iface: "Wireguard0", Entries: []string{"149.154.160.0/20", "198.51.100.7"}}}, nil
	}
	env.resolve = resolvesTo("149.154.167.51", "198.51.100.7", "198.51.100.8")
	out := explainText(t, env, "t.me")
	mustHave(t, out,
		"149.154.167.51 — в списке «domain-list2» → Wireguard0 (в наш xray): 149.154.160.0/20",
		"198.51.100.7 — в списке «domain-list2» → Wireguard0 (в наш xray): 198.51.100.7",
		"198.51.100.8 — ни списки, ни набор, ни исключения его не затрагивают",
		"Итог: адреса идут по-разному")
}

func TestExplain_AdaptiveSetEntryWithItsNote(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return []adaptiveroute.Member{
			{Addr: "203.0.113.9", Left: 5*time.Hour + 12*time.Minute, HasTimeout: true},
			{Addr: "203.0.113.10", Left: time.Hour, HasTimeout: true},
		}, nil
	}
	env.notes = func(addr string) (adaptiveroute.Note, bool) {
		if addr != "203.0.113.9" {
			return adaptiveroute.Note{}, false
		}
		return adaptiveroute.Note{Addr: addr, Tier: adaptiveroute.TierConfirmed, Reason: classifier.ReasonSilentSYN, Client: "192.168.1.130", Proto: "tcp", DPort: 443}, true
	}
	out := explainText(t, env, "blocked.example")
	mustHave(t, out,
		"203.0.113.9 — в наборе: подтверждён, осталось 5ч 12м, причина: SYN ушёл, ответа нет, клиент 192.168.1.130 tcp/443",
		"Итог: в туннель: адаптивный набор (подтверждён")
	mustNotHave(t, out, "203.0.113.10", "Сайт не открывается?")
}

func TestExplain_WidenedBlockCoversTheAddress(t *testing.T) {
	env := explainTestEnv()
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return []adaptiveroute.Member{{Addr: "203.0.113.0/24", Left: 20 * time.Minute, HasTimeout: true}}, nil
	}
	env.notes = func(addr string) (adaptiveroute.Note, bool) {
		return adaptiveroute.Note{Addr: addr, Tier: adaptiveroute.TierBlock, Reason: classifier.ReasonBlockWiden}, true
	}
	out := explainText(t, env, "203.0.113.77")
	mustHave(t, out, "203.0.113.77 — в наборе: подсеть 203.0.113.0/24, осталось 20м")
	mustNotHave(t, out, "Имя →", "L7 (по имени)")
}

func TestExplain_AdaptiveRoutingOffMeansTheSetIsNotApplied(t *testing.T) {
	env := explainTestEnv()
	env.cfg.AdaptiveRoute.Enabled = false
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return []adaptiveroute.Member{{Addr: "203.0.113.9", HasTimeout: false}}, nil
	}
	out := explainText(t, env, "203.0.113.9")
	mustHave(t, out,
		"адаптивная маршрутизация выключена",
		"Итог: напрямую: адрес есть в адаптивном наборе, но адаптивная маршрутизация выключена — набор не применяется")
}

func TestExplain_ExclusionsAndRussianRangesKeepAnAddressDirect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adaptive-exclude.txt")
	if err := os.WriteFile(path, []byte("# mine\n203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex, err := adaptiveroute.LoadExclusions(path)
	if err != nil {
		t.Fatal(err)
	}

	env := explainTestEnv()
	env.exclusions = ex
	env.ruRange = func(ip string) (string, bool) {
		if ip == "5.8.1.1" || ip == "203.0.113.5" {
			return "5.8.0.0/16", true
		}
		return "", false
	}

	out := explainText(t, env, "203.0.113.5")
	mustHave(t, out,
		"в списке исключений: 203.0.113.0/24",
		"российский диапазон: 5.8.0.0/16",
		"Итог: напрямую: адрес в вашем списке исключений (203.0.113.0/24)")
	mustNotHave(t, out, "Сайт не открывается?") // an answer, not a problem to hint about

	out = explainText(t, env, "5.8.1.1")
	mustHave(t, out, "Итог: напрямую: российский диапазон (5.8.0.0/16)")

	out = explainText(t, env, "198.51.100.1")
	mustHave(t, out, "Итог: напрямую: ни один список не покрывает, адаптивка этот адрес не заворачивала")
}

func TestExplain_NothingFoundForAName_HintsWhatToDo(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("198.51.100.1")
	out := explainText(t, env, "nothing.example")
	mustHave(t, out,
		"имя не входит ни в один список",
		"L7 (по имени): имени нет в списках — не ловится",
		"Итог: напрямую: ни один список не покрывает",
		"Сайт не открывается?")
}

func TestExplain_AdaptiveBeatsAListRoutedElsewhere_AndSaysSo(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list9", Iface: "UsbLte0", Entries: []string{"example.org"}}}, nil
	}
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return []adaptiveroute.Member{{Addr: "203.0.113.9", Left: time.Hour, HasTimeout: true}}, nil
	}
	out := explainText(t, env, "example.org")
	mustHave(t, out, "Итог: в туннель: адаптивный набор",
		"хотя список «domain-list9» ведёт через UsbLte0; адаптивный REDIRECT, скорее всего, перехватит трафик раньше")
}

func TestExplain_AListInTheTunnelBeatsTheAdaptiveSet(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"example.org"}}}, nil
	}
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return []adaptiveroute.Member{{Addr: "203.0.113.9", Left: time.Hour, HasTimeout: true}}, nil
	}
	out := explainText(t, env, "example.org")
	mustHave(t, out, "Итог: в туннель по списку «domain-list3» → Wireguard0", "в наборе: ")
}

func TestExplain_RouterListsUnreadable_FallsBackToTheConfig(t *testing.T) {
	env := explainTestEnv()
	env.cfg.Routing.Lists = []config.RouteList{{Name: "tg", Entries: []string{"x.com"}}} // no interface -> the Proxy interface
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) { return nil, errors.New("ndmc завис") }
	out := explainText(t, env, "x.com")
	mustHave(t, out,
		"Списки роутера прочитать не удалось (ndmc завис) — показаны списки конфига",
		"Списки (конфиг)",
		"«tg» → Proxy0 (в наш xray): x.com",
		"Итог: в туннель по списку «tg» → Proxy0")
	mustNotHave(t, out, "не применён") // nothing to compare the config against
}

func TestExplain_NotARouterSaysSo(t *testing.T) {
	env := explainTestEnv()
	env.routes, env.members = nil, nil
	env.cfg.Routing.Lists = []config.RouteList{{Name: "tg", Entries: []string{"x.com"}}}
	env.resolve = resolvesTo("203.0.113.9")
	out := explainText(t, env, "x.com")
	mustHave(t, out, "Это не роутер Keenetic", "Списки (конфиг)", "«tg»")
	mustNotHave(t, out, "прочитать не удалось")
}

func TestExplain_ConfigListNotAppliedToTheRouter(t *testing.T) {
	env := explainTestEnv()
	env.cfg.Routing.Lists = []config.RouteList{{Name: "tg", Entries: []string{"x.com"}}}
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) { return nil, nil }
	out := explainText(t, env, "x.com")
	mustHave(t, out,
		"имя не входит ни в один список",
		"список «tg» из конфига покрывает имя, но на роутере его группы нет — список не применён")

	// Once the group is there, the warning goes and the list shows as a hit.
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: keenetic.RouteGroupPrefix + "tg", Iface: "Proxy0", Entries: []string{"x.com"}}}, nil
	}
	out = explainText(t, env, "x.com")
	mustNotHave(t, out, "не применён")
	mustHave(t, out, "«keenetic-xray-tg» → Proxy0 (в наш xray): x.com")

	// A disabled list is not meant to be on the router: no warning.
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) { return nil, nil }
	env.cfg.Routing.Lists[0].Disabled = true
	mustNotHave(t, explainText(t, env, "x.com"), "не применён")
}

func TestExplain_NameThatDoesNotResolve(t *testing.T) {
	env := explainTestEnv()
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"example.org"}}}, nil
	}
	out := explainText(t, env, "example.org")
	mustHave(t, out,
		"Имя не резолвится: нет резолвера",
		"Итог по спискам: имя идёт в туннель — список «domain-list3» → Wireguard0 (адреса получить не удалось).")

	out = explainText(t, env, "unlisted.example")
	mustHave(t, out, "Имя не резолвится", "Итог: адресов нет и списки имя не покрывают — судить не по чему.")
}

func TestExplain_LANAddressIsNeverRouted(t *testing.T) {
	out := explainText(t, explainTestEnv(), "192.168.1.5")
	mustHave(t, out, "192.168.1.5 — адрес локальной сети", "Итог: напрямую: это адрес локальной сети, через туннель такие не ходят")
}

func TestExplain_ManyAddressesAreCapped(t *testing.T) {
	var ips []string
	for i := 1; i <= 12; i++ {
		ips = append(ips, fmt.Sprintf("198.51.100.%d", i))
	}
	env := explainTestEnv()
	env.resolve = resolvesTo(ips...)
	out := explainText(t, env, "many.example")
	mustHave(t, out, "198.51.100.8 — ", "…и ещё 4", "(так же и для остальных адресов: всего 12)")
	mustNotHave(t, out, "198.51.100.9 — ")
}

func TestExplain_AdaptiveSetUnreadableOnARouterIsSaid(t *testing.T) {
	env := explainTestEnv()
	env.members = func(context.Context) ([]adaptiveroute.Member, error) {
		return nil, errors.New("ipset: нет такого набора")
	}
	mustHave(t, explainText(t, env, "198.51.100.1"), "адаптивный набор прочитать не удалось: ipset: нет такого набора")

	// With adaptive routing off the set may simply not exist: nothing to warn about.
	env.cfg.AdaptiveRoute.Enabled = false
	mustNotHave(t, explainText(t, env, "198.51.100.1"), "прочитать не удалось")
}

func TestExplain_L7NeedsBothSwitches(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"example.org"}}}, nil
	}
	env.cfg.L7SNI.Enabled = false
	mustHave(t, explainText(t, env, "example.org"), "L7 (по имени): выключен (нужны L7 SNI и адаптивная маршрутизация)")
	env.cfg.L7SNI.Enabled = true
	mustHave(t, explainText(t, env, "example.org"), "L7 (по имени): увидит имя (ClientHello, HTTP Host)")
	env.cfg.AdaptiveRoute.Enabled = false
	mustHave(t, explainText(t, env, "example.org"), "L7 (по имени): выключен")
}

func TestExplain_RouterFollowsACNAMEChain(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.cname = func(context.Context, string) (string, error) { return "Edge.CDN.example.net.", nil }
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"cdn.example.net"}}}, nil
	}
	out := explainText(t, env, "www.example.com")
	mustHave(t, out,
		"Имя → 203.0.113.9 (DNS роутера; CNAME: edge.cdn.example.net)",
		"«domain-list3» → Wireguard0 (в наш xray): cdn.example.net (через CNAME edge.cdn.example.net)",
		"Итог: в туннель по списку «domain-list3» → Wireguard0",
		// L7 reads the name out of the connection and knows nothing of CNAMEs.
		"L7 (по имени): самого имени в списках нет (список «domain-list3» покрывает его CNAME edge.cdn.example.net)",
		"DNS-маршрут работает")
}

func TestExplain_ACNAMEThatEqualsTheNameOrFailsIsIgnored(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list3", Iface: "Wireguard0", Entries: []string{"example.org"}}}, nil
	}
	env.cname = func(context.Context, string) (string, error) { return "example.org.", nil } // no chain: the name itself
	out := explainText(t, env, "example.org")
	mustNotHave(t, out, "CNAME")
	mustHave(t, out, "«domain-list3» → Wireguard0 (в наш xray): example.org\n")

	env.cname = func(context.Context, string) (string, error) { return "", errors.New("SERVFAIL") }
	mustNotHave(t, explainText(t, env, "example.org"), "CNAME")
}

func TestExplain_ConfigListThatCoversOnlyTheCNAMEIsNotApplied(t *testing.T) {
	env := explainTestEnv()
	env.cfg.Routing.Lists = []config.RouteList{{Name: "cdn", Entries: []string{"cdn.example.net"}}}
	env.resolve = resolvesTo("203.0.113.9")
	env.cname = func(context.Context, string) (string, error) { return "edge.cdn.example.net.", nil }
	out := explainText(t, env, "www.example.com")
	mustHave(t, out, "список «cdn» из конфига покрывает имя, но на роутере его группы нет — список не применён")
}

// A list of subnets routes by address, with no DNS involved: the "works while
// the client asks the router's DNS" caveat belongs to name entries only.
func TestExplain_DNSCaveatOnlyForNameEntries(t *testing.T) {
	env := explainTestEnv()
	env.resolve = resolvesTo("149.154.167.51")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: "domain-list2", Iface: "Wireguard0", Entries: []string{"149.154.160.0/20"}}}, nil
	}
	out := explainText(t, env, "t.me")
	mustHave(t, out, "Итог: в туннель по списку «domain-list2» → Wireguard0")
	mustNotHave(t, out, "DNS-маршрут работает")
}

// Go's LookupCNAME gives the first target only; the router follows the whole
// chain, so explain has to as well.
func TestFollowCNAME_WalksToTheEndOfTheChain(t *testing.T) {
	chain := map[string]string{"www.a.com": "x.cdn1.net.", "x.cdn1.net": "Y.cdn2.net.", "y.cdn2.net": "y.cdn2.net."}
	calls := 0
	got, err := followCNAME(context.Background(), "www.a.com", func(_ context.Context, n string) (string, error) {
		calls++
		return chain[n], nil
	})
	if err != nil || got != "y.cdn2.net" {
		t.Fatalf("followCNAME = %q, %v; want y.cdn2.net", got, err)
	}
	if calls != 3 {
		t.Errorf("%d lookups, want 3 (stops when a name is its own canonical name)", calls)
	}

	// No chain at all, and a failure on the first hop is the caller's error.
	if got, err := followCNAME(context.Background(), "plain.example", func(context.Context, string) (string, error) { return "plain.example.", nil }); err != nil || got != "plain.example" {
		t.Errorf("no chain: %q, %v", got, err)
	}
	if _, err := followCNAME(context.Background(), "x.example", func(context.Context, string) (string, error) { return "", errors.New("SERVFAIL") }); err == nil {
		t.Error("a failing first lookup must be reported")
	}
	// A failure further along keeps what was found; a loop is cut off.
	n := 0
	got, err = followCNAME(context.Background(), "a.example", func(context.Context, string) (string, error) {
		n++
		if n == 2 {
			return "", errors.New("timeout")
		}
		return "b.example", nil
	})
	if err != nil || got != "b.example" {
		t.Errorf("failure mid-chain: %q, %v; want b.example", got, err)
	}
	loops := 0
	if _, err := followCNAME(context.Background(), "a.example", func(_ context.Context, n string) (string, error) {
		loops++
		return "z" + n, nil // never ends
	}); err != nil || loops != explainMaxCNAMEHops {
		t.Errorf("a runaway chain: %d lookups (err %v), want exactly %d", loops, err, explainMaxCNAMEHops)
	}
}

// A config list whose group IS on the router but routes nowhere is a different
// problem from one that was never applied.
func TestExplain_UnroutedGroupIsNotReportedAsNotApplied(t *testing.T) {
	env := explainTestEnv()
	env.cfg.Routing.Lists = []config.RouteList{{Name: "tg", Entries: []string{"x.com"}}}
	env.resolve = resolvesTo("203.0.113.9")
	env.routes = func(context.Context) ([]keenetic.LiveRoute, error) {
		return []keenetic.LiveRoute{{Group: keenetic.RouteGroupPrefix + "tg", Iface: "", Entries: []string{"x.com"}}}, nil
	}
	mustNotHave(t, explainText(t, env, "x.com"), "не применён")
}
