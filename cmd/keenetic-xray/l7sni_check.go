package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/l7capture"
)

// What the kernel does with the capture's rules, next to what the daemon's own
// counters say. The capture's counters stay at zero for two very different
// reasons -- no packet ever matches the iptables rules, or the rules fire and
// nothing arrives on the NFLOG socket -- and for two months nobody could tell
// which, because the only number anyone could read was the zero. (It was the
// first: the rules sat in a table the firmware's own ACCEPT rules end before.)
// The rules' own packet counters tell them apart at once, so every place that
// shows the counters shows these too.

// The points below are the only places this file touches the router, so a test
// can stand in for it.
var (
	// l7sniCheckEnabled: only on a router, and only while L7 SNI is on -- with
	// it off there are no rules, and "no rules" is not a finding.
	l7sniCheckEnabled = func() bool {
		if !keenetic.Available() {
			return false
		}
		cfg, err := config.Load(configPath())
		return err == nil && cfg.L7SNI.Enabled
	}
	l7sniRuleCounters = func(ctx context.Context) ([]l7capture.RuleStat, error) {
		return l7capture.RuleCounters(ctx, l7capture.DefaultGroup)
	}
	l7sniDefaultRoute = func() (string, error) { return l7capture.ResolveWANInterface("") }
)

// l7sniCaptureCheck is the text block for the places that show the counters: the
// kernel's count per rule and, when something is wrong, what. f is the stats
// file the daemon published, nil when there is none. Empty off a router and
// while L7 SNI is off.
func l7sniCaptureCheck(f *l7sniStatsFile) string {
	if !l7sniCheckEnabled() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stats, err := l7sniRuleCounters(ctx)
	wan, wanErr := l7sniDefaultRoute()
	return strings.Join(renderL7SNICaptureCheck(stats, err, wan, wanErr, f), "\n")
}

// l7sniRuleName is how a rule reads in the listing.
func l7sniRuleName(r l7capture.RuleStat) string {
	switch {
	case r.Proto == "udp" && r.DPort == 443:
		return "UDP/443 (QUIC)"
	default:
		return fmt.Sprintf("%s/%d", strings.ToUpper(r.Proto), r.DPort)
	}
}

// renderL7SNICaptureCheck lists the rules with their packet counts and says what
// the numbers mean. wan is the interface the default route goes out through now.
func renderL7SNICaptureCheck(stats []l7capture.RuleStat, statsErr error, wan string, wanErr error, f *l7sniStatsFile) []string {
	if statsErr != nil {
		return []string{"Правила захвата: не удалось прочитать счётчики iptables — " + statsErr.Error()}
	}
	var current, leftovers []l7capture.RuleStat
	for _, r := range stats {
		if r.Table == "mangle" {
			current = append(current, r)
		} else {
			leftovers = append(leftovers, r)
		}
	}

	var out []string
	if len(current) == 0 {
		out = append(out, "Правила захвата: в таблице mangle (цепочка FORWARD) их нет — демон ещё не поставил их или прошивка только что пересобрала таблицу.",
			"⚠️ Демон вернёт правила при ближайшей сверке (до 2 минут) или сразу, по сигналу хука NDM; если они не появляются — keenetic-xray logs 100 | grep l7sni")
	} else {
		out = append(out, "Правила захвата (iptables, таблица mangle, цепочка FORWARD) — сколько пакетов под них попало:")
		for _, r := range current {
			out = append(out, fmt.Sprintf("  %-15s → %s: пакетов %d", l7sniRuleName(r), r.Iface, r.Packets))
		}
	}
	if len(leftovers) > 0 {
		out = append(out, "⚠️ В таблице filter ещё стоят правила прошлой версии — они ничего не ловят; демон уберёт их при ближайшей сверке.")
	}
	if len(current) == 0 {
		return out
	}

	var total, tcp, quic uint64
	haveQUIC := false
	for _, r := range current {
		total += r.Packets
		if r.Proto == "udp" {
			quic += r.Packets
			haveQUIC = true
		} else {
			tcp += r.Packets
		}
	}
	var messages uint64
	if f != nil {
		messages = f.Messages
	}

	switch {
	case wanErr == nil && wan != "" && current[0].Iface != wan:
		out = append(out, fmt.Sprintf("⚠️ Правила стоят на %s, а наружу сейчас ведёт %s (default route) — демон переставит правила при ближайшей сверке.", current[0].Iface, wan))
	case total == 0:
		out = append(out, fmt.Sprintf("⚠️ Ни один пакет не попал под правила: с момента их установки клиенты не открыли ни одного нового соединения наружу через %s напрямую "+
			"(всё могло уйти в туннель, или в сети тихо). Откройте любой сайт с устройства в сети роутера и обновите.", current[0].Iface))
	case messages == 0:
		out = append(out, fmt.Sprintf("⚠️ Правила срабатывают (%d пакетов), а демон не получил из NFLOG ни одного — сокет захвата не принимает группу %d. Смотрите: keenetic-xray logs 100 | grep l7sni",
			total, l7capture.DefaultGroup))
	}
	if haveQUIC && quic == 0 && tcp >= 50 {
		out = append(out, fmt.Sprintf("QUIC: правило UDP/443 не сработало ни разу при %d срабатываниях TCP — клиенты не шлют QUIC наружу напрямую (браузер мог перейти на TCP) "+
			"либо окно connbytes 0:3 этой прошивке не подходит.", tcp))
	}
	return out
}
