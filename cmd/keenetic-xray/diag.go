package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/adaptiveroute"
	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

// cmdDiag prints a one-shot diagnostic bundle to stdout: version, the
// config with every secret redacted, resolver / addon / RCI / Keenetic
// state, disk, and the tail of the daemon log. Safe to redirect to a
// file or paste into a chat. `keenetic-xray diag` on the router; the
// bot's diag action returns the same text.
func cmdDiag(args []string) error {
	writeDiag(os.Stdout)
	return nil
}

func writeDiag(w io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Fprintf(w, "==== keenetic-xray diag  %s ====\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "agent:     %s\n", version.String())
	if v, err := xrayCoreVersion(); err == nil {
		fmt.Fprintf(w, "xray-core: %s\n", v)
	} else {
		fmt.Fprintf(w, "xray-core: %v\n", err)
	}
	fmt.Fprintf(w, "arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if free, err := diskspace.FreeBytes(optPath()); err == nil {
		fmt.Fprintf(w, "free %s:  %d MB\n", optPath(), free/1024/1024)
	}

	cfg, cfgErr := config.Load(configPath())

	fmt.Fprintln(w, "\n---- config (secrets redacted) ----")
	if cfgErr != nil {
		fmt.Fprintf(w, "load %s: %v\n", configPath(), cfgErr)
	} else {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false) // a diag bundle is read by humans; keep <redacted> literal
		_ = enc.Encode(cfg.Redacted())
	}

	fmt.Fprintln(w, "\n---- local resolvers ----")
	rh := addons.ResolverHealth(ctx)
	if len(rh) == 0 {
		fmt.Fprintln(w, "(нет установленных unbound/dnscrypt)")
	}
	for _, r := range rh {
		if r.Resolves {
			fmt.Fprintf(w, "%s: резолвит на 127.0.0.1:%d\n", r.ID, r.Port)
		} else {
			fmt.Fprintf(w, "%s: НЕ резолвит на 127.0.0.1:%d (%s)\n", r.ID, r.Port, r.Detail)
		}
	}

	fmt.Fprintln(w, "\n---- addons ----")
	for _, a := range addons.All() {
		st := a.Detect(ctx)
		state := "не установлен"
		if st.Installed {
			state = "установлен"
			if st.HasDaemon {
				if st.Running {
					state += ", работает"
				} else {
					state += ", остановлен"
				}
			}
			if st.Detail != "" {
				state += " · " + st.Detail
			}
		}
		fmt.Fprintf(w, "%-10s %s\n", a.ID(), state)
	}

	fmt.Fprintln(w, "\n---- rci ----")
	if cfgErr == nil && cfg.RCI.Enabled {
		if base, _, err := rciProbe(cfg.RCI.BaseURL()); err == nil {
			fmt.Fprintf(w, "включён, отвечает: %s\n", base)
		} else {
			fmt.Fprintf(w, "включён, но: %v\n", err)
		}
	} else {
		fmt.Fprintln(w, "выключен (читаем через ndmc)")
	}

	fmt.Fprintln(w, "\n---- keenetic ----")
	if !keenetic.Available() {
		fmt.Fprintln(w, "ndmc/RCI недоступны — не на роутере")
	} else if maj, min, patch, err := keenetic.OSVersion(ctx); err == nil {
		fmt.Fprintf(w, "KeeneticOS %d.%d.%d\n", maj, min, patch)
	} else {
		fmt.Fprintf(w, "show version: %v\n", err)
	}

	fmt.Fprintln(w, "\n---- memory ----")
	writeDiagMemory(w)

	if cfgErr == nil {
		fmt.Fprintln(w, "\n---- proxy0 / xray inbounds ----")
		writeDiagProxy0(ctx, w, cfg)
	}

	if keenetic.Available() {
		fmt.Fprintln(w, "\n---- dns-proxy routes (all lists, with what they resolve to now) ----")
		writeDiagRoutes(ctx, w)
	}

	fmt.Fprintln(w, "\n---- iptables: this project's rules ----")
	writeDiagIptables(ctx, w)

	fmt.Fprintln(w, "\n---- listening ports ----")
	if cfgErr != nil {
		fmt.Fprintf(w, "config not loaded: %v\n", cfgErr)
	} else {
		type portCheck struct {
			name string
			port int
		}
		checks := []portCheck{{"SOCKS", cfg.Failover.SOCKSPort}, {"HTTP", cfg.Failover.HTTPPort}}
		if cfg.AdaptiveRoute.Enabled {
			checks = append(checks, portCheck{"transparent-in (dokodemo-door)", cfg.AdaptiveRoute.EffectivePort()})
		}
		for _, c := range checks {
			state := "НЕ слушает"
			if diagPortListening(c.port) {
				state = "слушает"
			}
			fmt.Fprintf(w, ":%-5d %-30s %s\n", c.port, c.name, state)
		}
	}

	if cfgErr == nil && cfg.AdaptiveRoute.Enabled && keenetic.Available() {
		fmt.Fprintln(w, "\n---- adaptive-route dataplane ----")
		if iface, _, err := adaptiveRouteLAN(ctx, cfg); err != nil {
			fmt.Fprintf(w, "LAN detection: %v\n", err)
		} else {
			opts := adaptiveroute.RedirectOptions{
				SetName:       adaptiveroute.RedirectSetName,
				Port:          cfg.AdaptiveRoute.EffectivePort(),
				LANInterfaces: []string{iface},
			}
			redirect := "НЕ активен"
			if adaptiveroute.RedirectInPlace(ctx, opts) {
				redirect = "активен"
			}
			fmt.Fprintf(w, "REDIRECT (%s): %s\n", iface, redirect)
			if members, err := adaptiveroute.Members(ctx, adaptiveroute.RedirectSetName); err == nil {
				fmt.Fprintf(w, "ipset %s: %d записей\n", adaptiveroute.RedirectSetName, len(members))
			} else {
				fmt.Fprintf(w, "ipset %s: %v\n", adaptiveroute.RedirectSetName, err)
			}
		}
	}

	fmt.Fprintln(w, "\n---- watchdog ----")
	fmt.Fprintln(w, watchdogStatusText())

	fmt.Fprintln(w, "\n---- daemon log (last 80) ----")
	if tail, err := applog.Tail(daemonLogPath(), 80); err == nil {
		s := strings.TrimRight(tail, "\n")
		if s == "" {
			fmt.Fprintln(w, "(пусто)")
		} else {
			fmt.Fprintln(w, s)
		}
	} else {
		fmt.Fprintf(w, "%s: %v\n", daemonLogPath(), err)
	}
	fmt.Fprintln(w, "\n==== end ====")
}

// diagPortListening reports whether something accepts TCP on
// 127.0.0.1:port -- reaches a 0.0.0.0 bind too, loopback still connects.
// Separate copy of internal/botcontrol's own portListening: this project
// deliberately keeps the CLI and bot diagnostics as independent
// implementations (see cmdStatus's doc comment) rather than reaching
// into botcontrol from package main.
func diagPortListening(port int) bool {
	if port <= 0 {
		return false
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 400*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// writeDiagProxy0 is where client traffic meets xray: the Proxy
// interface's upstream and health check, and what the production xray
// actually listens on -- loopback while Proxy0 points at the LAN IP is
// the "connection refused" #277 fixed.
func writeDiagProxy0(ctx context.Context, w io.Writer, cfg *config.Config) {
	iface := cfg.Proxy0.IfaceName()
	fmt.Fprintf(w, "proxy0.enabled: %v, interface %s, inbound port %d\n", cfg.Proxy0.Enabled, iface, cfg.Proxy0Port())
	if keenetic.Available() {
		host, port, ok, err := keenetic.Proxy0Upstream(ctx, cfg.Proxy0.Interface)
		switch {
		case err != nil:
			fmt.Fprintf(w, "%s upstream: %v\n", iface, err)
		case !ok:
			fmt.Fprintf(w, "%s upstream: не задан\n", iface)
		case port != cfg.Proxy0Port():
			fmt.Fprintf(w, "%s upstream: %s:%d — не наш вход\n", iface, host, port)
		default:
			fmt.Fprintf(w, "%s upstream: %s:%d (наш вход)\n", iface, host, port)
			_, msg := proxy0HealthLine(ctx, cfg)
			fmt.Fprintln(w, msg)
		}
	}
	b, err := os.ReadFile(productionConfigPath())
	if err != nil {
		fmt.Fprintf(w, "xray inbounds: %v\n", err)
		return
	}
	var xc struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(b, &xc); err != nil {
		fmt.Fprintf(w, "xray inbounds: %s: %v\n", productionConfigPath(), err)
		return
	}
	for _, in := range xc.Inbounds {
		fmt.Fprintf(w, "xray inbound %-16s %s:%d (%s)\n", in.Tag, in.Listen, in.Port, in.Protocol)
	}
}

// writeDiagRoutes lists every dns-proxy route list, the operator's own
// included, with how many addresses and names each one holds right now
// -- KeeneticOS adds CNAME targets under a listed zone, so a list's own
// entries undersell what it sends into the tunnel.
func writeDiagRoutes(ctx context.Context, w io.Writer) {
	routes, err := keenetic.AllRoutes(ctx)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	if len(routes) == 0 {
		fmt.Fprintln(w, "(списков нет)")
		return
	}
	counts, cerr := keenetic.ObjectGroupCounts(ctx)
	for _, r := range routes {
		to := r.Iface
		if to == "" {
			to = "(без маршрута)"
		}
		if r.Reject {
			to += " reject"
		}
		now := ""
		if c, ok := counts[r.Group]; ok {
			now = fmt.Sprintf("  сейчас: %d IPv4, %d IPv6, %d имён", c.IPv4, c.IPv6, c.FQDN)
		}
		fmt.Fprintf(w, "%-28s -> %-16s записей %-4d%s\n", r.Group, to, len(r.Entries), now)
	}
	if cerr != nil {
		fmt.Fprintf(w, "счётчики: %v\n", cerr)
	}
}

// writeDiagIptables prints this project's own iptables rules -- the ones
// tagged keenetic-xray-*: adaptive routing's REDIRECT (nat), the MSS
// clamp (mangle), l7sni's NFLOG (filter). A rule missing here that the
// config wants is ndm having dropped it (see the netfilter.d hook).
func writeDiagIptables(ctx context.Context, w io.Writer) {
	if _, err := exec.LookPath("iptables-save"); err != nil {
		fmt.Fprintln(w, "iptables-save не найден")
		return
	}
	found := false
	for _, table := range []string{"nat", "mangle", "filter"} {
		out, err := exec.CommandContext(ctx, "iptables-save", "-t", table).Output()
		if err != nil {
			fmt.Fprintf(w, "%s: %v\n", table, err)
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "keenetic-xray-") {
				fmt.Fprintf(w, "%-7s %s\n", table+":", line)
				found = true
			}
		}
	}
	if !found {
		fmt.Fprintln(w, "(наших правил нет)")
	}
}
