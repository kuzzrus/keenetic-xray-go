package addons

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func init() { Register(&unboundAddon{}) }

// unbound is a local recursive DNS resolver: it talks to the root
// servers directly instead of trusting an upstream that can be poisoned.
// Two modes:
//
//	local  (default) -- listens on 127.0.0.1:<port> (5353); nothing on
//	        the router uses it yet, it's just there.
//	router (router-dns=on) -- listens on 0.0.0.0:53 and KeeneticOS's
//	        `opkg dns-override` is set, so every device on the LAN
//	        resolves through unbound instead of the ISP. Removing the
//	        component (or router-dns=off) reverts the override and moves
//	        unbound back to the local port.
const (
	unboundPkg      = "unbound-daemon"
	unboundInit     = "S61unbound"
	unboundConf     = "/opt/etc/unbound/unbound.conf"
	unboundDefPort  = 5353
	unboundRtrPort  = 53
	unboundDefCache = 8                    // MB, per rrset/msg cache
	unboundRtrMark  = "interface: 0.0.0.0" // present in the conf iff in router mode
)

type unboundAddon struct{}

func (*unboundAddon) ID() string    { return "unbound" }
func (*unboundAddon) Title() string { return "unbound — рекурсивный DNS" }

func (*unboundAddon) About() string {
	return "Локальный рекурсивный резолвер unbound: сам ходит по корневым серверам, а не " +
		"доверяет провайдерскому DNS, который может подменять ответы. Проверяет DNSSEC.\n\n" +
		"Настройки (addon configure unbound …):\n" +
		"  router-dns=on|off  сделать unbound резолвером всего роутера (0.0.0.0:53 +\n" +
		"                     opkg dns-override) или вернуть встроенный dns-proxy\n" +
		"  port=5353          локальный порт (в режиме router-dns игнорируется — там 53)\n" +
		"  cache=8            размер кэша, МБ (на каждый из rrset/msg)\n" +
		"  dnssec=on|off      проверка DNSSEC\n\n" +
		"При удалении компонента, если он был резолвером роутера, dns-override снимается " +
		"автоматически — роутер возвращается на свой dns-proxy."
}

// unboundState reads the current conf.
type unboundState struct {
	installed  bool
	version    string
	port       int
	cacheMB    int
	dnssec     bool
	routerMode bool
}

func unboundRead(ctx context.Context) unboundState {
	st := unboundState{port: unboundDefPort, cacheMB: unboundDefCache, dnssec: true}
	st.version = opkgInstalledVersion(ctx, unboundPkg)
	st.installed = st.version != ""
	body, err := readFile(unboundConf)
	if err != nil {
		return st
	}
	s := string(body)
	st.routerMode = strings.Contains(s, unboundRtrMark)
	if n := unboundGrepInt(s, "port:"); n > 0 {
		st.port = n
	}
	if strings.Contains(s, "val-permissive-mode: yes") {
		st.dnssec = false
	}
	if n := unboundGrepInt(s, "msg-cache-size:"); n > 0 {
		st.cacheMB = n / (1024 * 1024)
	}
	return st
}

func (*unboundAddon) Detect(ctx context.Context) State {
	u := unboundRead(ctx)
	st := State{Installed: u.installed, Version: u.version, HasDaemon: true}
	if !u.installed {
		return st
	}
	st.Running = portListening(ctx, u.port)
	if u.routerMode {
		st.Detail = "резолвер роутера, 0.0.0.0:53"
	} else {
		st.Detail = fmt.Sprintf("локально, 127.0.0.1:%d", u.port)
	}
	return st
}

func (*unboundAddon) Install(ctx context.Context) error {
	if err := opkgInstall(ctx, unboundPkg); err != nil {
		return err
	}
	if _, err := readFile(unboundConf); err != nil {
		if err := writeFile(unboundConf, []byte(unboundConfBody(unboundDefPort, unboundDefCache, true, false)), 0o644); err != nil {
			return fmt.Errorf("запись %s: %w", unboundConf, err)
		}
	}
	if _, err := initdRun(ctx, unboundInit, "start"); err != nil {
		return fmt.Errorf("unbound не запустился: %w", err)
	}
	return nil
}

func (*unboundAddon) Remove(ctx context.Context) error {
	u := unboundRead(ctx)
	// If unbound was the router's resolver, hand DNS back BEFORE pulling
	// the package -- otherwise the LAN is left with no resolver at all. A
	// failure here IS fatal to the removal (better to stop than strand
	// the router without DNS).
	if u.routerMode || (keeneticAvailable() && overrideOn(ctx)) {
		if err := setRouterDNSOverride(ctx, false); err != nil {
			return fmt.Errorf("сначала снимаю opkg dns-override, чтобы роутер не остался без DNS — не вышло: %w", err)
		}
	}
	_, _ = initdRun(ctx, unboundInit, "stop")
	return opkgRemove(ctx, unboundPkg)
}

func (*unboundAddon) Configure(ctx context.Context, kv map[string]string) error {
	u := unboundRead(ctx)
	if !u.installed {
		return fmt.Errorf("unbound не установлен")
	}
	port, cache, dnssec, router := u.port, u.cacheMB, u.dnssec, u.routerMode
	switchRouter := "" // "", "on", "off"

	for k, v := range kv {
		switch k {
		case "router-dns":
			switch v {
			case "on", "yes", "true":
				switchRouter, router = "on", true
			case "off", "no", "false":
				switchRouter, router = "off", false
			default:
				return fmt.Errorf("router-dns=%q: on или off", v)
			}
		case "port":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("port=%q вне диапазона", v)
			}
			port = n
		case "cache":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 64 {
				return fmt.Errorf("cache=%q: 1..64 МБ", v)
			}
			cache = n
		case "dnssec":
			switch v {
			case "on", "yes", "true":
				dnssec = true
			case "off", "no", "false":
				dnssec = false
			default:
				return fmt.Errorf("dnssec=%q: on или off", v)
			}
		default:
			return fmt.Errorf("неизвестный ключ %q (см. `addon show unbound`)", k)
		}
	}

	if router {
		port = unboundRtrPort // router mode always owns :53
	}

	writeConf := func() error {
		if err := writeFile(unboundConf, []byte(unboundConfBody(port, cache, dnssec, router)), 0o644); err != nil {
			return err
		}
		if _, err := initdRun(ctx, unboundInit, "restart"); err != nil {
			return fmt.Errorf("unbound не перезапустился: %w", err)
		}
		return nil
	}

	switch switchRouter {
	case "on":
		// Free :53 first (dns-proxy stands down), then bring unbound up on it.
		if !keeneticAvailable() {
			return fmt.Errorf("router-dns требует роутер Keenetic (ndmc не найден)")
		}
		if err := setRouterDNSOverride(ctx, true); err != nil {
			return fmt.Errorf("opkg dns-override: %w", err)
		}
		if err := writeConf(); err != nil {
			// roll the override back so the LAN isn't left dark
			_ = setRouterDNSOverride(ctx, false)
			return err
		}
	case "off":
		// Move unbound off :53 first, then let dns-proxy reclaim it.
		if err := writeConf(); err != nil {
			return err
		}
		if keeneticAvailable() {
			if err := setRouterDNSOverride(ctx, false); err != nil {
				return fmt.Errorf("не смог снять opkg dns-override: %w", err)
			}
		}
	default:
		if err := writeConf(); err != nil {
			return err
		}
	}
	return nil
}

func (*unboundAddon) Status(ctx context.Context) (string, error) {
	u := unboundRead(ctx)
	if !u.installed {
		return "unbound не установлен", nil
	}
	var b strings.Builder
	if portListening(ctx, u.port) {
		fmt.Fprintf(&b, "unbound: слушает %s:%d\n", ifaceForMode(u.routerMode), u.port)
	} else {
		fmt.Fprintf(&b, "unbound: установлен, но на порту %d тишина (проверь `%s/%s status`)\n", u.port, initdDir, unboundInit)
	}
	if u.routerMode {
		b.WriteString("режим: резолвер всего роутера (opkg dns-override)\n")
		if keeneticAvailable() {
			if on := overrideOn(ctx); !on {
				b.WriteString("⚠️ но `opkg dns-override` на роутере НЕ активен — примени `addon configure unbound router-dns=on` заново\n")
			}
		}
	} else {
		b.WriteString("режим: локальный (роутер этим резолвером не пользуется; включить: addon configure unbound router-dns=on)\n")
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func ifaceForMode(routerMode bool) string {
	if routerMode {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// overrideOn is routerDNSOverrideOn with the error swallowed to a bool.
func overrideOn(ctx context.Context) bool {
	on, err := routerDNSOverrideOn(ctx)
	return err == nil && on
}

func unboundGrepInt(body, key string) int {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, key); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// unboundConfBody renders the recursive-resolver config. routerMode
// widens the listen address to 0.0.0.0 and opens access-control to
// RFC1918 so LAN clients can use it.
func unboundConfBody(port, cacheMB int, dnssec, routerMode bool) string {
	bytesPerCache := cacheMB * 1024 * 1024
	dnssecLine := `auto-trust-anchor-file: "/opt/etc/unbound/root.key"`
	if !dnssec {
		dnssecLine = "val-permissive-mode: yes  # dnssec: off"
	}
	listen := "    interface: 127.0.0.1\n    access-control: 127.0.0.0/8 allow\n    access-control: 0.0.0.0/0 refuse"
	if routerMode {
		listen = "    interface: 0.0.0.0\n" +
			"    access-control: 127.0.0.0/8 allow\n" +
			"    access-control: 10.0.0.0/8 allow\n" +
			"    access-control: 172.16.0.0/12 allow\n" +
			"    access-control: 192.168.0.0/16 allow\n" +
			"    access-control: 0.0.0.0/0 refuse"
	}
	return fmt.Sprintf(`# Managed by keenetic-xray (addons: unbound). Regenerated on
# `+"`addon configure unbound …`"+` -- local edits do not stick.
server:
    verbosity: 0
%s
    port: %d
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    qname-minimisation: yes
    prefetch: yes
    prefetch-key: yes
    aggressive-nsec: yes
    rrset-cache-size: %d
    msg-cache-size: %d
    cache-min-ttl: 60
    cache-max-ttl: 86400
    num-threads: 1
    so-reuseport: yes
    %s
`, listen, port, bytesPerCache, bytesPerCache, dnssecLine)
}
