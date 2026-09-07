package addons

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func init() { Register(&unboundAddon{}) }

// unbound is a local recursive DNS resolver: it talks to the root
// servers directly instead of trusting an upstream that can be poisoned.
// Two modes:
//
//	local  (default) -- listens on 127.0.0.1:5335. Nothing on the router
//	        uses it; it's just available.
//	router (router-dns=on) -- also listens on the LAN IP:5335 and
//	        KeeneticOS gets an `ip name-server <LAN-IP>:5335` entry, so
//	        the router's dns-proxy forwards to unbound. dns-proxy stays
//	        in the path (unlike `opkg dns-override`), so its DNS-name →
//	        route snooping -- the thing keenetic-xray's own domain
//	        routing lists rely on -- keeps working. Removing the
//	        component (or router-dns=off) drops the name-server entry.
//
// NB: if the router already has secure upstreams configured (dns-proxy
// tls/https upstream), dns-proxy may keep preferring those -- router-dns
// replaces a plain ISP resolver, it doesn't override DoT/DoH.
const (
	unboundPkg  = "unbound-daemon"
	unboundInit = "S61unbound"
	unboundConf = "/opt/etc/unbound/unbound.conf"
	// 5335 is the pi-hole+unbound convention -- it dodges :53 (Keenetic's
	// dns-proxy) and :5353 (Keenetic's mDNS responder), both of which are
	// already bound on this firmware. The stock Entware conf has no
	// `port:` line so it defaults to 53 and never starts here.
	unboundPort     = 5335
	unboundDefCache = 8 // MB, per rrset/msg cache
	unboundRtrMark  = "# mode: router"
	// unboundManagedMark tags a conf this component wrote, so Install
	// knows to replace a stock package conf rather than leave it.
	unboundManagedMark = "Managed by keenetic-xray"
)

// privateV4 reports whether s is a plain RFC1918 IPv4 -- the only thing
// valid as the router-mode listen address / name-server target.
func privateV4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil || ip.To4() == nil {
		return false
	}
	return ip.IsPrivate()
}

type unboundAddon struct{}

func (*unboundAddon) ID() string    { return "unbound" }
func (*unboundAddon) Title() string { return "unbound — рекурсивный DNS" }

func (*unboundAddon) About() string {
	return "Локальный рекурсивный резолвер unbound: сам ходит по корневым серверам, а не " +
		"доверяет провайдерскому DNS, который может подменять ответы. Проверяет DNSSEC.\n\n" +
		"Настройки (addon configure unbound …):\n" +
		"  router-dns=on|off  подключить unbound резолвером роутера: он слушает и на LAN-IP,\n" +
		"                     на роутер добавляется `ip name-server <LAN-IP>:5335`. dns-proxy\n" +
		"                     остаётся в цепочке — маршрутизация по доменам продолжает работать.\n" +
		"  cache=8            размер кэша, МБ (на каждый из rrset/msg)\n" +
		"  dnssec=on|off      проверка DNSSEC\n\n" +
		"При удалении компонента запись `ip name-server` снимается автоматически. " +
		"Если на dns-proxy настроены DoT/DoH-апстримы, роутер может продолжить ходить в них — " +
		"router-dns заменяет голый DNS провайдера, не DoH."
}

// unboundState is the current conf, as read.
type unboundState struct {
	installed  bool
	version    string
	port       int
	cacheMB    int
	dnssec     bool
	routerMode bool
	routerIP   string // the LAN IP the router-mode conf binds / the name-server entry uses
}

func unboundRead(ctx context.Context) unboundState {
	st := unboundState{port: unboundPort, cacheMB: unboundDefCache, dnssec: true}
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
	// routerIP is only meaningful for a conf WE put into router mode --
	// a stock package conf can carry `interface: ::0` etc. that must not
	// be mistaken for the router's LAN IP.
	if st.routerMode {
		for _, line := range strings.Split(s, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "interface:"); ok {
				if v = strings.TrimSpace(v); privateV4(v) {
					st.routerIP = v
				}
			}
		}
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
		st.Detail = fmt.Sprintf("резолвер роутера (%s:%d)", u.routerIP, u.port)
	} else {
		st.Detail = fmt.Sprintf("локально, 127.0.0.1:%d", u.port)
	}
	return st
}

func (*unboundAddon) Install(ctx context.Context) error {
	if err := opkgInstall(ctx, unboundPkg); err != nil {
		return err
	}
	// Replace a stock package conf (or a missing one) with ours -- the
	// router-mode logic reads its own markers back, and a stock conf can
	// carry an `interface: ::0` that must not leak into `ip name-server`.
	if body, err := readFile(unboundConf); err != nil || !strings.Contains(string(body), unboundManagedMark) {
		if err := writeFile(unboundConf, []byte(unboundConfBody(unboundDefCache, true, false, "")), 0o644); err != nil {
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
	// Best-effort: drop the name-server entry if we have a real IP for it.
	// A leftover entry just gives dns-proxy a dead upstream alongside its
	// working ones -- not worth aborting the removal over.
	if u.routerMode && keeneticAvailable() && privateV4(u.routerIP) {
		_ = setLocalNameServer(ctx, u.routerIP, u.port, false)
	}
	_, _ = initdRun(ctx, unboundInit, "stop")
	return opkgRemove(ctx, unboundPkg)
}

// routerLANIP resolves the LAN IP for a DNS component's router mode:
// `stored` (what our conf already recorded) if it's a valid RFC1918
// IPv4, else ask ndmc. Never returns a non-RFC1918 value. Shared by the
// unbound and dnscrypt components.
func routerLANIP(ctx context.Context, stored string) (string, error) {
	if privateV4(stored) {
		return stored, nil
	}
	if !keeneticAvailable() {
		return "", fmt.Errorf("router-dns требует роутер Keenetic (ndmc не найден)")
	}
	ip, err := keeneticLANIP(ctx, "")
	if err != nil {
		return "", fmt.Errorf("не удалось определить LAN IP роутера: %w", err)
	}
	if !privateV4(ip) {
		return "", fmt.Errorf("LAN IP роутера %q не похож на приватный IPv4", ip)
	}
	return ip, nil
}

func (*unboundAddon) Configure(ctx context.Context, kv map[string]string) error {
	u := unboundRead(ctx)
	if !u.installed {
		return fmt.Errorf("unbound не установлен")
	}
	cache, dnssec, router := u.cacheMB, u.dnssec, u.routerMode
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

	// The LAN IP the router-mode conf binds and the name-server points at.
	// Resolve it up front (and validate) so a bad value never reaches ndmc.
	var lanIP string
	if router {
		ip, err := routerLANIP(ctx, u.routerIP)
		if err != nil {
			return err
		}
		lanIP = ip
	}

	writeConf := func(rtr bool, ip string) error {
		if err := writeFile(unboundConf, []byte(unboundConfBody(cache, dnssec, rtr, ip)), 0o644); err != nil {
			return err
		}
		if _, err := initdRun(ctx, unboundInit, "restart"); err != nil {
			return fmt.Errorf("unbound не перезапустился: %w", err)
		}
		return nil
	}

	switch switchRouter {
	case "on":
		// Bring unbound up on the LAN IP first, then hand dns-proxy the
		// name-server -- dns-proxy keeps serving from its existing
		// upstreams throughout, so there's no DNS gap.
		if err := writeConf(true, lanIP); err != nil {
			return err
		}
		if err := setLocalNameServer(ctx, lanIP, u.port, true); err != nil {
			_ = writeConf(false, "") // roll back to local so we're not half-on
			return fmt.Errorf("ip name-server %s:%d: %w", lanIP, u.port, err)
		}
	case "off":
		// Best-effort name-server removal: use the IP the conf recorded;
		// if it's junk (recovering from a bad state) just skip it -- the
		// important part is getting the conf back to local.
		if keeneticAvailable() && privateV4(u.routerIP) {
			if err := setLocalNameServer(ctx, u.routerIP, u.port, false); err != nil {
				_ = writeConf(false, "")
				return fmt.Errorf("вернул конфиг в локальный режим, но `ip name-server %s:%d` убрать не вышло — сними вручную: %w", u.routerIP, u.port, err)
			}
		}
		if err := writeConf(false, ""); err != nil {
			return err
		}
	default:
		if err := writeConf(router, lanIP); err != nil {
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
		fmt.Fprintf(&b, "unbound: слушает :%d\n", u.port)
	} else {
		fmt.Fprintf(&b, "unbound: установлен, но на :%d тишина (проверь `%s/%s status`)\n", u.port, initdDir, unboundInit)
	}
	if u.routerMode {
		fmt.Fprintf(&b, "режим: резолвер роутера — dns-proxy форвардит на %s:%d\n", u.routerIP, u.port)
		if keeneticAvailable() && u.routerIP != "" {
			if on, _ := localNameServerActive(ctx, u.routerIP, u.port); !on {
				b.WriteString("⚠️ но `ip name-server` на роутере не найден — примени `addon configure unbound router-dns=on` заново\n")
			}
		}
		b.WriteString("(если на dns-proxy есть DoT/DoH-апстримы, роутер может ходить в них — сними их вручную для полного перехода на unbound)\n")
	} else {
		b.WriteString("режим: локальный (роутер этим резолвером не пользуется; включить: addon configure unbound router-dns=on)\n")
	}
	return strings.TrimRight(b.String(), "\n"), nil
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

// unboundConfBody renders the recursive-resolver config. In router mode
// it also binds the LAN IP and opens access-control to RFC1918 so
// dns-proxy (and, incidentally, LAN clients) can reach it.
func unboundConfBody(cacheMB int, dnssec, routerMode bool, lanIP string) string {
	bytesPerCache := cacheMB * 1024 * 1024
	dnssecLine := `auto-trust-anchor-file: "/opt/etc/unbound/root.key"`
	if !dnssec {
		dnssecLine = "val-permissive-mode: yes  # dnssec: off"
	}
	marker := ""
	listen := "    interface: 127.0.0.1\n" +
		"    access-control: 127.0.0.0/8 allow\n" +
		"    access-control: 0.0.0.0/0 refuse"
	if routerMode {
		marker = unboundRtrMark + "\n"
		listen = "    interface: 127.0.0.1\n" +
			"    interface: " + lanIP + "\n" +
			"    access-control: 127.0.0.0/8 allow\n" +
			"    access-control: 10.0.0.0/8 allow\n" +
			"    access-control: 172.16.0.0/12 allow\n" +
			"    access-control: 192.168.0.0/16 allow\n" +
			"    access-control: 0.0.0.0/0 refuse"
	}
	return fmt.Sprintf(`# Managed by keenetic-xray (addons: unbound). Regenerated on
# `+"`addon configure unbound …`"+` -- local edits do not stick.
%sserver:
    verbosity: 1
    use-syslog: yes
    username: ""
    chroot: ""
    directory: "/opt/var/lib/unbound"
    pidfile: "/opt/var/run/unbound.pid"
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    port: %d
%s
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
    %s
`, marker, unboundPort, listen, bytesPerCache, bytesPerCache, dnssecLine)
}
