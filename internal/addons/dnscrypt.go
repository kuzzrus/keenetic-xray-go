package addons

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func init() { Register(&dnscryptAddon{}) }

// dnscrypt is dnscrypt-proxy2 (github.com/DNSCrypt/dnscrypt-proxy) as a
// local encrypted resolver: it talks to public resolvers over DNSCrypt
// or DoH, with an optional anonymized-DNS relay hop so the resolver
// never sees the client's IP. Like the unbound component it plugs into
// the router via `ip name-server <LAN-IP>:<port>` (router-dns=on), so
// KeeneticOS's dns-proxy stays in the path and domain routing keeps
// working. Compared to unbound's plain recursion this hides the queries
// from the ISP too, at the cost of trusting the chosen resolver.
const (
	dnscryptPkg      = "dnscrypt-proxy2"
	dnscryptInit     = "S09dnscrypt-proxy2"
	dnscryptConf     = "/opt/etc/dnscrypt-proxy.toml"
	dnscryptCacheDir = "/opt/var/lib/dnscrypt-proxy"
	// 65053: dnscrypt-proxy's own community-recommended "behind a
	// forwarder" port, clear of :53 (dns-proxy) and :5353 (mDNS).
	dnscryptPort = 65053
	dnscryptMark = "# keenetic-xray: router-dns"
	// minisignKey is the well-known signing key for the public resolver
	// and relay lists -- stable, published by the dnscrypt-proxy project.
	dnscryptMinisign = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
)

type dnscryptAddon struct{}

func (*dnscryptAddon) ID() string { return "dnscrypt" }
func (*dnscryptAddon) Title() string {
	return "dnscrypt-proxy — шифрованный DNS + анонимизация"
}

func (*dnscryptAddon) About() string {
	return "Локальный шифрованный резолвер dnscrypt-proxy2: запросы уходят к публичным резолверам " +
		"по DNSCrypt/DoH — провайдер не видит и не подменяет. С анонимизацией (relay-хоп) сам " +
		"резолвер тоже не видит твой IP.\n\n" +
		"Настройки (addon configure dnscrypt …):\n" +
		"  router-dns=on|off  подключить как резолвер роутера (слушает LAN-IP, на роутер\n" +
		"                     добавляется `ip name-server <LAN-IP>:65053`). dns-proxy остаётся\n" +
		"                     в цепочке — маршрутизация по доменам продолжает работать.\n" +
		"  anonymized=on|off  прогонять запросы через relay, чтобы резолвер не знал твой IP\n" +
		"                     (по умолчанию on)\n" +
		"  dnssec=on|off      требовать резолверы с DNSSEC (по умолчанию on)\n\n" +
		"vs unbound: unbound сам рекурсит (никому не доверяет, но провайдер видит домены); " +
		"dnscrypt шифрует запросы к выбранному резолверу. При удалении запись `ip name-server` " +
		"снимается автоматически."
}

type dnscryptState struct {
	installed  bool
	version    string
	port       int
	routerMode bool
	routerIP   string
	anonymized bool
	dnssec     bool
}

func dnscryptRead(ctx context.Context) dnscryptState {
	st := dnscryptState{port: dnscryptPort, anonymized: true, dnssec: true}
	st.version = opkgInstalledVersion(ctx, dnscryptPkg)
	st.installed = st.version != ""
	body, err := readFile(dnscryptConf)
	if err != nil {
		return st
	}
	s := string(body)
	st.routerMode = strings.Contains(s, dnscryptMark)
	st.anonymized = strings.Contains(s, "[anonymized_dns]")
	if strings.Contains(s, "require_dnssec = false") {
		st.dnssec = false
	}
	// listen_addresses = ['127.0.0.1:65053', '192.168.1.1:65053']
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "listen_addresses") {
			continue
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
			return r == '[' || r == ']' || r == ',' || r == '\'' || r == '"' || r == ' ' || r == '='
		}) {
			host, portStr, ok := strings.Cut(tok, ":")
			if !ok {
				continue
			}
			if n, e := strconv.Atoi(portStr); e == nil && n > 0 {
				st.port = n
			}
			if privateV4(host) {
				st.routerIP = host
			}
		}
	}
	return st
}

func (*dnscryptAddon) Detect(ctx context.Context) State {
	d := dnscryptRead(ctx)
	st := State{Installed: d.installed, Version: d.version, HasDaemon: true}
	if !d.installed {
		return st
	}
	st.Running = portListening(ctx, d.port) || initStatusOK(ctx, dnscryptInit)
	switch {
	case d.routerMode && d.anonymized:
		st.Detail = fmt.Sprintf("резолвер роутера, анонимно (%s:%d)", d.routerIP, d.port)
	case d.routerMode:
		st.Detail = fmt.Sprintf("резолвер роутера (%s:%d)", d.routerIP, d.port)
	default:
		st.Detail = fmt.Sprintf("локально, 127.0.0.1:%d", d.port)
	}
	return st
}

func (*dnscryptAddon) Install(ctx context.Context) error {
	if err := opkgInstall(ctx, dnscryptPkg, "ca-certificates"); err != nil {
		return err
	}
	_ = mkdirAll(dnscryptCacheDir)
	if body, err := readFile(dnscryptConf); err != nil || !strings.Contains(string(body), unboundManagedMark) {
		if err := writeFile(dnscryptConf, []byte(dnscryptConfBody(false, "", true, true)), 0o644); err != nil {
			return fmt.Errorf("запись %s: %w", dnscryptConf, err)
		}
	}
	if _, err := initdRun(ctx, dnscryptInit, "start"); err != nil {
		return fmt.Errorf("dnscrypt-proxy не запустился: %w", err)
	}
	return nil
}

func (*dnscryptAddon) Remove(ctx context.Context) error {
	d := dnscryptRead(ctx)
	if d.routerMode && keeneticAvailable() && privateV4(d.routerIP) {
		_ = setLocalNameServer(ctx, d.routerIP, d.port, false)
	}
	_, _ = initdRun(ctx, dnscryptInit, "stop")
	return opkgRemove(ctx, dnscryptPkg)
}

func (*dnscryptAddon) Configure(ctx context.Context, kv map[string]string) error {
	d := dnscryptRead(ctx)
	if !d.installed {
		return fmt.Errorf("dnscrypt-proxy не установлен")
	}
	anon, dnssec, router := d.anonymized, d.dnssec, d.routerMode
	switchRouter := ""

	for k, v := range kv {
		on, err := parseOnOff(v)
		switch k {
		case "router-dns":
			if err != nil {
				return fmt.Errorf("router-dns=%q: on или off", v)
			}
			router = on
			if on {
				switchRouter = "on"
			} else {
				switchRouter = "off"
			}
		case "anonymized":
			if err != nil {
				return fmt.Errorf("anonymized=%q: on или off", v)
			}
			anon = on
		case "dnssec":
			if err != nil {
				return fmt.Errorf("dnssec=%q: on или off", v)
			}
			dnssec = on
		default:
			return fmt.Errorf("неизвестный ключ %q (см. `addon show dnscrypt`)", k)
		}
	}

	var lanIP string
	if router {
		ip, err := routerLANIP(ctx, d.routerIP)
		if err != nil {
			return err
		}
		lanIP = ip
	}

	writeConf := func(rtr bool, ip string) error {
		if err := writeFile(dnscryptConf, []byte(dnscryptConfBody(rtr, ip, anon, dnssec)), 0o644); err != nil {
			return err
		}
		if _, err := initdRun(ctx, dnscryptInit, "restart"); err != nil {
			return fmt.Errorf("dnscrypt-proxy не перезапустился: %w", err)
		}
		return nil
	}

	switch switchRouter {
	case "on":
		if err := writeConf(true, lanIP); err != nil {
			return err
		}
		if err := setLocalNameServer(ctx, lanIP, d.port, true); err != nil {
			_ = writeConf(false, "")
			return fmt.Errorf("ip name-server %s:%d: %w", lanIP, d.port, err)
		}
	case "off":
		if keeneticAvailable() && privateV4(d.routerIP) {
			if err := setLocalNameServer(ctx, d.routerIP, d.port, false); err != nil {
				_ = writeConf(false, "")
				return fmt.Errorf("вернул конфиг в локальный режим, но `ip name-server %s:%d` не убрать — сними вручную: %w", d.routerIP, d.port, err)
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

func (*dnscryptAddon) Status(ctx context.Context) (string, error) {
	d := dnscryptRead(ctx)
	if !d.installed {
		return "dnscrypt-proxy не установлен", nil
	}
	var b strings.Builder
	if portListening(ctx, d.port) || initStatusOK(ctx, dnscryptInit) {
		fmt.Fprintf(&b, "dnscrypt-proxy: работает на :%d\n", d.port)
	} else {
		fmt.Fprintf(&b, "dnscrypt-proxy: установлен, но на :%d тишина (`%s/%s status`)\n", d.port, initdDir, dnscryptInit)
	}
	fmt.Fprintf(&b, "DNSSEC: %s · анонимизация: %s\n", onOff(d.dnssec), onOff(d.anonymized))
	if d.routerMode {
		fmt.Fprintf(&b, "режим: резолвер роутера — dns-proxy форвардит на %s:%d\n", d.routerIP, d.port)
		if keeneticAvailable() && d.routerIP != "" {
			if on, _ := localNameServerActive(ctx, d.routerIP, d.port); !on {
				b.WriteString("⚠️ `ip name-server` на роутере не найден — примени `router-dns=on` заново\n")
			}
		}
	} else {
		b.WriteString("режим: локальный (включить: addon configure dnscrypt router-dns=on)\n")
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// dnscryptConfBody renders a minimal but complete dnscrypt-proxy.toml.
func dnscryptConfBody(routerMode bool, lanIP string, anonymized, dnssec bool) string {
	listen := "['127.0.0.1:" + strconv.Itoa(dnscryptPort) + "']"
	marker := ""
	if routerMode {
		listen = "['127.0.0.1:" + strconv.Itoa(dnscryptPort) + "', '" + lanIP + ":" + strconv.Itoa(dnscryptPort) + "']"
		marker = dnscryptMark + "\n"
	}
	dnssecTOML := "true"
	if !dnssec {
		dnssecTOML = "false"
	}

	anonBlock := ""
	if anonymized {
		anonBlock = `
[anonymized_dns]
  skip_incompatible = true
  routes = [
    { server_name = '*', via = ['anon-cs-fr', 'anon-cs-nl', 'anon-cs-de', 'anon-scaleway'] },
  ]
`
	}

	return fmt.Sprintf(`# `+unboundManagedMark+` (addons: dnscrypt). Regenerated by
# `+"`addon configure dnscrypt …`"+` -- local edits do not stick.
%slisten_addresses = %s
max_clients = 250
ipv4_servers = true
ipv6_servers = false
block_ipv6 = true
dnscrypt_servers = true
doh_servers = true
odoh_servers = false
require_dnssec = %s
require_nolog = true
require_nofilter = true
force_tcp = false
timeout = 5000
keepalive = 30
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'
log_level = 2
use_syslog = true
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

[sources]
  [sources.public-resolvers]
    urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
    cache_file = '%s/public-resolvers.md'
    minisign_key = '%s'
    refresh_delay = 72
  [sources.relays]
    urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/relays.md']
    cache_file = '%s/relays.md'
    minisign_key = '%s'
    refresh_delay = 72
%s`, marker, listen, dnssecTOML, dnscryptCacheDir, dnscryptMinisign, dnscryptCacheDir, dnscryptMinisign, anonBlock)
}

// parseOnOff maps the usual truthy/falsy words to a bool.
func parseOnOff(v string) (bool, error) {
	switch v {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0":
		return false, nil
	}
	return false, fmt.Errorf("нужно on или off")
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// initStatusOK reports whether `<init> status` exits 0.
func initStatusOK(ctx context.Context, script string) bool {
	_, err := initdRun(ctx, script, "status")
	return err == nil
}
