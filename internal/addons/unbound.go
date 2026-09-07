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
// This component installs and manages it on 127.0.0.1:<port> (5353 by
// default) with DNSSEC validation. It does NOT yet repoint Keenetic's
// dns-proxy at it -- that wiring (opkg dns-override, and undoing it
// cleanly) needs verifying on hardware first and lands with the bot
// screen; for now Status prints the one manual step.
const (
	unboundPkg      = "unbound-daemon"
	unboundInit     = "S61unbound"
	unboundConf     = "/opt/etc/unbound/unbound.conf"
	unboundDefPort  = 5353
	unboundDefCache = 8 // MB, per rrset/msg cache
)

type unboundAddon struct{}

func (*unboundAddon) ID() string    { return "unbound" }
func (*unboundAddon) Title() string { return "unbound — рекурсивный DNS" }

func (*unboundAddon) About() string {
	return "Локальный рекурсивный резолвер unbound: сам ходит по корневым серверам, а не " +
		"доверяет провайдерскому DNS, который может подменять ответы. Проверяет DNSSEC. " +
		"Слушает 127.0.0.1:<port>.\n\n" +
		"Настройки (addon configure unbound …):\n" +
		"  port=5353     локальный порт\n" +
		"  cache=8       размер кэша, МБ (на каждый из rrset/msg)\n" +
		"  dnssec=on|off проверка DNSSEC\n\n" +
		"Пока НЕ подключается автоматически как резолвер роутера — этот шаг " +
		"(opkg dns-override) добавится отдельно после проверки на железе."
}

func (*unboundAddon) Detect(ctx context.Context) State {
	v := opkgInstalledVersion(ctx, unboundPkg)
	st := State{Installed: v != "", Version: v, HasDaemon: true}
	if !st.Installed {
		return st
	}
	port := unboundConfiguredPort(ctx)
	st.Running = portListening(ctx, port)
	st.Detail = fmt.Sprintf("127.0.0.1:%d", port)
	return st
}

func (*unboundAddon) Install(ctx context.Context) error {
	if err := opkgInstall(ctx, unboundPkg); err != nil {
		return err
	}
	if _, err := readFile(unboundConf); err != nil {
		// Fresh install with no usable conf -> lay down ours.
		if err := writeFile(unboundConf, []byte(unboundConfBody(unboundDefPort, unboundDefCache, true)), 0o644); err != nil {
			return fmt.Errorf("запись %s: %w", unboundConf, err)
		}
	}
	if _, err := initdRun(ctx, unboundInit, "start"); err != nil {
		return fmt.Errorf("unbound не запустился: %w", err)
	}
	return nil
}

func (*unboundAddon) Remove(ctx context.Context) error {
	_, _ = initdRun(ctx, unboundInit, "stop")
	return opkgRemove(ctx, unboundPkg)
}

func (*unboundAddon) Configure(ctx context.Context, kv map[string]string) error {
	port := unboundConfiguredPort(ctx)
	cache := unboundDefCache
	dnssec := true
	// seed cache/dnssec from the current file so a partial change keeps the rest
	if body, err := readFile(unboundConf); err == nil {
		s := string(body)
		if strings.Contains(s, "# dnssec: off") || strings.Contains(s, "val-permissive-mode: yes") {
			dnssec = false
		}
		if n := unboundGrepInt(s, "msg-cache-size:"); n > 0 {
			cache = n / (1024 * 1024)
		}
	}

	for k, v := range kv {
		switch k {
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

	if err := writeFile(unboundConf, []byte(unboundConfBody(port, cache, dnssec)), 0o644); err != nil {
		return err
	}
	if _, err := initdRun(ctx, unboundInit, "restart"); err != nil {
		return fmt.Errorf("unbound не перезапустился: %w", err)
	}
	return nil
}

func (*unboundAddon) Status(ctx context.Context) (string, error) {
	if opkgInstalledVersion(ctx, unboundPkg) == "" {
		return "unbound не установлен", nil
	}
	port := unboundConfiguredPort(ctx)
	var b strings.Builder
	if portListening(ctx, port) {
		fmt.Fprintf(&b, "unbound: слушает 127.0.0.1:%d\n", port)
	} else {
		fmt.Fprintf(&b, "unbound: установлен, но на 127.0.0.1:%d тишина (проверь `%s/%s status`)\n", port, initdDir, unboundInit)
	}
	fmt.Fprintf(&b, "как резолвер роутера пока не подключён — вручную: opkg dns-override, затем перезапуск dns-proxy\n")
	return strings.TrimRight(b.String(), "\n"), nil
}

// unboundConfiguredPort reads the port: line from the conf, or the
// default.
func unboundConfiguredPort(_ context.Context) int {
	data, err := readFile(unboundConf)
	if err != nil {
		return unboundDefPort
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "port:"); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return unboundDefPort
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

// unboundConfBody renders a conservative recursive-resolver config.
func unboundConfBody(port, cacheMB int, dnssec bool) string {
	bytesPerCache := cacheMB * 1024 * 1024
	dnssecLine := `auto-trust-anchor-file: "/opt/etc/unbound/root.key"`
	if !dnssec {
		dnssecLine = "val-permissive-mode: yes  # dnssec: off"
	}
	return fmt.Sprintf(`# Managed by keenetic-xray (addons: unbound). Regenerated on
# `+"`addon configure unbound …`"+` -- local edits do not stick.
server:
    verbosity: 0
    interface: 127.0.0.1
    port: %d
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
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
`, port, bytesPerCache, bytesPerCache, dnssecLine)
}
