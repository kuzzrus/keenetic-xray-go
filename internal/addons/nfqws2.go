package addons

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

func init() { Register(&nfqws2Addon{}) }

// nfqws2 is a DPI-bypass daemon (github.com/nfqws/nfqws2-keenetic, a
// fork of bol-van/zapret2). It desynchronises DPI on *direct* traffic --
// the connections that don't go through the xray tunnel -- so blocked
// sites keep working without routing them. It ships as a self-contained
// opkg package from its own feed: its own init script (S51nfqws2), its
// own NFQUEUE rules (chain nfqws_post, queue 300) and its own netfilter
// hooks. This component just adds the feed, installs the package, and
// edits its config file / domain list.
const (
	nfqwsPkg      = "nfqws2-keenetic"
	nfqwsFeedName = "nfqws2-keenetic" // src/gz <name> -- must match the package feed name
	nfqwsFeedBase = "https://nfqws.github.io/nfqws2-keenetic"
	nfqwsFeedFile = "/opt/etc/opkg/nfqws2-keenetic.conf"
	nfqwsInit     = "S51nfqws2"
	nfqwsConf     = "/opt/etc/nfqws2/nfqws2.conf"
	nfqwsUserList = "/opt/etc/nfqws2/lists/user.list"
	nfqwsLog      = "/opt/var/log/nfqws2.log"
)

// nfqwsFeedURL is the arch-specific opkg feed. The nfqws2-keenetic repo
// publishes per-arch indexes (mips / mipsel / aarch64 / …); the generic
// "/all" path carries no installable packages, which is why an install
// against it fails with "Unknown package".
func nfqwsFeedURL() string {
	arch := map[string]string{
		"mipsle": "mipsel",
		"mips":   "mips",
		"arm64":  "aarch64",
		"arm":    "armv7",
		"386":    "x86",
		"amd64":  "x86_64",
	}[runtime.GOARCH]
	if arch == "" {
		arch = runtime.GOARCH
	}
	return nfqwsFeedBase + "/" + arch
}

type nfqws2Addon struct{}

func (*nfqws2Addon) ID() string { return "nfqws2" }
func (*nfqws2Addon) Title() string {
	return "nfqws2 — обход DPI на прямом трафике"
}

func (*nfqws2Addon) About() string {
	return "Демон обхода DPI (nfqws2-keenetic, форк zapret2). Работает с трафиком, который " +
		"НЕ идёт в туннель xray: рассинхронизирует DPI, чтобы заблокированные сайты открывались " +
		"без заворачивания их в VPN. Ставится своим пакетом из отдельного репозитория, приносит " +
		"свой init-скрипт и правила NFQUEUE.\n\n" +
		"Настройки (addon configure nfqws2 …):\n" +
		"  mode=list|auto|all   список / автообнаружение / весь трафик (по умолчанию list)\n" +
		"  tcp_ports=443,80     TCP-порты\n" +
		"  udp_ports=443        UDP-порты (QUIC)\n" +
		"  isp_interface=       WAN-интерфейс провайдера (пусто — определит сам)\n" +
		"  domain=example.com   добавить домен в lists/user.list\n\n" +
		"Держи mode=list и веди user.list — так nfqws2 трогает только нужное и не мешает " +
		"Reality-соединению самого xray."
}

func (*nfqws2Addon) Detect(ctx context.Context) State {
	v := opkgInstalledVersion(ctx, nfqwsPkg)
	st := State{Installed: v != "", Version: v, HasDaemon: true}
	if !st.Installed {
		return st
	}
	st.Running = nfqwsRunning(ctx)
	if mode, tcp := nfqwsReadConf(ctx); mode != "" {
		st.Detail = fmt.Sprintf("режим %s, TCP %s", mode, tcp)
	}
	return st
}

func (*nfqws2Addon) Install(ctx context.Context) error {
	if err := writeFile(nfqwsFeedFile, []byte(fmt.Sprintf("src/gz %s %s\n", nfqwsFeedName, nfqwsFeedURL())), 0o644); err != nil {
		return fmt.Errorf("добавление репозитория nfqws2 (%s): %w", nfqwsFeedFile, err)
	}
	if err := opkgInstall(ctx, nfqwsPkg); err != nil {
		return err
	}
	// The package's postinst normally starts it; make sure.
	_, _ = initdRun(ctx, nfqwsInit, "start")
	return nil
}

func (*nfqws2Addon) Remove(ctx context.Context) error {
	_, _ = initdRun(ctx, nfqwsInit, "stop")
	if err := opkgRemove(ctx, nfqwsPkg); err != nil {
		return err
	}
	_ = removeFile(nfqwsFeedFile)
	return nil
}

func (*nfqws2Addon) Configure(ctx context.Context, kv map[string]string) error {
	if len(kv) == 0 {
		return fmt.Errorf("нечего менять — см. `addon show nfqws2`")
	}
	set := map[string]string{}
	for k, v := range kv {
		switch k {
		case "mode":
			if v != "list" && v != "auto" && v != "all" {
				return fmt.Errorf("mode=%q: только list, auto или all", v)
			}
			set["NFQWS_EXTRA_ARGS"] = v
		case "tcp_ports":
			if err := validPorts(v); err != nil {
				return fmt.Errorf("tcp_ports=%q: %w", v, err)
			}
			set["TCP_PORTS"] = v
		case "udp_ports":
			if err := validPorts(v); err != nil {
				return fmt.Errorf("udp_ports=%q: %w", v, err)
			}
			set["UDP_PORTS"] = v
		case "isp_interface":
			set["ISP_INTERFACE"] = v
		case "domain":
			if err := nfqwsAddDomain(v); err != nil {
				return err
			}
		default:
			return fmt.Errorf("неизвестный ключ %q (см. `addon show nfqws2`)", k)
		}
	}
	if len(set) > 0 {
		if err := shellConfSet(nfqwsConf, set); err != nil {
			return err
		}
	}
	if _, err := initdRun(ctx, nfqwsInit, "restart"); err != nil {
		return fmt.Errorf("nfqws2 не перезапустился после изменения настроек: %w", err)
	}
	return nil
}

func (*nfqws2Addon) Status(ctx context.Context) (string, error) {
	if opkgInstalledVersion(ctx, nfqwsPkg) == "" {
		return "nfqws2 не установлен", nil
	}
	var b strings.Builder
	if nfqwsRunning(ctx) {
		b.WriteString("nfqws2: работает\n")
	} else {
		b.WriteString("nfqws2: остановлен\n")
	}
	if mode, tcp := nfqwsReadConf(ctx); mode != "" {
		fmt.Fprintf(&b, "режим %s · TCP %s\n", mode, tcp)
	}
	if tail := lastLines(ctx, nfqwsLog, 8); tail != "" {
		b.WriteString("--- " + nfqwsLog + " ---\n")
		b.WriteString(tail)
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// nfqwsRunning is true if the init script reports it up or a bare nfqws
// process is visible (some busybox init scripts have a flaky `status`).
func nfqwsRunning(ctx context.Context) bool {
	if _, err := initdRun(ctx, nfqwsInit, "status"); err == nil {
		return true
	}
	return processMatches(ctx, "nfqws")
}

// nfqwsReadConf pulls the operating mode and TCP ports out of the conf
// for the one-line Detail / Status summary.
func nfqwsReadConf(ctx context.Context) (mode, tcpPorts string) {
	data, err := readFile(nfqwsConf)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "NFQWS_EXTRA_ARGS":
			mode = v
		case "TCP_PORTS":
			tcpPorts = v
		}
	}
	return mode, tcpPorts
}

func nfqwsAddDomain(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || strings.ContainsAny(domain, " /\t") {
		return fmt.Errorf("domain=%q: одно доменное имя без пробелов и схемы", domain)
	}
	existing, _ := readFile(nfqwsUserList)
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == domain {
			return nil // already there
		}
	}
	body := string(existing)
	if body != "" && !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	body += domain + "\n"
	return writeFile(nfqwsUserList, []byte(body), 0o644)
}

func validPorts(s string) error {
	if s == "" {
		return fmt.Errorf("пусто")
	}
	for _, p := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("порт %q вне диапазона", p)
		}
	}
	return nil
}

// shellConfSet rewrites a KEY=value shell config: each key in set
// replaces its existing KEY= line (value quoted), or is appended if
// absent. Other lines are preserved verbatim.
func shellConfSet(path string, set map[string]string) error {
	data, err := readFile(path)
	if err != nil {
		return fmt.Errorf("чтение %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	for i, line := range lines {
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if v, want := set[strings.TrimSpace(key)]; want {
			lines[i] = fmt.Sprintf(`%s="%s"`, strings.TrimSpace(key), v)
			seen[strings.TrimSpace(key)] = true
		}
	}
	// Append any keys that weren't already present, in a stable order.
	var missing []string
	for k := range set {
		if !seen[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		lines = append(lines, fmt.Sprintf(`%s="%s"`, k, set[k]))
	}
	return writeFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

// lastLines returns the final n lines of a file, or "" if unreadable.
func lastLines(_ context.Context, path string, n int) string {
	data, err := readFile(path)
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}
