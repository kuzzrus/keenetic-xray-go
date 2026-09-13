package addons

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/susanincore"
)

func init() { Register(susaninAddon{}) }

// Susanin (github.com/R17a/Susanin.Keenetic) is an adaptive, conntrack-based
// router: it watches /proc/net/nf_conntrack for silent-block signals (TCP
// SYN retried with no reply, a stalled TCP flow, QUIC with no reply) and
// routes just that destination IP through a VPN tunnel, no domain list
// needed -- see docs/HANDOFF-susanin.md (Phase 1 of the plan). This
// component doesn't reimplement its install/control logic: it fetches the
// vendored release (internal/susanincore) and runs upstream's own
// install.sh / susanin.sh, the same way it would if an operator did this
// by hand over SSH.
const (
	susaninPrefix = "/opt/susanin"
	susaninBin    = susaninPrefix + "/bin/susanin-agent"
	susaninTools  = susaninPrefix + "/tools"
	susaninConf   = susaninPrefix + "/etc/susanin.conf"
	// susaninInitd is upstream's own boot-script path. install.sh only
	// copies its bundled S94susanin there -- the release tarball this
	// project mirrors doesn't include one (confirmed against the real
	// upstream deploy tarball: it ships install.sh/susanin.sh/datapath.sh/
	// update.sh/uninstall.sh/susanin-agent/config.example.conf/
	// vpn_always.txt/vpn_never.txt only -- S94susanin lives solely in the
	// git checkout's init/entware or init/openwrt, for the full manual
	// DEPLOY.md flow), so this path never actually exists on a router
	// this addon installed. See Remove's comment for why that matters.
	susaninInitd = "/opt/etc/init.d/S94susanin"
)

// susaninEnsure / susaninVersion are susanincore.Ensure/Version, swappable
// in tests -- same injectable-var convention as naivecore.go for the one
// call in this package that reaches the network instead of opkg/init.d.
// runScript runs `sh <path> <args...>`, for upstream's own install.sh /
// susanin.sh -- also swappable, so tests never actually shell out.
var (
	susaninEnsure  = susanincore.Ensure
	susaninVersion = susanincore.Version
	runScript      = func(ctx context.Context, path string, args ...string) (string, error) {
		return runCombined(ctx, "sh", append([]string{path}, args...)...)
	}
)

type susaninAddon struct{}

func (susaninAddon) ID() string { return "susanin" }
func (susaninAddon) Title() string {
	return "Susanin — адаптивная маршрутизация по IP"
}

func (susaninAddon) About() string {
	return "Следит за conntrack и по тихим признакам блокировки (SYN без ответа, обрыв TCP, " +
		"QUIC без ответа) сам находит заблокированные IP и заворачивает именно их в VPN -- без " +
		"доменных списков. Помнит рабочие адреса между перезагрузками, возвращается на прямой " +
		"доступ при падении туннеля. Сторонний бинарь (github.com/R17a/Susanin.Keenetic, MIT), " +
		"ставится и управляется его же install.sh/susanin.sh -- этот компонент их не подменяет.\n\n" +
		"⚠️ Два обязательных условия:\n" +
		"  1) должен быть включён WG-транспорт (Susanin поедет через этот интерфейс egress'ом) --\n" +
		"  2) DNS-based маршрутизация Keenetic (наш `routes`) на время работы Susanin должна быть " +
		"выключена -- это тот же самый механизм, оба разом работать не должны.\n\n" +
		"Настройки (addon configure susanin …), обязателен egress перед первым запуском:\n" +
		"  egress=Wireguard4     OS-имя интерфейса WG-транспорта (не NDM-имя!) -- узнать:\n" +
		"                        `ndmc -c show interface <NDM-имя-из-WGTransport.Iface>`,\n" +
		"                        строка `interface-name:`\n" +
		"  lan=br0,br1           LAN-интерфейсы (по умолчанию определяются сами)\n" +
		"  subnets=192.168.1.0/24  LAN-подсети (по умолчанию определяются сами)\n" +
		"  health_probe=1.1.1.1,8.8.8.8  цели проверки живости туннеля\n\n" +
		"Списки vpn_always.txt/vpn_never.txt (всегда через VPN / всегда напрямую) правятся " +
		"напрямую на роутере: /opt/susanin/etc/{vpn_always,vpn_never}.txt."
}

func (susaninAddon) Detect(ctx context.Context) State {
	v, err := susaninVersion(susaninBin)
	st := State{Installed: err == nil, Version: v, HasDaemon: true}
	if !st.Installed {
		return st
	}
	st.Running = processMatches(ctx, "susanin-agent")
	if eg := susaninConfValue("egress_interface"); eg != "" {
		st.Detail = "egress " + eg
	} else {
		st.Detail = "не настроен -- нужен `addon configure susanin egress=<iface>`"
	}
	return st
}

func (susaninAddon) Install(ctx context.Context) error {
	dir, err := susaninEnsure(ctx, susanincore.Options{})
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// --no-start: without a real egress configured yet (Configure sets
	// it), starting the daemon now would just run it against whatever
	// install.sh's own auto-detection guessed -- Configure's restart is
	// what actually brings it up meaningfully.
	installSh := filepath.Join(dir, "install.sh")
	if out, err := runScript(ctx, installSh, "--yes", "--no-start", "--prefix", susaninPrefix); err != nil {
		return fmt.Errorf("susanin install.sh: %w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

func (susaninAddon) Remove(ctx context.Context) error {
	if _, err := susaninVersion(susaninBin); err != nil {
		return nil // never installed
	}
	// Upstream's uninstall.sh runs under `set -e` and, unconditionally,
	// does `[ -f "$INITD" ] && rm -f "$INITD" && say ...` as a bare
	// statement -- when that file doesn't exist (see susaninInitd's
	// comment: it never does, on a router this addon installed), the
	// compound expression's exit status is non-zero and the whole script
	// aborts right there, before ever reaching the actual file removal
	// further down. It does stop the daemon and tear down the data plane
	// first (those steps are properly guarded), so the practical symptom
	// is "🗑 Удалить runs, susanin stops working, but still shows
	// installed" -- nothing was actually deleted. Touch a harmless empty
	// placeholder so upstream's own check passes; it removes the
	// placeholder itself moments later as part of its normal cleanup.
	if err := writeFile(susaninInitd, nil, 0o644); err != nil {
		return fmt.Errorf("susanin: подготовка к удалению не удалась: %w", err)
	}
	if out, err := runScript(ctx, susaninTools+"/uninstall.sh"); err != nil {
		return fmt.Errorf("susanin uninstall.sh: %w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

func (susaninAddon) Configure(ctx context.Context, kv map[string]string) error {
	if len(kv) == 0 {
		return fmt.Errorf("нечего менять — см. `addon show susanin`")
	}
	set := map[string]string{}
	for k, v := range kv {
		switch k {
		case "egress":
			if strings.TrimSpace(v) == "" {
				return fmt.Errorf("egress=%q: пустое имя интерфейса", v)
			}
			set["egress_interface"] = v
		case "lan":
			set["lan_interfaces"] = v
		case "subnets":
			set["lan_subnets"] = v
		case "health_probe":
			set["health_probe"] = v
		default:
			return fmt.Errorf("неизвестный ключ %q (см. `addon show susanin`)", k)
		}
	}
	if err := shellConfSet(susaninConf, set); err != nil {
		return err
	}
	// susanin.sh install brings up the data plane (iptables chain, ip
	// rules/routes, ipsets) from the config just written -- idempotent
	// (upstream's own datapath.sh: "delete-then-add"). It's a distinct
	// step from the daemon process itself and from this addon's Install(),
	// which only lays out files (see the --no-start comment there);
	// restart alone never brought up anything beyond a bare daemon
	// process watching a data plane that never existed.
	if out, err := runScript(ctx, susaninTools+"/susanin.sh", "install"); err != nil {
		return fmt.Errorf("susanin: настройка дата-плейна не удалась: %w\n%s", err, strings.TrimSpace(out))
	}
	if out, err := runScript(ctx, susaninTools+"/susanin.sh", "restart"); err != nil {
		return fmt.Errorf("susanin не перезапустился после изменения настроек: %w\n%s", err, strings.TrimSpace(out))
	}
	return nil
}

func (susaninAddon) Status(ctx context.Context) (string, error) {
	if _, err := susaninVersion(susaninBin); err != nil {
		return "susanin не установлен", nil
	}
	if susaninConfValue("egress_interface") == "" {
		return "susanin установлен, но не настроен -- нужен `addon configure susanin egress=<iface>` " +
			"(OS-имя интерфейса WG-транспорта)", nil
	}
	out, err := runScript(ctx, susaninTools+"/susanin.sh", "status")
	if err != nil {
		return "", fmt.Errorf("susanin.sh status: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// susaninConfValue reads one KEY from susanin.conf's shell-format config
// (KEY=value, same shape nfqws2's shellConfSet already writes).
func susaninConfValue(key string) string {
	data, err := readFile(susaninConf)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(k) != key {
			continue
		}
		return strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return ""
}
