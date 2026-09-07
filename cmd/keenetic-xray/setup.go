package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/install"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
	"github.com/kuzzrus/keenetic-xray-go/internal/subscription"
	"github.com/kuzzrus/keenetic-xray-go/internal/xraycore"
)

// errSlotSkipped is returned by promptSlotSource when the operator hits
// Enter on an optional slot (the backup).
var errSlotSkipped = errors.New("slot skipped")

// setupOpts drives runSetup. With From set (and/or --yes) it runs fully
// non-interactive -- that's the path the .ipk postinst takes when the
// installer was given a link, so `install.sh --sub=...` needs no follow-up
// commands. Without From and without --yes, postinst now runs this
// interactively too (see packaging/ipk/postinst), asking primary and
// backup as two independent sources -- same model as the bot's
// 🔗 Источники (Config.PrimarySource/BackupSource) -- plus the SOCKS/HTTP
// port numbers, rather than the older single-source-then-pick-an-index
// flow non-interactive mode still uses.
type setupOpts struct {
	From       string // vless:// link or http(s):// subscription URL -- non-interactive mode only
	PrimarySel string // index or a remark substring; "" -> 0 -- non-interactive mode only
	BackupSel  string // index or a remark substring; "" -> 1 (or 0 with one profile) -- non-interactive mode only
	Proxy0     string // "", "yes", "no" ("" -> prompt interactively, or auto when non-interactive)
	SOCKSPort  int    // 0 -> prompt interactively, or config.Default's 1080 when non-interactive
	HTTPPort   int    // 0 -> prompt interactively, or config.Default's 1081 when non-interactive
	Yes        bool
}

// cmdSetup is the first-run configurator: pick a primary/backup pair,
// optionally wire Keenetic's Proxy0 to the local inbound, and
// (interactively) offer to restart the daemon so the change takes
// effect.
func cmdSetup(args []string) error {
	var o setupOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes" || a == "-y":
			o.Yes = true
		case a == "--proxy0":
			o.Proxy0 = "yes"
		case a == "--no-proxy0":
			o.Proxy0 = "no"
		case strings.HasPrefix(a, "--from="):
			o.From = a[len("--from="):]
		case a == "--from" && i+1 < len(args):
			i++
			o.From = args[i]
		case strings.HasPrefix(a, "--primary="):
			o.PrimarySel = a[len("--primary="):]
		case strings.HasPrefix(a, "--backup="):
			o.BackupSel = a[len("--backup="):]
		case strings.HasPrefix(a, "--socks-port="):
			n, err := strconv.Atoi(a[len("--socks-port="):])
			if err != nil {
				return fmt.Errorf("--socks-port: %w", err)
			}
			o.SOCKSPort = n
		case strings.HasPrefix(a, "--http-port="):
			n, err := strconv.Atoi(a[len("--http-port="):])
			if err != nil {
				return fmt.Errorf("--http-port: %w", err)
			}
			o.HTTPPort = n
		default:
			return fmt.Errorf("setup: unexpected argument %q", a)
		}
	}
	return runSetup(os.Stdin, o)
}

func runSetup(stdin io.Reader, o setupOpts) error {
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	if o.From != "" || o.Yes {
		return runSetupNonInteractive(cfg, o)
	}

	// Interactive. When stdin isn't a terminal (the `curl | sh` postinst
	// path pipes the script), read the keyboard from /dev/tty instead; if
	// there's no controlling terminal at all, skip the wizard cleanly
	// rather than half-run it on empty input.
	in := stdin
	if f, ok := stdin.(*os.File); ok && !isCharDevice(f) {
		tty, terr := os.Open("/dev/tty")
		if terr != nil {
			fmt.Println("нет терминала — мастер настройки пропущен.")
			fmt.Println("запусти его вручную:  keenetic-xray setup")
			return nil
		}
		defer tty.Close()
		in = tty
	}
	return runSetupInteractive(bufio.NewReader(in), cfg, o)
}

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runSetupNonInteractive is the postinst / scripted path: one source
// (a link or a subscription), primary/backup picked from it by index or
// name, no prompts. Unchanged in shape since before per-slot independent
// sources existed; `install.sh --sub=...` and CI depend on this exact
// behavior.
func runSetupNonInteractive(cfg *config.Config, o setupOpts) error {
	input := strings.TrimSpace(o.From)
	if input == "" {
		return fmt.Errorf("no vless:// link or subscription URL given")
	}

	var profiles []config.Profile
	switch {
	case strings.HasPrefix(input, "vless://"):
		p, err := config.ParseVLESSURI(input)
		if err != nil {
			return fmt.Errorf("parsing vless link: %w", err)
		}
		profiles = []config.Profile{p}
	case strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://"):
		fmt.Println("fetching subscription...")
		result, err := subscription.Refresh(context.Background(), input, "", "")
		if err != nil {
			return fmt.Errorf("fetching subscription: %w", err)
		}
		for _, w := range result.Warnings {
			fmt.Println("warning:", w)
		}
		profiles = result.Profiles
		cfg.Subscription = &config.Subscription{URL: input, LastFetchedAt: time.Now()}
	default:
		return fmt.Errorf("input doesn't look like a vless:// link or an http(s):// subscription URL")
	}

	if len(profiles) == 0 {
		return fmt.Errorf("no usable vless:// profiles found")
	}
	if cfg.PrimarySource != nil || cfg.BackupSource != nil {
		fmt.Println("warning: this replaces ALL profiles, including the independent primary/backup sources set via the bot's 🔗 Источники -- re-add them afterward if you still want them")
	}
	cfg.Profiles = profiles

	primaryIdx, err := resolveProfileSelector(profiles, o.PrimarySel, 0)
	if err != nil {
		return fmt.Errorf("--primary: %w", err)
	}
	defBackup := 0
	if len(profiles) > 1 {
		defBackup = 1
		if primaryIdx == 1 {
			defBackup = 0
		}
	}
	backupIdx, err := resolveProfileSelector(profiles, o.BackupSel, defBackup)
	if err != nil {
		return fmt.Errorf("--backup: %w", err)
	}

	cfg.PrimaryIndex = primaryIdx
	cfg.BackupIndex = backupIdx
	if cfg.Subscription != nil {
		cfg.Subscription.PrimaryKey = profiles[primaryIdx].Remark
		cfg.Subscription.BackupKey = profiles[backupIdx].Remark
	}
	applyPortOverrides(cfg, o)

	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	fmt.Printf("\nSaved: primary=%s, backup=%s\n", profiles[primaryIdx].Remark, profiles[backupIdx].Remark)

	if o.Proxy0 == "yes" || (o.Proxy0 != "no" && keenetic.Available()) {
		doSetupProxy0(cfg)
	}
	applyDaemonChange(nil, false)
	return nil
}

// runSetupInteractive is the terminal wizard: primary and backup each
// get their own prompt (a vless:// link, or a subscription URL with an
// interactive pick among its profiles) and their own SlotSource, exactly
// like the bot's 🔗 Источники -- so a slot set up this way is never at
// risk of a subscription refresh elsewhere silently discarding it (see
// Config.PrimarySource/BackupSource, IndependentSlots). Then SOCKS/HTTP
// port numbers, Proxy0, and a restart offer.
func runSetupInteractive(reader *bufio.Reader, cfg *config.Config, o setupOpts) error {
	fmt.Print("Мастер настройки keenetic-xray\n\n")

	primary, err := promptSlotSource(reader, cfg, "основной", false)
	if err != nil {
		return err
	}
	cfg.PrimaryIndex = cfg.UpsertProfile(primary.profile)
	cfg.PrimarySource = &config.SlotSource{URL: primary.src, Selector: primary.selector}
	fmt.Printf("  основной: %s\n\n", primary.profile.Remark)

	haveBackup := true
	backup, err := promptSlotSource(reader, cfg, "резервный", true)
	switch {
	case errors.Is(err, errSlotSkipped):
		haveBackup = false
		cfg.BackupSource = nil
		cfg.BackupIndex = cfg.PrimaryIndex // single-profile: daemon supervises, no switching
		fmt.Print("  резервный: пропущен — один профиль, автопереключения не будет\n\n")
	case err != nil:
		return err
	default:
		cfg.BackupIndex = cfg.UpsertProfile(backup.profile)
		cfg.BackupSource = &config.SlotSource{URL: backup.src, Selector: backup.selector}
		fmt.Printf("  резервный: %s\n\n", backup.profile.Remark)
	}

	socksPort, httpPort, err := promptPorts(reader, cfg, o)
	if err != nil {
		return err
	}
	cfg.Failover.SOCKSPort = socksPort
	cfg.Failover.HTTPPort = httpPort

	if err := cfg.Save(configPath()); err != nil {
		return err
	}

	promptTransport(reader, cfg, o)
	promptTelegramRoute(reader, cfg)
	promptXrayCore(reader, o)

	applyDaemonChange(reader, true)
	printSetupSummary(cfg, haveBackup)
	return nil
}

// transportIface names the Keenetic interface the wizard just pointed
// router traffic at -- the in-router WireGuard transport, or Proxy0 --
// or "" when the operator kept Keenetic untouched (transport option 4)
// or this isn't a router. WG wins if both somehow got set.
func transportIface(cfg *config.Config) string {
	switch {
	case cfg.WGTransport.Enabled && cfg.WGTransport.Iface != "":
		return cfg.WGTransport.Iface
	case cfg.Proxy0.Enabled:
		return cfg.Proxy0.IfaceName()
	default:
		return ""
	}
}

// promptTelegramRoute offers, right after the transport is chosen, to
// send Telegram straight through it -- so a fresh install comes up with
// Telegram already tunnelled without a second command. Binds the
// embedded telegram / telegram-ip presets to the just-picked interface
// and runs the normal routes apply. Skipped when there's no transport to
// ride (option 4, or not a Keenetic).
func promptTelegramRoute(reader *bufio.Reader, cfg *config.Config) {
	iface := transportIface(cfg)
	if iface == "" || !keenetic.Available() {
		return
	}
	fmt.Printf("\nЗавернуть Telegram в туннель через %s? [Y/n]: ", iface)
	line, _ := reader.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "n", "no", "н", "нет":
		fmt.Println("  пропущено — позже:  keenetic-xray routes preset add telegram --ip --iface=" + iface)
		return
	}

	presets.SetOverlay(presetsOverlayDir())
	names, err := presets.Apply(cfg, "telegram", true, iface, false)
	if err != nil {
		fmt.Println("  список telegram не применился:", err)
		fmt.Println("  позже:  keenetic-xray routes preset add telegram --ip --iface=" + iface)
		return
	}
	// presets.Apply lands the interface on the domain list only; Telegram's
	// CIDR ranges are tight and service-specific, so send them the same way.
	if ip := presets.BoundList(cfg, "telegram-ip"); ip != nil {
		ip.Interface = iface
	}
	if err := routesApply(cfg, fmt.Sprintf("Telegram → %s (%s)", iface, strings.Join(names, ", "))); err != nil {
		fmt.Println(" ", err)
	}
}

// promptXrayCore offers to switch the just-installed stable core to the
// vetted pre-release build. Skipped when there's no distinct pre-release
// tag, or in non-interactive mode. Delegates to `internal
// ensure-xray-core --tag`, which persists the choice in config.
func promptXrayCore(reader *bufio.Reader, o setupOpts) {
	if o.Yes || xraycore.PrereleaseTag == "" || xraycore.PrereleaseTag == xraycore.DefaultTag {
		return
	}
	fmt.Println("\nЯдро xray:")
	fmt.Printf("  1) стабильное  %s  (по умолчанию, уже стоит)\n", xraycore.DefaultTag)
	fmt.Printf("  2) пререлизное %s  (новее, opt-in)\n", xraycore.PrereleaseTag)
	fmt.Print("> ")
	line, _ := reader.ReadString('\n')
	if strings.TrimSpace(line) != "2" {
		return
	}
	fmt.Println("ставлю пререлизное ядро…")
	cmd := exec.Command(os.Args[0], "internal", "ensure-xray-core", "--tag="+xraycore.PrereleaseTag)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Println("не удалось поставить пререлизное ядро:", err)
		fmt.Println("позже:  keenetic-xray internal ensure-xray-core --tag=" + xraycore.PrereleaseTag)
	}
}

// slotSourceResult is one resolved slot source: the chosen profile, plus
// what to persist in Config.PrimarySource/BackupSource (the source
// string as typed, and the selector -- either what the user typed, or
// the index they picked from a listed subscription -- so a later
// re-resolution of the same source picks the same profile).
type slotSourceResult struct {
	profile  config.Profile
	src      string
	selector string
}

// promptSlotSource asks for one slot's source (a vless:// link, or a
// subscription URL followed by an interactive pick if it has more than
// one profile) and resolves it to a single profile. label is "PRIMARY"
// or "BACKUP", used only in the prompts.
func promptSlotSource(reader *bufio.Reader, cfg *config.Config, label string, optional bool) (slotSourceResult, error) {
	hint := ""
	if optional {
		hint = " (Enter — пропустить)"
	}
	fmt.Printf("%s профиль%s — вставь vless:// или ссылку на подписку http(s)://:\n> ", label, hint)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" && !optional {
		return slotSourceResult{}, fmt.Errorf("чтение ввода: %w", err)
	}
	src := strings.TrimSpace(line)
	if src == "" {
		if optional {
			return slotSourceResult{}, errSlotSkipped
		}
		return slotSourceResult{}, fmt.Errorf("%s: не задана ни vless://-ссылка, ни URL подписки", label)
	}

	switch {
	case strings.HasPrefix(src, "vless://"):
		p, err := config.ParseVLESSURI(src)
		if err != nil {
			return slotSourceResult{}, fmt.Errorf("%s: разбор vless-ссылки: %w", label, err)
		}
		return slotSourceResult{profile: p, src: src}, nil
	case strings.HasPrefix(src, "http://"), strings.HasPrefix(src, "https://"):
		fmt.Println("тяну подписку…")
		result, err := subscription.Refresh(context.Background(), src, "", "")
		if err != nil {
			return slotSourceResult{}, fmt.Errorf("%s: загрузка подписки: %w", label, err)
		}
		for _, w := range result.Warnings {
			fmt.Println("  пропущено:", w)
		}
		if len(result.Profiles) == 0 {
			return slotSourceResult{}, fmt.Errorf("%s: в подписке нет рабочих vless://-профилей", label)
		}
		if len(result.Profiles) == 1 {
			return slotSourceResult{profile: result.Profiles[0], src: src}, nil
		}
		fmt.Println("\nПрофили в подписке:")
		for i, p := range result.Profiles {
			fmt.Printf("  %d: %s — %s:%d\n", i, p.Remark, p.Address, p.Port)
		}
		idx, err := promptIndex(reader, "Выбери "+label, len(result.Profiles), 0)
		if err != nil {
			return slotSourceResult{}, err
		}
		return slotSourceResult{profile: result.Profiles[idx], src: src, selector: strconv.Itoa(idx)}, nil
	default:
		return slotSourceResult{}, fmt.Errorf("%s: не похоже ни на vless://-ссылку, ни на http(s)://-подписку", label)
	}
}

// promptPorts asks for the SOCKS/HTTP inbound ports, defaulting to
// whatever's already in cfg (config.Default's 1080/1081 on a fresh
// config). A flag (--socks-port=/--http-port=) skips its own prompt.
// Re-prompts if the two would collide.
func promptPorts(reader *bufio.Reader, cfg *config.Config, o setupOpts) (socksPort, httpPort int, err error) {
	fmt.Println()
	for {
		socksPort = o.SOCKSPort
		if socksPort == 0 {
			if socksPort, err = promptPort(reader, "SOCKS port", cfg.Failover.SOCKSPort); err != nil {
				return 0, 0, err
			}
		}
		httpPort = o.HTTPPort
		if httpPort == 0 {
			if httpPort, err = promptPort(reader, "HTTP port", cfg.Failover.HTTPPort); err != nil {
				return 0, 0, err
			}
		}
		if socksPort != httpPort {
			return socksPort, httpPort, nil
		}
		fmt.Println("порты SOCKS и HTTP должны отличаться, ещё раз")
		if o.SOCKSPort != 0 && o.HTTPPort != 0 {
			// Both came from flags -- re-prompting can't change them.
			return 0, 0, fmt.Errorf("--socks-port и --http-port должны отличаться")
		}
	}
}

// promptPort reads a line, re-prompting on an invalid or out-of-range
// port; an empty line (just Enter) accepts def.
func promptPort(reader *bufio.Reader, label string, def int) (int, error) {
	for {
		fmt.Printf("%s [Enter — %d]: ", label, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return def, nil // EOF on a piped script -> take the default
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 1 || n > 65535 {
			fmt.Println("некорректный порт, ещё раз")
			continue
		}
		return n, nil
	}
}

// applyPortOverrides sets cfg's SOCKS/HTTP ports from --socks-port=/
// --http-port= when given; used by the non-interactive path, which
// otherwise never touches them (config.Default's 1080/1081 stand).
func applyPortOverrides(cfg *config.Config, o setupOpts) {
	if o.SOCKSPort != 0 {
		cfg.Failover.SOCKSPort = o.SOCKSPort
	}
	if o.HTTPPort != 0 {
		cfg.Failover.HTTPPort = o.HTTPPort
	}
}

// resolveProfileSelector turns a --primary/--backup value into an index:
// an integer index, or a case-insensitive substring of exactly one
// profile's remark. Empty selects def.
func resolveProfileSelector(profiles []config.Profile, sel string, def int) (int, error) {
	sel = strings.TrimSpace(sel)
	if sel == "" {
		return def, nil
	}
	if n, err := strconv.Atoi(sel); err == nil {
		if n < 0 || n >= len(profiles) {
			return 0, fmt.Errorf("index %d out of range (0..%d)", n, len(profiles)-1)
		}
		return n, nil
	}
	match := -1
	low := strings.ToLower(sel)
	for i, p := range profiles {
		if strings.Contains(strings.ToLower(p.Remark), low) {
			if match >= 0 {
				return 0, fmt.Errorf("%q matches more than one profile", sel)
			}
			match = i
		}
	}
	if match < 0 {
		return 0, fmt.Errorf("no profile matches %q", sel)
	}
	return match, nil
}

// doSetupProxy0 performs the ndmc-side Proxy0 wiring and records it in the
// config. Router-only; a no-op where ndmc isn't present.
func doSetupProxy0(cfg *config.Config) {
	if !keenetic.Available() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, err := keenetic.LANIP(ctx, cfg.Proxy0.LANIP)
	if err != nil {
		fmt.Println("  could not detect the router LAN IP:", err)
		fmt.Println("  run: keenetic-xray proxy0 set --lan-ip=192.168.x.1")
		return
	}
	if err := keenetic.ConfigureProxy0(ctx, keenetic.Proxy0Options{
		Interface:    cfg.Proxy0.Interface,
		UpstreamHost: ip,
		UpstreamPort: cfg.Proxy0Port(),
		Protocol:     cfg.Proxy0.Protocol,
	}); err != nil {
		fmt.Println("  Proxy0 setup failed:", err)
		return
	}
	cfg.Proxy0.Enabled = true
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  Proxy0 configured on the router but saving config failed:", err)
		return
	}
	fmt.Printf("  Proxy0 -> %s:%d. Assign devices/policies to Proxy0 in the Keenetic UI.\n", ip, cfg.Proxy0Port())
}

// promptTransport asks how to get the router's LAN traffic into xray:
// Keenetic's Proxy0 (SOCKS5 or HTTP), the in-router WireGuard transport,
// or nothing (local proxy only). Replaces the old y/N Proxy0 question.
func promptTransport(reader *bufio.Reader, cfg *config.Config, o setupOpts) {
	switch {
	case o.Proxy0 == "no":
		return
	case o.Proxy0 == "yes":
		doSetupProxy0(cfg)
		return
	}
	if !keenetic.Available() {
		return // not on a Keenetic; the local proxy is all there is
	}
	fmt.Println("\nКак завернуть трафик роутера в xray:")
	fmt.Println("  1) Proxy0 · SOCKS5   — обычный путь (по умолчанию)")
	fmt.Println("  2) Proxy0 · HTTP")
	fmt.Println("  3) WireGuard-транспорт — LAN → WireguardN → xray, ключи сгенерируются сами")
	fmt.Println("  4) не трогать Keenetic — только локальный прокси на портах выше")
	fmt.Print("> ")
	line, _ := reader.ReadString('\n')
	switch strings.TrimSpace(line) {
	case "2":
		cfg.Proxy0.Protocol = "http"
		_ = cfg.Save(configPath())
		doSetupProxy0(cfg)
	case "3":
		cfg.Proxy0.Enabled = false // WG transport is the chosen path, don't also wire Proxy0
		if err := wgTransportApply(cfg); err != nil {
			fmt.Println("  WG-транспорт не поднялся:", err)
			fmt.Println("  позже:  keenetic-xray transport wg on")
			return
		}
	case "4":
		cfg.Proxy0.Enabled = false
		_ = cfg.Save(configPath())
		fmt.Println("  Keenetic не трогаем. Прокси на 127.0.0.1 и в LAN на портах выше.")
	default: // "1" or Enter
		cfg.Proxy0.Protocol = "socks5"
		_ = cfg.Save(configPath())
		doSetupProxy0(cfg)
	}
}

// printSetupSummary is the end-of-wizard recap: what got configured, a
// quick TCP reachability check on the primary server (not a tunnel
// test), and a watchdog warning when cron didn't install.
func printSetupSummary(cfg *config.Config, haveBackup bool) {
	fmt.Print("\n── готово ──\n")
	if p := cfg.Primary(); p != nil {
		fmt.Printf("  профиль:   %s\n", p.Remark)
	}
	if haveBackup {
		if b := cfg.Backup(); b != nil {
			fmt.Printf("  резерв:    %s\n", b.Remark)
		}
	} else {
		fmt.Println("  резерв:    нет (один профиль)")
	}
	fmt.Printf("  порты:     SOCKS %d · HTTP %d\n", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	switch {
	case cfg.Proxy0.Enabled:
		proto := cfg.Proxy0.Protocol
		if proto == "" {
			proto = "socks5"
		}
		fmt.Printf("  транспорт: Proxy0 / %s\n", proto)
	case cfg.WGTransport.Enabled:
		fmt.Printf("  транспорт: WireGuard (%s)\n", cfg.WGTransport.Iface)
	default:
		fmt.Println("  транспорт: только локальный прокси")
	}
	if l := presets.BoundList(cfg, "telegram"); l != nil {
		fmt.Printf("  telegram:  → %s\n", l.RouteIface())
	}
	if v, err := xraycore.Version(xrayBinaryPath()); err == nil {
		if i := strings.Index(v, " ("); i > 0 {
			v = v[:i]
		}
		fmt.Printf("  ядро:      %s\n", v)
	}
	fmt.Printf("  вариант:   %s\n", cfg.Variant)

	if p := cfg.Primary(); p != nil {
		addr := net.JoinHostPort(p.Address, strconv.Itoa(p.Port))
		fmt.Printf("  проверка %s … ", addr)
		if c, err := net.DialTimeout("tcp", addr, 5*time.Second); err != nil {
			fmt.Println("⚠️ не отвечает —", shortDialErr(err))
			fmt.Println("     (это адрес сервера, не туннель; проверь ссылку, если дальше не заработает)")
		} else {
			_ = c.Close()
			fmt.Println("✅ отвечает")
		}
	}

	if !watchdogArmed() {
		fmt.Println("\n⚠️ watchdog не активен — упавший демон не поднимется сам.")
		fmt.Println("   поставь cron:  opkg install cron  &&  keenetic-xray internal postinst-setup")
	}
	fmt.Println("\nдальше:  keenetic-xray status   ·   keenetic-xray doctor")
}

func shortDialErr(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "таймаут"
	case strings.Contains(s, "connection refused"):
		return "порт закрыт"
	case strings.Contains(s, "no such host"):
		return "хост не резолвится"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "network is unreachable"):
		return "нет маршрута"
	}
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

func watchdogArmed() bool {
	b, err := os.ReadFile(cronFilePath())
	return err == nil && strings.Contains(string(b), install.WatchdogMarker)
}

// promptIndex reads a line, re-prompting on invalid input; an empty line
// (just Enter) accepts def.
func promptIndex(reader *bufio.Reader, label string, count, def int) (int, error) {
	for {
		fmt.Printf("%s [0-%d, Enter — %d]: ", label, count-1, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return def, nil
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return def, nil
		}
		idx, err := strconv.Atoi(line)
		if err != nil || idx < 0 || idx >= count {
			fmt.Println("нет такого номера, ещё раз")
			continue
		}
		return idx, nil
	}
}
