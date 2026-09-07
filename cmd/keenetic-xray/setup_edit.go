package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// runSetupEdit is what `keenetic-xray setup` does on a router that's
// already configured: print every setting, let the operator change one
// (or a few, one at a time), then apply. `setup --wizard` skips this and
// re-runs the full linear flow. Each editor reuses the wizard's own
// prompt helpers so a field means exactly the same thing either way.
func runSetupEdit(reader *bufio.Reader, cfg *config.Config, o setupOpts) error {
	changed := false
	for {
		printCurrentConfig(cfg)
		fmt.Print("\nчто изменить? [1-5, w — мастер заново, Enter — выход] > ")
		line, err := reader.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "":
			if err != nil {
				fmt.Println()
			}
			fallthrough
		case "q", "0", "exit", "quit", "выход":
			if changed {
				applyDaemonChange(reader, true)
				fmt.Println("готово.")
			} else {
				fmt.Println("без изменений.")
			}
			return nil
		case "1":
			changed = editPrimary(reader, cfg) || changed
		case "2":
			changed = editBackup(reader, cfg) || changed
		case "3":
			changed = editPorts(reader, cfg, o) || changed
		case "4":
			changed = editTransport(reader, cfg, o) || changed
		case "5":
			changed = editTelegramRoute(reader, cfg) || changed
		case "w", "wizard", "м", "мастер":
			return runSetupInteractive(reader, cfg, o)
		default:
			fmt.Println("нет такого пункта")
		}
	}
}

// printCurrentConfig is the field editor's always-on header: the five
// editable settings with their current values, numbered to match the
// prompt.
func printCurrentConfig(cfg *config.Config) {
	fmt.Print("\nТекущая настройка keenetic-xray\n\n")

	if p := cfg.Primary(); p != nil {
		fmt.Printf("  1) основной профиль    %s%s\n", p.Remark, sourceSuffix(cfg.PrimarySource))
	} else {
		fmt.Println("  1) основной профиль    —")
	}

	if cfg.BackupSource != nil {
		if b := cfg.Backup(); b != nil {
			fmt.Printf("  2) резервный профиль   %s%s\n", b.Remark, sourceSuffix(cfg.BackupSource))
		} else {
			fmt.Println("  2) резервный профиль   (источник задан, профиль не разобран)")
		}
	} else {
		fmt.Println("  2) резервный профиль   нет (один профиль, автопереключения не будет)")
	}

	fmt.Printf("  3) порты               SOCKS %d · HTTP %d\n", cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort)
	fmt.Printf("  4) транспорт           %s\n", transportSummary(cfg))

	tg := "нет"
	if l := presets.BoundList(cfg, "telegram"); l != nil && !l.Disabled {
		tg = "→ " + l.RouteIface()
	}
	fmt.Printf("  5) Telegram в туннель  %s\n", tg)
}

// transportSummary is the one-line "how router traffic reaches xray"
// label -- shared by the field editor's header and the end-of-wizard
// recap so both read identically.
func transportSummary(cfg *config.Config) string {
	switch {
	case cfg.WGTransport.Enabled && cfg.WGTransport.Iface != "":
		return "WireGuard (" + cfg.WGTransport.Iface + ")"
	case cfg.Proxy0.Enabled:
		proto := cfg.Proxy0.Protocol
		if proto == "" {
			proto = "socks5"
		}
		return "Proxy0 / " + proto
	default:
		return "только локальный прокси"
	}
}

// sourceSuffix renders "   ← vless://…@host" for the editor header, or ""
// when there's no recorded source. Secrets (the vless UUID, a
// subscription token in the path) are never shown.
func sourceSuffix(s *config.SlotSource) string {
	if s == nil || s.URL == "" {
		return ""
	}
	return "   ← " + sourceLabel(s.URL)
}

func sourceLabel(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(источник задан)"
	}
	switch u.Scheme {
	case "vless":
		return "vless://…@" + u.Host
	case "http", "https":
		tail := ""
		if p := strings.Trim(u.Path, "/"); p != "" {
			tail = "/…"
		}
		return u.Scheme + "://" + u.Host + tail
	default:
		return u.Scheme + "://" + u.Host
	}
}

func editPrimary(reader *bufio.Reader, cfg *config.Config) bool {
	res, err := promptSlotSource(reader, cfg, "основной", false)
	if err != nil {
		fmt.Println("  ", err)
		return false
	}
	cfg.PrimaryIndex = cfg.UpsertProfile(res.profile)
	cfg.PrimarySource = &config.SlotSource{URL: res.src, Selector: res.selector}
	// No independent backup means single-profile mode: keep the backup
	// slot mirroring the (now new) primary so the daemon just supervises.
	if cfg.BackupSource == nil {
		cfg.BackupIndex = cfg.PrimaryIndex
	}
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  сохранение:", err)
		return false
	}
	fmt.Printf("  основной: %s\n", res.profile.Remark)
	return true
}

func editBackup(reader *bufio.Reader, cfg *config.Config) bool {
	res, err := promptSlotSource(reader, cfg, "резервный", true)
	switch {
	case errors.Is(err, errSlotSkipped):
		cfg.BackupSource = nil
		cfg.BackupIndex = cfg.PrimaryIndex
		fmt.Println("  резервный: убран — один профиль, автопереключения не будет")
	case err != nil:
		fmt.Println("  ", err)
		return false
	default:
		cfg.BackupIndex = cfg.UpsertProfile(res.profile)
		cfg.BackupSource = &config.SlotSource{URL: res.src, Selector: res.selector}
		fmt.Printf("  резервный: %s\n", res.profile.Remark)
	}
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  сохранение:", err)
		return false
	}
	return true
}

func editPorts(reader *bufio.Reader, cfg *config.Config, o setupOpts) bool {
	oldS, oldH := cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort
	// Clear any flag-supplied ports so the editor always prompts.
	o.SOCKSPort, o.HTTPPort = 0, 0
	sp, hp, err := promptPorts(reader, cfg, o)
	if err != nil {
		fmt.Println("  ", err)
		return false
	}
	if sp == oldS && hp == oldH {
		fmt.Println("  порты не изменились")
		return false
	}
	cfg.Failover.SOCKSPort, cfg.Failover.HTTPPort = sp, hp
	if err := cfg.Save(configPath()); err != nil {
		fmt.Println("  сохранение:", err)
		return false
	}
	fmt.Printf("  порты: SOCKS %d · HTTP %d\n", sp, hp)
	return true
}

func editTransport(reader *bufio.Reader, cfg *config.Config, o setupOpts) bool {
	if !keenetic.Available() {
		fmt.Println("  не Keenetic — транспорт настраивать нечем (только локальный прокси)")
		return false
	}
	before := transportSummary(cfg)
	// promptTransport reads o.Proxy0 first; clear it so the menu shows.
	o.Proxy0 = ""
	promptTransport(reader, cfg, o) // saves the config itself in each branch
	after := transportSummary(cfg)
	if before == after {
		fmt.Println("  транспорт не изменился")
		return false
	}
	fmt.Printf("  транспорт: %s\n", after)
	return true
}

func editTelegramRoute(reader *bufio.Reader, cfg *config.Config) bool {
	iface := transportIface(cfg)
	if iface == "" || !keenetic.Available() {
		fmt.Println("  нет транспорта — сначала настрой п.4")
		return false
	}
	l := presets.BoundList(cfg, "telegram")
	if l != nil && !l.Disabled {
		fmt.Printf("  Telegram сейчас идёт через %s. Отключить? [y/N]: ", l.RouteIface())
		line, _ := reader.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes", "д", "да":
			for _, n := range []string{"telegram", "telegram-ip"} {
				if bl := presets.BoundList(cfg, n); bl != nil {
					bl.Disabled = true
				}
			}
			if err := routesApply(cfg, "Telegram убран из туннеля"); err != nil {
				fmt.Println("  ", err)
				return false
			}
			return true
		default:
			return false
		}
	}
	// Not routed yet -> the wizard's turn-on path (asks, applies).
	promptTelegramRoute(reader, cfg)
	if bl := presets.BoundList(cfg, "telegram"); bl != nil && !bl.Disabled {
		return true
	}
	return false
}
