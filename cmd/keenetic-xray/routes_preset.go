package main

import (
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/presets"
)

// routesPreset drives `keenetic-xray routes preset …`: browse the
// built-in curated lists (internal/presets), bind one to a route list,
// and re-sync a bound list when a newer agent build ships a fresher
// version. The bot's 📦 Готовые списки screen calls the same
// presets.Apply / presets.Sync / presets.Drift.
func routesPreset(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return routesUsage()
	}
	presets.SetOverlay(presetsOverlayDir())
	switch args[0] {
	case "list", "ls":
		return presetList(cfg)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: routes preset show <name>")
		}
		return presetShow(cfg, args[1])
	case "add":
		return presetAdd(cfg, args[1:])
	case "sync":
		return presetSyncCmd(cfg, args[1:])
	case "update":
		return cmdRoutesPresetUpdate(cfg)
	default:
		return routesUsage()
	}
}

func presetList(cfg *config.Config) error {
	fmt.Printf("встроенные списки (обновляются в репозитории, сборка от %s)\n\n", presets.Generated())
	for _, cat := range presets.ByCategory() {
		fmt.Printf("  %s\n", cat.Name)
		for _, p := range cat.Presets {
			mark := ""
			if l := presets.BoundList(cfg, p.Name); l != nil {
				if a, r, _, _ := presets.Drift(*l); a+r > 0 {
					mark = fmt.Sprintf("⬆ +%d−%d", a, r)
				} else {
					mark = "✓"
				}
			}
			ip := ""
			if presets.HasCIDR(p.Name) {
				ip = " +IP"
			}
			fmt.Printf("    %-16s %4d дом.%-5s %s\n", p.Name, p.Count, ip, mark)
		}
	}
	fmt.Println("\nдобавить: keenetic-xray routes preset add <name> [--ip]")
	return nil
}

func presetShow(cfg *config.Config, name string) error {
	p, ok := presets.Find(name)
	if !ok {
		return fmt.Errorf("нет встроенного списка %q (см. routes preset list)", name)
	}
	fmt.Printf("%s — %s\n", p.Name, p.Title)
	fmt.Printf("  категория:  %s\n", p.Category)
	fmt.Printf("  вид:        %s, записей: %d\n", p.Kind, p.Count)
	fmt.Printf("  версия:     %s\n", p.Rev)
	if len(p.Sources) > 0 {
		fmt.Printf("  источники:  %s\n", strings.Join(p.Sources, ", "))
	}
	if p.Kind == "domains" && presets.HasCIDR(p.Name) {
		if ipp, ok := presets.Find(p.Name + "-ip"); ok {
			fmt.Printf("  +IP-список: %s-ip (%d подсетей)\n", p.Name, ipp.Count)
		}
	}
	if l := presets.BoundList(cfg, p.Name); l != nil {
		a, r, _, _ := presets.Drift(*l)
		state := "актуально"
		if a+r > 0 {
			state = fmt.Sprintf("есть обновление: +%d −%d (routes preset sync %s)", a, r, p.Name)
		}
		fmt.Printf("  применён:   да, %s\n", state)
	} else {
		fmt.Printf("  применён:   нет\n")
	}
	return nil
}

func presetAdd(cfg *config.Config, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: routes preset add <name> [--ip] [--iface=Proxy0|Wireguard4] [--exclusive]")
	}
	name := args[0]
	var withIP, exclusive bool
	iface := ""
	for _, a := range args[1:] {
		switch {
		case a == "--ip":
			withIP = true
		case a == "--exclusive":
			exclusive = true
		case strings.HasPrefix(a, "--iface="):
			iface = strings.TrimPrefix(a, "--iface=")
		default:
			return fmt.Errorf("неизвестный флаг %q", a)
		}
	}

	names, err := presets.Apply(cfg, name, withIP, iface, exclusive)
	if err != nil {
		return err
	}
	return routesApply(cfg, fmt.Sprintf("пресет применён: %s", strings.Join(names, ", ")))
}

func presetSyncCmd(cfg *config.Config, args []string) error {
	target := ""
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			target = a
		}
	}
	res, err := presets.Sync(cfg, target)
	if err != nil {
		return err
	}
	if len(res) == 0 {
		fmt.Println("нечего синхронизировать (нет привязанных к пресетам списков)")
		return nil
	}
	changed := 0
	for _, r := range res {
		fmt.Printf("  %-16s +%d −%d\n", r.Name, r.Added, r.Removed)
		if r.Added+r.Removed > 0 {
			changed++
		}
	}
	if changed == 0 {
		fmt.Println("всё уже актуально")
		return nil
	}
	return routesApply(cfg, fmt.Sprintf("синхронизировано списков: %d", changed))
}
