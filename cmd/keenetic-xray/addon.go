package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
)

// cmdAddon drives the optional router-side components (unbound, nfqws2,
// conntrack, cron) through internal/addons. The bot's 🧩 Дополнения
// screen calls the same package, so CLI and bot behave identically.
func cmdAddon(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch args[0] {
	case "list", "ls":
		return addonList(ctx)
	case "show":
		if len(args) < 2 {
			return fmt.Errorf("usage: keenetic-xray addon show <id>")
		}
		return addonShow(ctx, args[1])
	case "status":
		if len(args) < 2 {
			return fmt.Errorf("usage: keenetic-xray addon status <id>")
		}
		return addonStatus(ctx, args[1])
	case "install":
		if len(args) < 2 {
			return fmt.Errorf("usage: keenetic-xray addon install <id>")
		}
		return addonInstall(ctx, args[1])
	case "remove", "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: keenetic-xray addon remove <id>")
		}
		return addonRemove(ctx, args[1])
	case "configure", "config", "set":
		if len(args) < 3 {
			return fmt.Errorf("usage: keenetic-xray addon configure <id> <key=value>…")
		}
		return addonConfigure(ctx, args[1], args[2:])
	default:
		return fmt.Errorf("usage: keenetic-xray addon {list | show <id> | status <id> | install <id> | remove <id> | configure <id> <k=v>…}")
	}
}

func addonFind(id string) (addons.Addon, error) {
	a, ok := addons.Find(id)
	if !ok {
		var ids []string
		for _, x := range addons.All() {
			ids = append(ids, x.ID())
		}
		return nil, fmt.Errorf("нет компонента %q (есть: %s)", id, strings.Join(ids, ", "))
	}
	return a, nil
}

func addonList(ctx context.Context) error {
	for _, a := range addons.All() {
		st := a.Detect(ctx)
		mark := "⬜"
		if st.Installed {
			mark = "✅"
		}
		line := fmt.Sprintf("%s %-10s %s", mark, a.ID(), a.Title())
		var tail []string
		if st.Version != "" {
			tail = append(tail, st.Version)
		}
		if st.Installed && st.HasDaemon {
			if st.Running {
				tail = append(tail, "работает")
			} else {
				tail = append(tail, "остановлен")
			}
		}
		if st.Detail != "" {
			tail = append(tail, st.Detail)
		}
		if len(tail) > 0 {
			line += "  · " + strings.Join(tail, " · ")
		}
		fmt.Println(line)
	}
	fmt.Println("\nподробнее:  keenetic-xray addon show <id>")
	return nil
}

func addonShow(ctx context.Context, id string) error {
	a, err := addonFind(id)
	if err != nil {
		return err
	}
	st := a.Detect(ctx)
	fmt.Printf("%s — %s\n\n", a.ID(), a.Title())
	fmt.Println(a.About())
	fmt.Println()
	switch {
	case !st.Installed:
		fmt.Println("состояние: не установлен  →  keenetic-xray addon install " + id)
	case st.HasDaemon && !st.Running:
		fmt.Println("состояние: установлен, остановлен")
	default:
		fmt.Println("состояние: установлен" + detailSuffix(st))
	}
	return nil
}

func detailSuffix(st addons.State) string {
	if st.Detail != "" {
		return " · " + st.Detail
	}
	return ""
}

func addonStatus(ctx context.Context, id string) error {
	a, err := addonFind(id)
	if err != nil {
		return err
	}
	out, err := a.Status(ctx)
	if err != nil {
		return err
	}
	fmt.Println(out)
	return nil
}

func addonInstall(ctx context.Context, id string) error {
	a, err := addonFind(id)
	if err != nil {
		return err
	}
	if a.Detect(ctx).Installed {
		fmt.Printf("%s уже установлен\n", id)
		return nil
	}
	fmt.Printf("ставлю %s…\n", id)
	if err := a.Install(ctx); err != nil {
		return err
	}
	out, _ := a.Status(ctx)
	fmt.Println(out)
	return nil
}

func addonRemove(ctx context.Context, id string) error {
	a, err := addonFind(id)
	if err != nil {
		return err
	}
	if !a.Detect(ctx).Installed {
		fmt.Printf("%s не установлен\n", id)
		return nil
	}
	fmt.Printf("удаляю %s…\n", id)
	if err := a.Remove(ctx); err != nil {
		return err
	}
	fmt.Printf("%s удалён\n", id)
	return nil
}

func addonConfigure(ctx context.Context, id string, kvArgs []string) error {
	a, err := addonFind(id)
	if err != nil {
		return err
	}
	kv, err := addons.ParseKV(kvArgs)
	if err != nil {
		return err
	}
	if err := a.Configure(ctx, kv); err != nil {
		return err
	}
	fmt.Printf("%s: настройки применены\n", id)
	out, _ := a.Status(ctx)
	if out != "" {
		fmt.Println(out)
	}
	return nil
}
