package botcontrol

import (
	"context"
	"fmt"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
)

// The addon_* actions drive the optional router-side components
// (unbound, nfqws2, conntrack, cron) through internal/addons -- the same
// package `keenetic-xray addon …` uses, so the bot's 🧩 Дополнения
// screen and the CLI behave identically. addon_list is machine-readable
// (TSV) so the bot can render one button per component; the rest return
// human text.

func (h *RouterHandler) addonList(ctx context.Context) (string, error) {
	var b strings.Builder
	for _, a := range addons.All() {
		st := a.Detect(ctx)
		inst := "0"
		if st.Installed {
			inst = "1"
		}
		run := "-"
		if st.Installed && st.HasDaemon {
			run = "0"
			if st.Running {
				run = "1"
			}
		}
		// id \t title \t installed \t running \t version \t detail.
		// "-" stands in for an empty version/detail so no field is ever
		// blank -- a trailing empty tab-field is fragile to trim on the
		// way back (parseAddonList).
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\n",
			a.ID(), a.Title(), inst, run, dashIfEmpty(st.Version), dashIfEmpty(oneLine(st.Detail)))
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

func (h *RouterHandler) addonFind(args []string) (addons.Addon, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("addon: не указан компонент")
	}
	a, ok := addons.Find(args[0])
	if !ok {
		return nil, fmt.Errorf("нет компонента %q", args[0])
	}
	return a, nil
}

func (h *RouterHandler) addonShow(ctx context.Context, args []string) (string, error) {
	a, err := h.addonFind(args)
	if err != nil {
		return "", err
	}
	st := a.Detect(ctx)
	var b strings.Builder
	fmt.Fprintf(&b, "%s — %s\n\n%s\n\n", a.ID(), a.Title(), a.About())
	switch {
	case !st.Installed:
		b.WriteString("состояние: не установлен")
	case st.HasDaemon && !st.Running:
		b.WriteString("состояние: установлен, остановлен")
	default:
		b.WriteString("состояние: установлен")
		if st.Detail != "" {
			b.WriteString(" · " + st.Detail)
		}
	}
	return b.String(), nil
}

func (h *RouterHandler) addonStatus(ctx context.Context, args []string) (string, error) {
	a, err := h.addonFind(args)
	if err != nil {
		return "", err
	}
	return a.Status(ctx)
}

func (h *RouterHandler) addonInstall(ctx context.Context, args []string) (string, error) {
	a, err := h.addonFind(args)
	if err != nil {
		return "", err
	}
	if a.Detect(ctx).Installed {
		return a.ID() + ": уже установлен", nil
	}
	if err := a.Install(ctx); err != nil {
		return "", err
	}
	out, _ := a.Status(ctx)
	return a.ID() + ": установлен\n" + out, nil
}

func (h *RouterHandler) addonRemove(ctx context.Context, args []string) (string, error) {
	a, err := h.addonFind(args)
	if err != nil {
		return "", err
	}
	if !a.Detect(ctx).Installed {
		return a.ID() + ": не установлен", nil
	}
	if err := a.Remove(ctx); err != nil {
		return "", err
	}
	return a.ID() + ": удалён", nil
}

func (h *RouterHandler) addonConfigure(ctx context.Context, args []string) (string, error) {
	a, err := h.addonFind(args)
	if err != nil {
		return "", err
	}
	kv, err := addons.ParseKV(args[1:])
	if err != nil {
		return "", err
	}
	if err := a.Configure(ctx, kv); err != nil {
		return "", err
	}
	out, _ := a.Status(ctx)
	return a.ID() + ": настройки применены\n" + out, nil
}

// oneLine flattens any newlines so a value is safe in a TSV field.
func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\t", " ")
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
