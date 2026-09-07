package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/addons"
	"github.com/kuzzrus/keenetic-xray-go/internal/applog"
	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/diskspace"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

// cmdDiag prints a one-shot diagnostic bundle to stdout: version, the
// config with every secret redacted, resolver / addon / RCI / Keenetic
// state, disk, and the tail of the daemon log. Safe to redirect to a
// file or paste into a chat. `keenetic-xray diag` on the router; the
// bot's diag action returns the same text.
func cmdDiag(args []string) error {
	writeDiag(os.Stdout)
	return nil
}

func writeDiag(w io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Fprintf(w, "==== keenetic-xray diag  %s ====\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "agent:     %s\n", version.String())
	if v, err := xrayCoreVersion(); err == nil {
		fmt.Fprintf(w, "xray-core: %s\n", v)
	} else {
		fmt.Fprintf(w, "xray-core: %v\n", err)
	}
	fmt.Fprintf(w, "arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if free, err := diskspace.FreeBytes(optPath()); err == nil {
		fmt.Fprintf(w, "free %s:  %d MB\n", optPath(), free/1024/1024)
	}

	cfg, cfgErr := config.Load(configPath())

	fmt.Fprintln(w, "\n---- config (secrets redacted) ----")
	if cfgErr != nil {
		fmt.Fprintf(w, "load %s: %v\n", configPath(), cfgErr)
	} else {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false) // a diag bundle is read by humans; keep <redacted> literal
		_ = enc.Encode(cfg.Redacted())
	}

	fmt.Fprintln(w, "\n---- local resolvers ----")
	rh := addons.ResolverHealth(ctx)
	if len(rh) == 0 {
		fmt.Fprintln(w, "(нет установленных unbound/dnscrypt)")
	}
	for _, r := range rh {
		if r.Resolves {
			fmt.Fprintf(w, "%s: резолвит на 127.0.0.1:%d\n", r.ID, r.Port)
		} else {
			fmt.Fprintf(w, "%s: НЕ резолвит на 127.0.0.1:%d (%s)\n", r.ID, r.Port, r.Detail)
		}
	}

	fmt.Fprintln(w, "\n---- addons ----")
	for _, a := range addons.All() {
		st := a.Detect(ctx)
		state := "не установлен"
		if st.Installed {
			state = "установлен"
			if st.HasDaemon {
				if st.Running {
					state += ", работает"
				} else {
					state += ", остановлен"
				}
			}
			if st.Detail != "" {
				state += " · " + st.Detail
			}
		}
		fmt.Fprintf(w, "%-10s %s\n", a.ID(), state)
	}

	fmt.Fprintln(w, "\n---- rci ----")
	if cfgErr == nil && cfg.RCI.Enabled {
		if base, _, err := rciProbe(cfg.RCI.BaseURL()); err == nil {
			fmt.Fprintf(w, "включён, отвечает: %s\n", base)
		} else {
			fmt.Fprintf(w, "включён, но: %v\n", err)
		}
	} else {
		fmt.Fprintln(w, "выключен (читаем через ndmc)")
	}

	fmt.Fprintln(w, "\n---- keenetic ----")
	if !keenetic.Available() {
		fmt.Fprintln(w, "ndmc/RCI недоступны — не на роутере")
	} else if maj, min, patch, err := keenetic.OSVersion(ctx); err == nil {
		fmt.Fprintf(w, "KeeneticOS %d.%d.%d\n", maj, min, patch)
	} else {
		fmt.Fprintf(w, "show version: %v\n", err)
	}

	fmt.Fprintln(w, "\n---- daemon log (last 80) ----")
	if tail, err := applog.Tail(daemonLogPath(), 80); err == nil {
		s := strings.TrimRight(tail, "\n")
		if s == "" {
			fmt.Fprintln(w, "(пусто)")
		} else {
			fmt.Fprintln(w, s)
		}
	} else {
		fmt.Fprintf(w, "%s: %v\n", daemonLogPath(), err)
	}
	fmt.Fprintln(w, "\n==== end ====")
}
