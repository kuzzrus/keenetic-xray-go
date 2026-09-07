package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/keenetic"
)

// cmdRCI manages reading the router config over Keenetic's local RCI
// JSON API instead of `ndmc -c`. A hedge for firmware that sandboxes
// Entware away from ndmc; writes still use ndmc. `probe` finds a working
// port, `enable`/`disable` flip config.RCI (applied on the next daemon
// start / SIGHUP).
func cmdRCI(args []string) error {
	if len(args) == 0 {
		args = []string{"show"}
	}
	cfg, err := config.Load(configPath())
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		return rciShow(cfg)
	case "probe":
		var url string
		if len(args) > 1 {
			url = args[1]
		}
		base, detail, err := rciProbe(url)
		if err != nil {
			return err
		}
		fmt.Printf("%s — OK\n%s", base, detail)
		return nil
	case "enable", "on":
		var url string
		if len(args) > 1 {
			url = args[1]
		}
		return rciEnable(cfg, url)
	case "disable", "off":
		return rciDisable(cfg)
	default:
		return fmt.Errorf("usage: keenetic-xray rci {show | probe [url] | enable [url] | disable}")
	}
}

func rciShow(cfg *config.Config) error {
	if cfg.RCI.Enabled {
		fmt.Printf("RCI: включён, база %s\n", cfg.RCI.BaseURL())
	} else {
		fmt.Printf("RCI: выключен (читаем конфиг через ndmc). Включить: keenetic-xray rci enable\n")
	}
	if !cfg.RCI.Enabled {
		return nil
	}
	base, _, err := rciProbe(cfg.RCI.BaseURL())
	if err != nil {
		fmt.Println("проверка:", err)
		return nil
	}
	fmt.Printf("проверка: отвечает (%s)\n", base)
	return nil
}

// rciCandidates is the base URL(s) to try: the explicit one, else the
// historical command port then the web port.
func rciCandidates(explicit string) []string {
	if e := strings.TrimRight(strings.TrimSpace(explicit), "/"); e != "" {
		return []string{e}
	}
	return []string{"http://127.0.0.1:79", "http://127.0.0.1:80", "http://127.0.0.1:81"}
}

// rciProbe GETs /ci/running-config.txt + /rci/show/version on each
// candidate and returns the first base that answers both, plus a short
// human detail block. Quiet -- callers decide whether to print.
func rciProbe(explicit string) (base, detail string, err error) {
	hc := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	var lastErr error
	for _, b := range rciCandidates(explicit) {
		cfgBytes, e := rciGet(hc, b+"/ci/running-config.txt")
		if e != nil {
			lastErr = fmt.Errorf("%s: %w", b, e)
			continue
		}
		verBytes, e := rciGet(hc, b+"/rci/show/version")
		if e != nil {
			lastErr = fmt.Errorf("%s: /rci/show/version: %w", b, e)
			continue
		}
		return b, fmt.Sprintf("  running-config: %d байт\n  show/version:   %s\n",
			len(cfgBytes), firstLine(string(verBytes))), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ни один адрес не ответил")
	}
	return "", "", fmt.Errorf("RCI недоступен: %w", lastErr)
}

func rciGet(hc *http.Client, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return b, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func rciEnable(cfg *config.Config, url string) error {
	base, _, err := rciProbe(url)
	if err != nil {
		return err
	}
	cfg.RCI.Enabled = true
	// Only pin a non-default URL; keep "" so DefaultRCIURL tracks any
	// future change.
	if base == config.DefaultRCIURL {
		cfg.RCI.URL = ""
	} else {
		cfg.RCI.URL = base
	}
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	// Apply now if a daemon is running.
	applyDaemonChange(nil, false)
	fmt.Printf("RCI включён (%s). Конфиг роутера теперь читается по RCI; записи по-прежнему через ndmc.\n", base)
	return nil
}

func rciDisable(cfg *config.Config) error {
	cfg.RCI.Enabled = false
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	_, _ = keenetic.UseRCI("") // no-op if this process isn't the daemon
	applyDaemonChange(nil, false)
	fmt.Println("RCI выключен — читаем конфиг через ndmc.")
	return nil
}
