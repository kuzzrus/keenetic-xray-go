package main

import (
	"context"
	"errors"
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
// port, `enable`/`disable` flip config.RCI, `token` stores the access
// token KeeneticOS 5.2+ requires (all applied live over SIGHUP when a
// daemon runs).
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
		base, detail, err := rciProbe(url, cfg.RCI.Token)
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
	case "token":
		if len(args) == 1 {
			fmt.Println("токен RCI:", rciTokenState(cfg.RCI.Token))
			return nil
		}
		return rciSetToken(cfg, args[1])
	default:
		return fmt.Errorf("usage: keenetic-xray rci {show | probe [url] | enable [url] | disable | token [<token>|clear]}")
	}
}

func rciShow(cfg *config.Config) error {
	if cfg.RCI.Enabled {
		fmt.Printf("RCI: включён, база %s\n", cfg.RCI.BaseURL())
	} else {
		fmt.Printf("RCI: выключен (читаем конфиг через ndmc). Включить: keenetic-xray rci enable\n")
	}
	fmt.Println("токен:", rciTokenState(cfg.RCI.Token))
	if !cfg.RCI.Enabled {
		return nil
	}
	base, _, err := rciProbe(cfg.RCI.BaseURL(), cfg.RCI.Token)
	if err != nil {
		fmt.Println("проверка:", err)
		fmt.Print(rciAuthHint(err))
		return nil
	}
	fmt.Printf("проверка: отвечает (%s)\n", base)
	return nil
}

// rciTokenState says whether a token is set without showing any of it.
func rciTokenState(token string) string {
	if token == "" {
		return "не задан (нужен только на KeeneticOS 5.2+)"
	}
	return fmt.Sprintf("задан (%d символов)", len(token))
}

// rciAuthHint is the next step after RCI refused a request (HTTP
// 401/403), or "" for any other error.
func rciAuthHint(err error) string {
	if !errors.Is(err, keenetic.ErrRCIAuth) {
		return ""
	}
	return "KeeneticOS 5.2+ пускает в RCI только с токеном: веб-интерфейс роутера → Пользователи и доступ → Токены доступа → Добавить токен, затем:\n  keenetic-xray rci token <токен>\n"
}

// rciCandidates is the base URL(s) to try: the explicit one, else
// KeeneticOS's local RCI port. Port 79 on loopback answers /rci/* (no
// credentials up to 5.1, a token from 5.2); :80 is the web UI.
func rciCandidates(explicit string) []string {
	if e := strings.TrimRight(strings.TrimSpace(explicit), "/"); e != "" {
		return []string{e}
	}
	return []string{"http://127.0.0.1:79", "http://127.0.0.1:80"}
}

// rciProbe GETs /rci/show/version + /rci/show/running-config on each
// candidate, with token when it isn't empty, and returns the first base
// that answers both, plus a short human detail block. Quiet -- callers
// decide whether to print.
func rciProbe(explicit, token string) (base, detail string, err error) {
	hc := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	var lastErr error
	for _, b := range rciCandidates(explicit) {
		verBytes, e := rciGet(hc, b+"/rci/show/version", token)
		if e != nil {
			lastErr = fmt.Errorf("%s: /rci/show/version: %w", b, e)
			continue
		}
		cfgBytes, e := rciGet(hc, b+"/rci/show/running-config", token)
		if e != nil {
			lastErr = fmt.Errorf("%s: /rci/show/running-config: %w", b, e)
			continue
		}
		return b, fmt.Sprintf("  show/version:        %s\n  show/running-config: %d байт\n",
			firstLine(string(verBytes)), len(cfgBytes)), nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ни один адрес не ответил")
	}
	return "", "", fmt.Errorf("RCI недоступен: %w", lastErr)
}

func rciGet(hc *http.Client, url, token string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set(keenetic.RCITokenHeader, token)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("HTTP %d: %w", resp.StatusCode, keenetic.ErrRCIAuth)
	case resp.StatusCode != http.StatusOK:
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
	base, _, err := rciProbe(url, cfg.RCI.Token)
	if err != nil {
		if hint := rciAuthHint(err); hint != "" {
			return fmt.Errorf("%w\n%s", err, strings.TrimRight(hint, "\n"))
		}
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
	_, _ = keenetic.UseRCI("", "") // no-op if this process isn't the daemon
	applyDaemonChange(nil, false)
	fmt.Println("RCI выключен — читаем конфиг через ndmc.")
	return nil
}

// rciSetToken stores (or, given "clear", removes) the RCI access token
// and reports whether RCI accepts it. It never prints the token back.
func rciSetToken(cfg *config.Config, value string) error {
	value = strings.TrimSpace(value)
	switch value {
	case "clear", "off", "-":
		value = ""
	default:
		if !config.ValidRCIToken(value) {
			return fmt.Errorf("это не похоже на токен RCI: ожидается одна строка из латиницы, цифр и +/=_.- длиной от 16 символов")
		}
	}
	cfg.RCI.Token = value
	if err := cfg.Save(configPath()); err != nil {
		return err
	}
	if value == "" {
		fmt.Println("токен RCI удалён")
	} else {
		fmt.Println("токен RCI сохранён")
	}
	if _, _, err := rciProbe(cfg.RCI.BaseURL(), value); err != nil {
		fmt.Println("проверка:", err)
		fmt.Print(rciAuthHint(err))
	} else {
		fmt.Println("проверка: RCI отвечает")
		if !cfg.RCI.Enabled {
			fmt.Println("RCI-режим выключен — включить: keenetic-xray rci enable")
		}
	}
	if cfg.RCI.Enabled {
		applyDaemonChange(nil, false)
	}
	return nil
}
