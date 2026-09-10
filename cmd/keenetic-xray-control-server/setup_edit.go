package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
)

// runSetupEdit is what `keenetic-xray-control-server setup` does on a
// server that's already configured: print every setting, let the
// operator change one (or a few, one at a time), then save. `setup
// --wizard` skips this and re-runs the full linear flow instead (see
// cmdSetup). Each editor item reuses the wizard's own prompt helpers so
// a field means exactly the same thing either way.
func runSetupEdit(in *bufio.Reader, out io.Writer, configPath string, s settings) error {
	p := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }
	changed := false
	for {
		printCurrentSettings(out, s)
		p("\nчто изменить? [1-4, w — мастер заново, Enter — выход] > ")
		line, err := in.ReadString('\n')
		choice := strings.ToLower(strings.TrimSpace(line))
		switch choice {
		case "":
			if err != nil {
				p("\n")
			}
			fallthrough
		case "q", "0", "exit", "quit", "выход":
			if changed {
				p("готово. не забудь перезапустить сервис, чтобы применилось:\n  systemctl restart keenetic-xray-control-server\n")
			} else {
				p("без изменений.\n")
			}
			return nil
		case "1":
			changed = editTelegramToken(in, out, &s, configPath) || changed
		case "2":
			changed = editChatIDs(in, out, &s, configPath) || changed
		case "3":
			changed = editListenAddr(in, out, &s, configPath) || changed
		case "4":
			changed = editPublicAddress(in, out, &s, configPath) || changed
		case "w", "wizard", "м", "мастер":
			// *bufio.Reader already satisfies io.Reader; runSetup wraps
			// it in its own bufio.NewReader, which is harmless (an extra
			// buffering layer, not a double-read) since nothing here
			// reads from `in` again after handing off control.
			//
			// Starts from s (the settings already on disk), not
			// defaultSettings() -- otherwise CertPath/KeyPath/QueuePath/
			// AutocertCacheDir, none of which the wizard ever prompts
			// for, would silently reset to hardcoded defaults (the same
			// bug cmdSetup's own --wizard dispatch had).
			return runSetup(in, out, configPath, s)
		default:
			p("нет такого пункта\n")
		}
	}
}

// printCurrentSettings is the field editor's always-on header. The
// Telegram token itself is never shown -- only whether one is set --
// same care internal/config.Redacted takes with router-side secrets.
func printCurrentSettings(out io.Writer, s settings) {
	fmt.Fprint(out, "\nТекущая настройка keenetic-xray-control-server\n\n")

	tok := "не задан"
	if s.TelegramToken != "" {
		tok = "задан"
	}
	fmt.Fprintf(out, "  1) Telegram-токен       %s\n", tok)

	ids := "не заданы"
	if len(s.AllowedChatIDs) > 0 {
		parts := make([]string, len(s.AllowedChatIDs))
		for i, id := range s.AllowedChatIDs {
			parts[i] = fmt.Sprintf("%d", id)
		}
		ids = strings.Join(parts, ", ")
	}
	fmt.Fprintf(out, "  2) Chat ID              %s\n", ids)

	fmt.Fprintf(out, "  3) Адрес прослушивания  %s\n", s.ListenAddr)

	switch {
	case s.Domain != "":
		fmt.Fprintf(out, "  4) Публичный адрес      %s (домен %s — Let's Encrypt)\n", orDash(s.PublicURL), s.Domain)
	case s.PublicURL != "":
		fmt.Fprintf(out, "  4) Публичный адрес      %s (без домена — self-signed + отпечаток)\n", s.PublicURL)
	default:
		fmt.Fprintf(out, "  4) Публичный адрес      не задан (без домена — self-signed + отпечаток)\n")
	}
}

func editTelegramToken(in *bufio.Reader, out io.Writer, s *settings, configPath string) bool {
	token, err := askNonEmpty(in, out, "Новый токен Telegram-бота (от @BotFather)")
	if err != nil {
		fmt.Fprintln(out, " ", err)
		return false
	}
	if !looksLikeTelegramToken(token) {
		fmt.Fprintln(out, "  примечание: не похоже на токен бота (<цифры>:<~35 символов>); сохраняю всё равно")
	}
	s.TelegramToken = token
	if err := saveSettings(*s, configPath, out); err != nil {
		return false
	}
	fmt.Fprintln(out, "  токен обновлён")
	return true
}

func editChatIDs(in *bufio.Reader, out io.Writer, s *settings, configPath string) bool {
	for {
		raw, err := askNonEmpty(in, out, "Разрешённые chat ID Telegram (числа через запятую)")
		if err != nil {
			fmt.Fprintln(out, " ", err)
			return false
		}
		ids, perr := parseChatIDs(raw)
		if perr != nil {
			fmt.Fprintf(out, "  %v; попробуйте ещё раз\n", perr)
			continue
		}
		s.AllowedChatIDs = ids
		break
	}
	if err := saveSettings(*s, configPath, out); err != nil {
		return false
	}
	fmt.Fprintln(out, "  chat ID обновлены")
	return true
}

func editListenAddr(in *bufio.Reader, out io.Writer, s *settings, configPath string) bool {
	addr, err := askLine(in, out, fmt.Sprintf("Адрес прослушивания [%s]", s.ListenAddr))
	if err != nil {
		fmt.Fprintln(out, " ", err)
		return false
	}
	if addr == "" || addr == s.ListenAddr {
		fmt.Fprintln(out, "  без изменений")
		return false
	}
	s.ListenAddr = addr
	// A domain-derived PublicURL embeds the old port -- keep it in sync
	// rather than silently pointing routers at a now-wrong port.
	if s.Domain != "" {
		s.PublicURL = "https://" + s.Domain + ":" + listenPort(s.ListenAddr)
	}
	if err := saveSettings(*s, configPath, out); err != nil {
		return false
	}
	fmt.Fprintf(out, "  адрес прослушивания: %s\n", addr)
	return true
}

func editPublicAddress(in *bufio.Reader, out io.Writer, s *settings, configPath string) bool {
	before := *s
	if err := promptPublicAddress(in, out, s); err != nil {
		fmt.Fprintln(out, " ", err)
		*s = before
		return false
	}
	if s.PublicURL == before.PublicURL && s.Domain == before.Domain {
		fmt.Fprintln(out, "  без изменений")
		return false
	}
	if err := saveSettings(*s, configPath, out); err != nil {
		*s = before
		return false
	}
	if s.Domain != "" {
		fmt.Fprintf(out, "  публичный адрес: %s (домен %s -- сертификат получится сам через Let's Encrypt при следующем запуске сервиса; нужен открытый порт 80)\n", s.PublicURL, s.Domain)
	} else {
		fmt.Fprintf(out, "  публичный адрес: %s (без домена)\n", orDash(s.PublicURL))
	}
	return true
}

// saveSettings persists s, generating the self-signed certificate first
// if it doesn't exist yet -- the editor can be reached even when a
// previous run only got partway through (e.g. a config hand-edited or
// restored without the cert files next to it).
func saveSettings(s settings, configPath string, out io.Writer) error {
	if err := s.save(configPath); err != nil {
		fmt.Fprintln(out, "  сохранение:", err)
		return err
	}
	if _, err := botcontrol.LoadOrGenerateCert(s.CertPath, s.KeyPath, "keenetic-xray-control-server"); err != nil {
		fmt.Fprintln(out, "  предупреждение: TLS-сертификат не проверен/не создан:", err)
	}
	return nil
}
