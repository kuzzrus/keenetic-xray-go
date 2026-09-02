package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
)

const defaultConfigPath = "/etc/keenetic-xray-control-server/config.json"

// cmdSetup is the interactive first-run configurator: it walks the
// operator through building config.json, generates a bearer token per
// router, generates the TLS certificate, and prints the certificate
// fingerprint plus a ready-to-paste `keenetic-xray agent configure` line
// for each router. It is the server-side counterpart to `keenetic-xray
// setup` on the router.
func cmdSetup(configPath string) error {
	return runSetup(os.Stdin, os.Stdout, configPath, defaultSettings())
}

func runSetup(stdin io.Reader, stdout io.Writer, configPath string, defaults settings) error {
	in := bufio.NewReader(stdin)
	p := func(format string, a ...any) { fmt.Fprintf(stdout, format, a...) }

	p("Настройка keenetic-xray-control-server\n")
	p("Конфигурация будет записана в %s\n\n", configPath)

	if _, err := os.Stat(configPath); err == nil {
		yes, err := askYesNo(in, stdout, fmt.Sprintf("%s уже существует — перезаписать?", configPath), false)
		if err != nil {
			return err
		}
		if !yes {
			return fmt.Errorf("отменено; существующий конфиг не изменён")
		}
		p("\n")
	}

	s := defaults

	token, err := askNonEmpty(in, stdout, "Токен Telegram-бота (от @BotFather)")
	if err != nil {
		return err
	}
	if !looksLikeTelegramToken(token) {
		p("  примечание: не похоже на токен бота (<цифры>:<~35 символов>); продолжаю всё равно\n")
	}
	s.TelegramToken = token

	for {
		raw, err := askNonEmpty(in, stdout, "Разрешённые chat ID Telegram (числа через запятую)")
		if err != nil {
			return err
		}
		ids, perr := parseChatIDs(raw)
		if perr != nil {
			p("  %v; попробуйте ещё раз\n", perr)
			continue
		}
		s.AllowedChatIDs = ids
		break
	}

	n, err := askCount(in, stdout, "Сколько роутеров будет обслуживать этот сервер", 1)
	if err != nil {
		return err
	}
	s.Routers = make(map[string]string, n)
	type routerCred struct{ id, token string }
	creds := make([]routerCred, 0, n)
	for i := 0; i < n; i++ {
		var id string
		for {
			id, err = askNonEmpty(in, stdout, fmt.Sprintf("ID роутера %d (например, home-router)", i+1))
			if err != nil {
				return err
			}
			if _, dup := s.Routers[id]; dup {
				p("  %q уже занят; выберите другой\n", id)
				continue
			}
			break
		}
		tok, terr := randomToken()
		if terr != nil {
			return terr
		}
		s.Routers[id] = tok
		creds = append(creds, routerCred{id, tok})
		p("  сгенерирован токен для %s\n", id)
	}

	addr, err := askLine(in, stdout, fmt.Sprintf("Адрес прослушивания [%s]", s.ListenAddr))
	if err != nil {
		return err
	}
	if addr != "" {
		s.ListenAddr = addr
	}

	if err := s.save(configPath); err != nil {
		return err
	}
	p("\nЗаписано: %s (права 0600)\n", configPath)

	// Generate the certificate now so the operator gets the fingerprint
	// in this same run; LoadOrGenerateCert is a no-op on later starts.
	cert, err := botcontrol.LoadOrGenerateCert(s.CertPath, s.KeyPath, "keenetic-xray-control-server")
	if err != nil {
		return fmt.Errorf("генерация TLS-сертификата: %w", err)
	}
	fp, err := botcontrol.FingerprintSHA256(cert)
	if err != nil {
		return err
	}

	host := s.ListenAddr
	if strings.HasPrefix(host, ":") {
		host = "<this-server-host>" + host
	}
	p("\nОтпечаток сертификата (SHA-256):\n  %s\n", fp)
	p("\nНа каждом роутере (по SSH) выполните:\n")
	for _, c := range creds {
		p("  keenetic-xray agent configure https://%s %s %s %s\n", host, c.id, fp, c.token)
	}
	p("  keenetic-xray agent enable\n")
	p("\nЗатем запустите сервер:\n  systemctl enable --now keenetic-xray-control-server\n")
	return nil
}

func askLine(in *bufio.Reader, out io.Writer, prompt string) (string, error) {
	fmt.Fprintf(out, "%s: ", prompt)
	line, err := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" && err != nil {
		return "", fmt.Errorf("ошибка чтения ввода: %w", err)
	}
	return line, nil
}

func askNonEmpty(in *bufio.Reader, out io.Writer, prompt string) (string, error) {
	for {
		v, err := askLine(in, out, prompt)
		if err != nil {
			return "", err
		}
		if v != "" {
			return v, nil
		}
		fmt.Fprintln(out, "  обязательное поле")
	}
}

func askYesNo(in *bufio.Reader, out io.Writer, prompt string, def bool) (bool, error) {
	suffix := " [y/N]"
	if def {
		suffix = " [Y/n]"
	}
	line, err := askLine(in, out, prompt+suffix)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(line) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return def, nil
	}
}

func askCount(in *bufio.Reader, out io.Writer, prompt string, def int) (int, error) {
	for {
		line, err := askLine(in, out, fmt.Sprintf("%s [%d]", prompt, def))
		if err != nil {
			return 0, err
		}
		if line == "" {
			return def, nil
		}
		n, cerr := strconv.Atoi(line)
		if cerr == nil && n >= 1 && n <= 100 {
			return n, nil
		}
		fmt.Fprintln(out, "  введите число от 1 до 100")
	}
}

func parseChatIDs(raw string) ([]int64, error) {
	var ids []int64
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q — не число", part)
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("не указано ни одного chat ID")
	}
	return ids, nil
}

// looksLikeTelegramToken does a loose shape check ("<digits>:<rest>") so a
// pasted chat ID or an obvious typo gets a warning. It never rejects --
// only @BotFather and Telegram know what is really valid.
func looksLikeTelegramToken(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 || i >= len(s)-1 {
		return false
	}
	for _, r := range s[:i] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s[i+1:]) >= 30
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("генерация токена: %w", err)
	}
	return hex.EncodeToString(b), nil
}
