package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/botcontrol"
)

const defaultConfigPath = "/etc/keenetic-xray-control-server/config.json"

// lookupHost is net.LookupHost, overridable in tests so the domain step's
// sanity check doesn't depend on real DNS/network access.
var lookupHost = net.LookupHost

// cmdSetup is `keenetic-xray-control-server setup`: on a fresh install
// it's the interactive first-run configurator (builds config.json,
// generates the TLS certificate, prints the fingerprint plus a
// ready-to-paste `keenetic-xray agent configure` line). On an
// already-configured server it instead opens the field editor (show
// every setting, change one) -- same "wizard first time, editor after"
// split as `keenetic-xray setup` on the router (setup_edit.go there);
// --wizard forces the full walk-through either way.
func cmdSetup(configPath string, args []string) error {
	wizard := false
	for _, a := range args {
		switch a {
		case "--wizard":
			wizard = true
		default:
			return fmt.Errorf("setup: unexpected argument %q", a)
		}
	}

	existing, loadErr := loadSettings(configPath)
	if !wizard && loadErr == nil {
		return runSetupEdit(bufio.NewReader(os.Stdin), os.Stdout, configPath, existing)
	}
	// Also the --wizard-on-an-already-configured-server path: start from
	// the existing settings (so CertPath/KeyPath/QueuePath/
	// AutocertCacheDir -- none of which the wizard ever prompts for --
	// carry over instead of silently resetting to hardcoded defaults)
	// rather than defaultSettings(), unless there's truly nothing to
	// carry over (first run).
	defaults := defaultSettings()
	if loadErr == nil {
		defaults = existing
	}
	return runSetup(os.Stdin, os.Stdout, configPath, defaults)
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

	addr, err := askLine(in, stdout, fmt.Sprintf("Адрес прослушивания [%s]", s.ListenAddr))
	if err != nil {
		return err
	}
	if addr != "" {
		s.ListenAddr = addr
	}

	if err := promptPublicAddress(in, stdout, &s); err != nil {
		return err
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

	p("\nОтпечаток self-signed сертификата (SHA-256):\n  %s\n", fp)
	if s.Domain != "" {
		p("\nДомен %s: сертификат получим сами через Let's Encrypt при первом запуске (нужен открытый порт 80 у VPS/security group).\n", s.Domain)
		p("Новые роутеры настраивай БЕЗ отпечатка (3 аргумента agent configure, не 4) -- доверие идёт через сертификат, а не пиннинг.\n")
		p("Отпечаток self-signed выше по-прежнему нужен, если когда-нибудь настроишь роутер по IP вместо домена.\n")
	}
	p("\nЗапустите сервер:\n  systemctl enable --now keenetic-xray-control-server\n")
	p("\nЗатем добавляйте роутеры прямо в чате бота:\n  /add_router <id> [имя]\nБот вернёт готовую строку keenetic-xray agent configure для этого роутера.\n")
	return nil
}

// listenPort pulls just the port out of a listen address like ":8443" or
// "0.0.0.0:8443" -- used to build PublicURL from a bare domain without
// asking the operator to retype the port they already gave above.
func listenPort(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil {
		return port
	}
	return strings.TrimPrefix(addr, ":")
}

// promptPublicAddress asks for the plain PublicURL, then whether a
// domain (ACME instead of self-signed + pinning) should override it --
// shared by the first-run wizard and the field editor's own "публичный
// адрес / домен" item so the two mean exactly the same thing. Mutates s
// in place; a "yes" to the domain question always wins over whatever
// PublicURL was just typed, matching the original wizard's ordering.
func promptPublicAddress(in *bufio.Reader, out io.Writer, s *settings) error {
	p := func(format string, a ...any) { fmt.Fprintf(out, format, a...) }

	pub, err := askLine(in, out, fmt.Sprintf("Публичный адрес сервера для роутеров, напр. https://vps.example.com:8443 [%s]", orDash(s.PublicURL)))
	if err != nil {
		return err
	}
	if pub != "" {
		s.PublicURL = pub
	}

	hasDomain, err := askYesNo(in, out, "Есть домен, указывающий A-записью на этот сервер? (тогда сертификат получаем сами через Let's Encrypt, вместо self-signed + отпечатка)", s.Domain != "")
	if err != nil {
		return err
	}
	if !hasDomain {
		s.Domain = ""
		return nil
	}

	domain, err := askLine(in, out, fmt.Sprintf("Домен (без схемы и порта, напр. vps.example.com) [%s]", orDash(s.Domain)))
	if err != nil {
		return err
	}
	if domain == "" {
		domain = s.Domain
	}
	if domain == "" {
		return fmt.Errorf("отменено; домен не указан")
	}
	if _, lerr := lookupHost(domain); lerr != nil {
		p("  не резолвится прямо сейчас (%v) -- если домен только что заведён, DNS ещё не разошёлся\n", lerr)
		cont, err := askYesNo(in, out, "  продолжить всё равно?", true)
		if err != nil {
			return err
		}
		if !cont {
			return fmt.Errorf("отменено; домен не резолвится")
		}
	}
	s.Domain = domain
	if s.AutocertCacheDir == "" {
		s.AutocertCacheDir = defaultSettings().AutocertCacheDir
	}
	s.PublicURL = "https://" + domain + ":" + listenPort(s.ListenAddr)
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
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
