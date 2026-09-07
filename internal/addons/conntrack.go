package addons

import "context"

func init() { Register(conntrackAddon{}) }

// conntrackAddon is the Entware `conntrack` package (the CLI tool, not
// conntrack-tools). keenetic-xray uses it after a routes change to drop
// stale connection-tracking entries so open connections move onto the
// new path; without it that step is silently skipped.
type conntrackAddon struct{}

func (conntrackAddon) ID() string { return "conntrack" }
func (conntrackAddon) Title() string {
	return "conntrack — сброс соединений при смене маршрута"
}

func (conntrackAddon) About() string {
	return "Утилита conntrack. После смены маршрута (routes/preset) keenetic-xray сбрасывает " +
		"через неё записи отслеживания соединений, чтобы уже открытые соединения переехали на " +
		"новый путь. Без пакета этот шаг просто пропускается. Настроек нет."
}

func (conntrackAddon) Detect(ctx context.Context) State {
	v := opkgInstalledVersion(ctx, "conntrack")
	return State{Installed: v != "", Version: v}
}

func (conntrackAddon) Install(ctx context.Context) error { return opkgInstall(ctx, "conntrack") }
func (conntrackAddon) Remove(ctx context.Context) error  { return opkgRemove(ctx, "conntrack") }

func (conntrackAddon) Configure(context.Context, map[string]string) error {
	return errNoConfig
}

func (conntrackAddon) Status(ctx context.Context) (string, error) {
	if v := opkgInstalledVersion(ctx, "conntrack"); v != "" {
		return "conntrack " + v + " установлен — сброс соединений при смене маршрута работает", nil
	}
	return "conntrack не установлен — смена маршрута не сбрасывает открытые соединения", nil
}
