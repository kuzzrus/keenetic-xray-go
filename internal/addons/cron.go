package addons

import (
	"context"
	"fmt"

	"github.com/kuzzrus/keenetic-xray-go/internal/install"
)

func init() { Register(cronAddon{}) }

// cronAddon is the Entware `cron` package. keenetic-xray's watchdog is a
// cron entry that restarts the failover daemon if it ever stops
// (rc.func doesn't do that on its own); no cron daemon -> no watchdog.
// Install/Remove/Status delegate to internal/install, which already
// owns the cron lifecycle for `watchdog enable`.
type cronAddon struct{}

func (cronAddon) ID() string    { return "cron" }
func (cronAddon) Title() string { return "cron — сторож демона (watchdog)" }

func (cronAddon) About() string {
	return "Демон cron. Сторож keenetic-xray — это запись в cron, которая раз в 2 минуты " +
		"перезапускает демон отказоустойчивости, если он почему-то не работает. Без cron " +
		"сторож не действует (упавший демон не поднимется сам). Настроек нет; " +
		"саму запись включает `keenetic-xray watchdog enable`."
}

func (cronAddon) Detect(ctx context.Context) State {
	running := install.CronRunning()
	v := opkgInstalledVersion(ctx, "cron")
	return State{
		Installed: v != "" || running,
		Running:   running,
		HasDaemon: true,
		Version:   v,
	}
}

func (cronAddon) Install(ctx context.Context) error {
	if err := install.EnsureCron(); err != nil {
		return fmt.Errorf("%w (на этом роутере пакет cron может быть недоступен — тогда сторож не поставить)", err)
	}
	return nil
}

func (cronAddon) Remove(ctx context.Context) error { return opkgRemove(ctx, "cron") }

func (cronAddon) Configure(context.Context, map[string]string) error { return errNoConfig }

func (cronAddon) Status(ctx context.Context) (string, error) {
	if install.CronRunning() {
		return "cron работает — сторож демона может действовать (`keenetic-xray watchdog enable`)", nil
	}
	return "cron не запущен — сторож демона неактивен", nil
}
