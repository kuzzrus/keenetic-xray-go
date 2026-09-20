package botcontrol

import (
	"context"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
)

// TestReloadRace_ConcurrentSIGHUPAndBotCommands is CFG-01's regression
// test: it stresses the ConfigReload handoff itself under -race, using
// the real post-fix wiring -- RouterHandler.Config is a fully independent
// *config.Config from Daemon's own cfg, exactly like cmd/keenetic-xray's
// cmdDaemon now constructs them (a second config.Load, never the same
// pointer). One goroutine simulates rapid SIGHUP reloads, mirroring
// main.go's own handler: an independent object for the daemon side via
// Daemon.ReloadConfig, and a *separate* independent object Store()d into
// ConfigReload for the bot side -- never the same object passed to both,
// which is itself part of what this test guards (see ConfigReload's own
// doc comment for why reusing one object for both would reintroduce a
// narrower race). Another goroutine dispatches Handle calls that mutate
// config directly (setPorts), the same way a live bot command would.
// go test -race must find nothing.
func TestReloadRace_ConcurrentSIGHUPAndBotCommands(t *testing.T) {
	d := newTestDaemon(t)
	ctx := context.Background()

	profiles := []config.Profile{testProfile("primary", "primary.invalid"), testProfile("backup", "backup.invalid")}
	botCfg := config.Default()
	botCfg.Profiles = profiles
	botCfg.PrimaryIndex, botCfg.BackupIndex = 0, 1
	h := &RouterHandler{Daemon: d, Config: botCfg, ConfigPath: filepath.Join(t.TempDir(), "config.json")}

	stop := time.Now().Add(1 * time.Second)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(stop) {
			daemonFresh := config.Default()
			daemonFresh.Profiles = profiles
			daemonFresh.PrimaryIndex, daemonFresh.BackupIndex = 0, 1
			d.ReloadConfig(ctx, daemonFresh)

			botFresh := config.Default()
			botFresh.Profiles = profiles
			botFresh.PrimaryIndex, botFresh.BackupIndex = 0, 1
			h.ConfigReload.Store(botFresh)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for time.Now().Before(stop) {
			i++
			p1 := strconv.Itoa(1090 + i%50)
			p2 := strconv.Itoa(2090 + i%50)
			_, _ = h.Handle(ctx, Command{Action: ActionSetPorts, Args: []string{p1, p2}})
		}
	}()

	wg.Wait()
}
