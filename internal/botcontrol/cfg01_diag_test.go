package botcontrol

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/failover"
)

// TestCFG01_DiagnosticRepro deliberately recreates the PRE-FIX wiring
// (cmd/keenetic-xray's old cmdDaemon): one *config.Config shared, by the
// same pointer, between a running failover.Daemon and a RouterHandler
// whose Handle is hammered concurrently. Run manually with -race to
// confirm the diagnosis; not meant to be a permanent, always-green test
// (aliasing the pointer on purpose means -race should fire by
// construction, so this can't be a standing CI test).
func TestCFG01_DiagnosticRepro(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.Profiles = []config.Profile{testProfile("primary", "primary.invalid"), testProfile("backup", "backup.invalid")}
	cfg.PrimaryIndex = 0
	cfg.BackupIndex = 1
	cfg.Failover.CheckIntervalSeconds = 60

	paths := failover.Paths{
		XrayBinary:       os.Args[0],
		ProductionConfig: filepath.Join(dir, "production.json"),
		PretestConfig:    filepath.Join(dir, "pretest.json"),
		Env:              []string{"BOTCONTROL_TEST_HELPER=1"},
	}
	d := failover.NewDaemon(paths, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ran := d.State(ctx); ran {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// PRE-FIX wiring: RouterHandler.Config is the *same* pointer as cfg,
	// exactly like the old cmdDaemon used to pass to both NewDaemon and
	// RouterHandler.
	h := &RouterHandler{Daemon: d, Config: cfg}

	stop := time.Now().Add(1 * time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		other := config.Default()
		other.Profiles = cfg.Profiles
		other.PrimaryIndex, other.BackupIndex = 0, 1
		for time.Now().Before(stop) {
			d.ReloadConfig(ctx, other)
		}
	}()
	go func() {
		i := 0
		for time.Now().Before(stop) {
			i++
			p1 := 1090 + (i % 50)
			p2 := 2090 + (i % 50)
			_, _ = h.Handle(ctx, Command{Action: ActionSetPorts, Args: []string{strconv.Itoa(p1), strconv.Itoa(p2)}})
		}
	}()
	<-done
	time.Sleep(1200 * time.Millisecond)
}
