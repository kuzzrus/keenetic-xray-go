package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kuzzrus/keenetic-xray-go/internal/version"
)

// notifyIfUpdated compares the running version against what versionFile
// recorded on the *previous* run; if they differ, announces the change
// via notify. This is how the "⬆️ Обновить сервер" button's completion
// gets reported: that button just touches a trigger file, which a root
// oneshot (server-install.sh, re-run by the systemd .path unit) uses to
// replace the binary and restart the service -- the *old* process is
// killed mid-flight by that restart and can never announce its own
// replacement, so the *new* process announces itself here on startup
// instead, the same way any self-update actually completes.
//
// Also notifies (with different wording, since there's no "from"
// version to name) when versionFile doesn't exist yet -- which in
// practice almost never means a genuinely brand new install (by the
// time the service first starts, `setup` has already run and
// AllowedChatIDs is already populated, so there's always someone to
// tell) and instead usually means an *existing* server was just
// upgraded from a build that predates this file ever being written --
// exactly what happened the first time this feature itself shipped:
// silently doing nothing there was the actual bug, not a safeguard.
// Silent only on an unchanged version (a plain restart -- a reboot, a
// crash, `systemctl restart` for some unrelated reason -- is not an
// update and must not be reported as one).
func notifyIfUpdated(versionFile string, notify func(string)) error {
	current := version.String()
	data, err := os.ReadFile(versionFile)
	prev := ""
	if err == nil {
		prev = strings.TrimSpace(string(data))
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", versionFile, err)
	}

	switch {
	case prev == "":
		// Missing or empty file -- no "from" version worth naming,
		// whether that's this feature's own first rollout or a
		// genuinely fresh install.
		notify(fmt.Sprintf("✅ Сервер запущен: %s", current))
	case prev != current:
		notify(fmt.Sprintf("✅ Сервер обновлён: %s → %s", prev, current))
	}
	return os.WriteFile(versionFile, []byte(current), 0o644)
}
