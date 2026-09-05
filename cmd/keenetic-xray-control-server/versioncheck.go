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
// Silent on a first-ever run (versionFile doesn't exist yet -- nothing
// to compare against, and announcing "updated" on a fresh install would
// be wrong) and on an unchanged version (a plain restart -- a reboot, a
// crash, `systemctl restart` for some unrelated reason -- is not an
// update and must not be reported as one).
func notifyIfUpdated(versionFile string, notify func(string)) error {
	current := version.String()
	prev, err := os.ReadFile(versionFile)
	switch {
	case err == nil:
		if p := strings.TrimSpace(string(prev)); p != "" && p != current {
			notify(fmt.Sprintf("✅ Сервер обновлён: %s → %s", p, current))
		}
	case os.IsNotExist(err):
		// fresh install -- nothing to compare against, stay quiet.
	default:
		return fmt.Errorf("reading %s: %w", versionFile, err)
	}
	return os.WriteFile(versionFile, []byte(current), 0o644)
}
