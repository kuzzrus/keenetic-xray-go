package main

import (
	"os"
	"path/filepath"
)

const defaultConfigPath = "/opt/etc/keenetic-xray/config.json"

func configPath() string {
	return envOr("KEENETIC_XRAY_CONFIG", defaultConfigPath)
}

const defaultXrayBinary = "/opt/sbin/xray"

func xrayBinaryPath() string {
	return envOr("KEENETIC_XRAY_BINARY", defaultXrayBinary)
}

const defaultProductionConfigPath = "/opt/var/lib/keenetic-xray/xray-production.json"

func productionConfigPath() string {
	return envOr("KEENETIC_XRAY_PRODUCTION_CONFIG", defaultProductionConfigPath)
}

const defaultPretestConfigPath = "/opt/var/lib/keenetic-xray/xray-pretest.json"

func pretestConfigPath() string {
	return envOr("KEENETIC_XRAY_PRETEST_CONFIG", defaultPretestConfigPath)
}

// qualitySweepConfigPath is the scratch xray config the all-profiles
// quality sweep rewrites once per probed profile.
func qualitySweepConfigPath() string {
	return envOr("KEENETIC_XRAY_SWEEP_CONFIG", "/opt/var/lib/keenetic-xray/xray-sweep.json")
}

// qualityStatePath is where the quality sweep persists its last run, read
// by `keenetic-xray status` and the bot heartbeat.
func qualityStatePath() string {
	return envOr("KEENETIC_XRAY_QUALITY_STATE", logDir()+"/quality.json")
}

// selfUpdateMarkerPath is where a self-update drops its rollback marker
// (selfupdate.Marker): the version it left + the .ipk URL to get back.
// Read by the post-update watcher and `internal self-rollback`.
func selfUpdateMarkerPath() string {
	return envOr("KEENETIC_XRAY_SELFUPDATE_MARKER", logDir()+"/self-update.json")
}

const defaultOptPath = "/opt"

func optPath() string {
	return envOr("KEENETIC_XRAY_OPT", defaultOptPath)
}

const defaultLogDir = "/opt/var/log/keenetic-xray"

// daemonLogPath is the daemon's own rolling activity log (applog): its
// startup/reconcile lines plus supervised xray-core stderr. Read by
// `keenetic-xray logs` and the bot's daemon_log action.
func daemonLogPath() string {
	return envOr("KEENETIC_XRAY_DAEMON_LOG", logDir()+"/daemon.log")
}

func logDir() string {
	return envOr("KEENETIC_XRAY_LOG_DIR", defaultLogDir)
}

// watchdogLogPath is where the watchdog cron entry appends a line each
// time it actually restarts the daemon (not on every routine check) --
// see install.SetWatchdogCron. Under logDir so `menu`'s existing log
// tail already picks it up alongside anything else logged there.
func watchdogLogPath() string {
	return envOr("KEENETIC_XRAY_WATCHDOG_LOG", logDir()+"/watchdog.log")
}

// watchdogScriptPath is the small shell script the watchdog cron entry
// runs. It's a file rather than an inline crontab command because
// busybox crond echoes the whole command of every job to syslog on each
// tick -- an inline snippet would litter the router log every couple of
// minutes (see install.SetWatchdogCron). Kept next to config.json so a
// package purge (install.PrermCleanup) removes it along with everything
// else under the config dir.
func watchdogScriptPath() string {
	return envOr("KEENETIC_XRAY_WATCHDOG_SCRIPT", filepath.Dir(configPath())+"/watchdog.sh")
}

const defaultRunDir = "/opt/var/run"

func runDir() string {
	return envOr("KEENETIC_XRAY_RUN_DIR", defaultRunDir)
}

// netfilterHookPath is the ndm firewall-rebuild hook this project ships
// (packaging/ndm/netfilter.d/50-keenetic-xray.sh) -- it SIGUSR1's the
// daemon so a reconcile runs the instant ndm touches the firewall.
func netfilterHookPath() string {
	return envOr("KEENETIC_XRAY_NETFILTER_HOOK", "/opt/etc/ndm/netfilter.d/50-keenetic-xray.sh")
}

// ndmHookPaths is every ndm hook script the package installs -- the
// firewall-rebuild one plus the ifipchanged / ifstatechanged siblings
// (see packaging/ndm/*). opkg deletes them with the package; prerm
// cleanup drops them too in case a botched removal leaves a copy behind
// SIGUSR1'ing a dead PID. The KEENETIC_XRAY_NETFILTER_HOOK override
// still names the firewall hook so existing tests keep working; the
// other two derive from the same directory root.
func ndmHookPaths() []string {
	nf := netfilterHookPath()
	ndmRoot := filepath.Dir(filepath.Dir(nf)) // .../ndm/netfilter.d -> .../ndm
	base := filepath.Base(nf)                 // 50-keenetic-xray.sh
	return []string{
		nf,
		filepath.Join(ndmRoot, "ifipchanged.d", base),
		filepath.Join(ndmRoot, "ifstatechanged.d", base),
	}
}

// presetsOverlayDir is where internal/presets.Refresh keeps the daily
// repo-refreshed routing-list presets. Next to config.json so a package
// purge (install.PrermCleanup) clears it too; the embedded copy is the
// fallback when it's absent.
func presetsOverlayDir() string {
	return envOr("KEENETIC_XRAY_PRESETS_DIR", filepath.Dir(configPath())+"/presets")
}

const defaultAgentTokenFile = "/opt/etc/keenetic-xray/agent-token.secret"

func defaultAgentTokenPath() string {
	return envOr("KEENETIC_XRAY_AGENT_TOKEN_FILE", defaultAgentTokenFile)
}

// defaultCronFile is Entware's per-user crontab (dcron/vixie-cron
// convention -- confirmed against the reference project's own scheduled
// recovery entries, internal/install.SetWatchdogCron).
const defaultCronFile = "/opt/var/spool/cron/crontabs/root"

func cronFilePath() string {
	return envOr("KEENETIC_XRAY_CRON_FILE", defaultCronFile)
}

// pidFilePath is where `keenetic-xray daemon` records its own PID, so a
// CLI command run afterward (setup, subscription, proxy0, failover set)
// can find it and signal a live config reload -- see signalDaemonReload
// in daemonctl.go. Deliberately project-controlled rather than reusing
// whatever pidfile rc.func manages internally: that path/format isn't
// part of any documented contract here.
func pidFilePath() string {
	return envOr("KEENETIC_XRAY_PID_FILE", runDir()+"/keenetic-xray.pid")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
