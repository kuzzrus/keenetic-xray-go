package main

import "os"

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

const defaultOptPath = "/opt"

func optPath() string {
	return envOr("KEENETIC_XRAY_OPT", defaultOptPath)
}

const defaultLogDir = "/opt/var/log/keenetic-xray"

func logDir() string {
	return envOr("KEENETIC_XRAY_LOG_DIR", defaultLogDir)
}

const defaultRunDir = "/opt/var/run"

func runDir() string {
	return envOr("KEENETIC_XRAY_RUN_DIR", defaultRunDir)
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
