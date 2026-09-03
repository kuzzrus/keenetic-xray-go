#!/bin/sh
# server-install.sh -- one-shot installer for keenetic-xray-control-server
# on a systemd VPS. It:
#   1. downloads the latest release binary for this host's architecture
#      into /usr/local/bin,
#   2. creates a "keenetic-xray" system user and the config/state dirs,
#   3. installs a hardened systemd unit,
#   4. runs the interactive `setup` wizard (writes config.json, generates
#      a bearer token per router, prints the cert fingerprint), and
#   5. enables and starts the service.
#
# The router installer (install.sh) is unrelated -- this one never runs
# on a router.
#
# Usage (on the VPS, as root):
#   curl -fsSL https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh | sudo sh
set -eu

REPO="kuzzrus/keenetic-xray-go"
RAW="https://raw.githubusercontent.com/${REPO}/main/packaging/server"
BIN_PATH="/usr/local/bin/keenetic-xray-control-server"
UNIT_PATH="/etc/systemd/system/keenetic-xray-control-server.service"
UNIT_URL="${RAW}/keenetic-xray-control-server.service"
UPDATE_SVC_PATH="/etc/systemd/system/keenetic-xray-control-server-update.service"
UPDATE_PATH_PATH="/etc/systemd/system/keenetic-xray-control-server-update.path"
SELF_UPDATE_SCRIPT="/usr/local/lib/keenetic-xray/control-server-self-update.sh"
CONFIG_DIR="/etc/keenetic-xray-control-server"
STATE_DIR="/var/lib/keenetic-xray-control-server"
SVC_USER="keenetic-xray"

die() { echo "server-install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (pipe into 'sudo sh', or run 'sudo sh server-install.sh')"
[ -d /run/systemd/system ] || die "this installer targets systemd only; /run/systemd/system is not present"
command -v useradd >/dev/null 2>&1 || die "useradd not found; create the '${SVC_USER}' user manually and re-run"

# fetch <url> [outfile] -- prints to stdout when no outfile is given.
# Prefers curl; falls back to wget. Mirrors install.sh: some minimal
# wget builds can't do HTTPS, and vice versa on other boxes.
fetch() {
    _url="$1"
    _out="${2:-}"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$_out" ]; then curl -fsSL "$_url" -o "$_out"; else curl -fsSL "$_url"; fi
    else
        if [ -n "$_out" ]; then wget -qO "$_out" "$_url"; else wget -qO- "$_url"; fi
    fi
}

case "$(uname -m)" in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "unsupported architecture '$(uname -m)' -- prebuilt control-server binaries exist for amd64 and arm64 only" ;;
esac
echo "server-install: architecture ${ARCH}"

API_URL="https://api.github.com/repos/${REPO}/releases/latest"
ASSET_URL="$(fetch "$API_URL" \
    | grep -o "\"browser_download_url\": *\"[^\"]*keenetic-xray-control-server-linux-${ARCH}\"" \
    | sed -e 's/.*"\(https[^"]*\)"/\1/' \
    | head -n 1)"
[ -n "$ASSET_URL" ] || die "no keenetic-xray-control-server-linux-${ARCH} asset in the latest release (${API_URL})"

echo "server-install: downloading ${ASSET_URL}"
TMP_BIN="$(mktemp)"
fetch "$ASSET_URL" "$TMP_BIN"
chmod 0755 "$TMP_BIN"
mv "$TMP_BIN" "$BIN_PATH"

id "$SVC_USER" >/dev/null 2>&1 \
    || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin "$SVC_USER"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 0700 "$CONFIG_DIR" "$STATE_DIR"

echo "server-install: installing the systemd unit"
fetch "$UNIT_URL" "$UNIT_PATH"

# Self-update path: the control-server runs unprivileged and can't swap
# its own binary or restart itself. The .path unit watches a trigger file
# the service *can* create (the Telegram "Обновить сервер" button), and
# fires a root oneshot that re-runs this installer.
echo "server-install: installing the self-update units"
install -d -m 0755 /usr/local/lib/keenetic-xray
fetch "${RAW}/control-server-self-update.sh" "$SELF_UPDATE_SCRIPT"
chmod 0755 "$SELF_UPDATE_SCRIPT"
fetch "${RAW}/keenetic-xray-control-server-update.service" "$UPDATE_SVC_PATH"
fetch "${RAW}/keenetic-xray-control-server-update.path" "$UPDATE_PATH_PATH"
systemctl daemon-reload
systemctl enable --now keenetic-xray-control-server-update.path >/dev/null 2>&1 || true

# Re-running the installer is the update path: the new binary is already
# in place above. Only run the wizard on a first install (no config yet);
# otherwise keep the existing config untouched -- reconfigure later with
# `keenetic-xray-control-server setup`.
if [ -s "${CONFIG_DIR}/config.json" ]; then
    echo "server-install: config already present -- keeping it (run 'keenetic-xray-control-server setup' to change it)"
elif [ -e /dev/tty ]; then
    echo "server-install: running the setup wizard"
    KEENETIC_XRAY_CS_CONFIG="${CONFIG_DIR}/config.json" "$BIN_PATH" setup </dev/tty
else
    echo "server-install: no controlling terminal -- finish manually:" >&2
    echo "  KEENETIC_XRAY_CS_CONFIG=${CONFIG_DIR}/config.json ${BIN_PATH} setup" >&2
    echo "  systemctl enable --now keenetic-xray-control-server" >&2
    exit 0
fi

chown -R "${SVC_USER}:${SVC_USER}" "$CONFIG_DIR" "$STATE_DIR"

# `enable` (persist) + `restart` (start if stopped, replace the running
# process if not) -- `enable --now` alone would leave an already-running
# old binary in place on an update.
echo "server-install: (re)starting the service"
systemctl enable keenetic-xray-control-server >/dev/null 2>&1 || true
systemctl restart keenetic-xray-control-server

if systemctl is-active --quiet keenetic-xray-control-server; then
    VERSION="$("$BIN_PATH" version 2>/dev/null || echo '?')"
    echo "server-install: keenetic-xray-control-server $VERSION is running"
else
    echo "server-install: the service did not come up; recent logs:" >&2
    journalctl -u keenetic-xray-control-server -n 20 --no-pager >&2 || true
    exit 1
fi
