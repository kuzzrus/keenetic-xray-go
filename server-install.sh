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
RELEASE_JSON="$(fetch "$API_URL")"
ASSET_URL="$(printf '%s\n' "$RELEASE_JSON" \
    | grep -o "\"browser_download_url\": *\"[^\"]*keenetic-xray-control-server-linux-${ARCH}\"" \
    | sed -e 's/.*"\(https[^"]*\)"/\1/' \
    | head -n 1)"
[ -n "$ASSET_URL" ] || die "no keenetic-xray-control-server-linux-${ARCH} asset in the latest release (${API_URL})"
# goreleaser publishes a single sha256 checksums.txt alongside every
# release's binaries (see .goreleaser.yaml's `checksum:` block) -- same
# release response, so it can't disagree with $ASSET_URL on version.
CHECKSUMS_URL="$(printf '%s\n' "$RELEASE_JSON" \
    | grep -o '"browser_download_url": *"[^"]*checksums\.txt"' \
    | sed -e 's/.*"\(https[^"]*\)"/\1/' \
    | head -n 1)"
[ -n "$CHECKSUMS_URL" ] || die "no checksums.txt asset in the latest release (${API_URL})"

echo "server-install: downloading ${ASSET_URL}"
TMP_BIN="$(mktemp)"
PREV_BIN=""
# A no-op once mv below succeeds (nothing left at $TMP_BIN to remove);
# guards the case where fetch/checksum/smoke fails first and set -e exits
# early. $PREV_BIN only exists once the backup below is actually made
# (empty until then; `rm -f ""` is a silent no-op), and is cleared again
# once a rollback consumes it.
trap 'rm -f "$TMP_BIN" "$PREV_BIN"' EXIT
fetch "$ASSET_URL" "$TMP_BIN"

# INST-03: the old version of this script went straight from download to
# `mv` onto the live path -- no checksum, no smoke test, and no way back
# if the new binary turned out to be broken (wrong arch, truncated
# download, bad build). Verify against goreleaser's own checksums.txt
# first, then prove the binary actually runs, before it ever touches
# $BIN_PATH.
WANT_SUM="$(fetch "$CHECKSUMS_URL" | grep "  keenetic-xray-control-server-linux-${ARCH}\$" | awk '{print $1}' | head -n 1)"
[ -n "$WANT_SUM" ] || die "no checksum for keenetic-xray-control-server-linux-${ARCH} in ${CHECKSUMS_URL}"
GOT_SUM="$(sha256sum "$TMP_BIN" | awk '{print $1}')"
[ "$GOT_SUM" = "$WANT_SUM" ] || die "checksum mismatch for ${ASSET_URL}: got ${GOT_SUM}, want ${WANT_SUM}"

chmod 0755 "$TMP_BIN"
"$TMP_BIN" version >/dev/null 2>&1 \
    || die "downloaded binary does not run ('$TMP_BIN version' failed its smoke test) -- not installing it"

# Keep the previous binary around so a new version that passes its own
# smoke test but still fails to actually run as the service (bad config
# migration, a runtime-only crash) can be rolled back automatically below,
# instead of leaving the server on a broken binary with no way back short
# of a manual reinstall.
if [ -e "$BIN_PATH" ]; then
    PREV_BIN="$(mktemp)"
    cp -p "$BIN_PATH" "$PREV_BIN"
fi
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
    # INST-04: /dev/tty existing as a device node doesn't prove anyone is
    # actually there to answer prompts -- e.g. this installer invoked
    # from an automated/unattended provisioning pipeline where /dev/tty
    # still resolves to some stale controlling terminal. Bound the wait
    # so that case fails into the same "finish manually" guidance the
    # no-tty branch below already gives, instead of hanging indefinitely
    # -- and, since this runs under `set -eu`, an unguarded failure here
    # would otherwise abort the whole script before the chown/
    # systemctl-enable steps below ever run.
    _setup_ok=1
    if command -v timeout >/dev/null 2>&1; then
        KEENETIC_XRAY_CS_CONFIG="${CONFIG_DIR}/config.json" timeout 300 "$BIN_PATH" setup </dev/tty || _setup_ok=0
    else
        KEENETIC_XRAY_CS_CONFIG="${CONFIG_DIR}/config.json" "$BIN_PATH" setup </dev/tty || _setup_ok=0
    fi
    if [ "$_setup_ok" = 0 ]; then
        echo "server-install: setup wizard failed, was cancelled, or timed out -- finish manually:" >&2
        echo "  KEENETIC_XRAY_CS_CONFIG=${CONFIG_DIR}/config.json ${BIN_PATH} setup" >&2
        echo "  systemctl enable --now keenetic-xray-control-server" >&2
    fi
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
    exit 0
fi

echo "server-install: the service did not come up; recent logs:" >&2
journalctl -u keenetic-xray-control-server -n 20 --no-pager >&2 || true

# The new binary smoke-tested fine standalone but still failed as the
# actual service (bad config migration, a runtime-only crash) -- roll
# back to whatever was running before this install/update, if anything.
[ -n "$PREV_BIN" ] || die "the service failed to start and there is no previous binary to roll back to"

echo "server-install: rolling back to the previously installed binary" >&2
mv "$PREV_BIN" "$BIN_PATH"
PREV_BIN=""
systemctl restart keenetic-xray-control-server || true
if systemctl is-active --quiet keenetic-xray-control-server; then
    echo "server-install: rolled back -- the previous binary is running again" >&2
else
    echo "server-install: rollback restart also failed; recent logs:" >&2
    journalctl -u keenetic-xray-control-server -n 20 --no-pager >&2 || true
fi
exit 1
