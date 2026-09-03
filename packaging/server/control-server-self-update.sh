#!/bin/sh
# control-server-self-update.sh -- run as root by
# keenetic-xray-control-server-update.service, which is triggered by the
# .path unit when the unprivileged control-server creates
# /var/lib/keenetic-xray-control-server/update.request (the Telegram
# "Обновить сервер" button).
#
# It just re-runs server-install.sh, whose re-run path downloads the
# latest release binary, keeps config.json untouched, reinstalls the
# units and restarts the service.
set -eu

REQ=/var/lib/keenetic-xray-control-server/update.request
INSTALLER=https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh

# Clear the trigger first so the .path unit re-arms and a later button
# press fires again.
rm -f "$REQ"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$INSTALLER" | sh
else
    wget -qO- "$INSTALLER" | sh
fi
