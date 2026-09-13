#!/bin/sh
# control-server-self-update.sh -- run as root by
# keenetic-xray-control-server-update.service, which is triggered by the
# .path unit when the unprivileged control-server creates
# /var/lib/keenetic-xray-control-server/update.request (the Telegram
# "Обновить сервер" button).
#
# It just re-runs server-install.sh, whose re-run path downloads the
# latest release binary, keeps config.json untouched, reinstalls the
# units and restarts the service. On success the *new* process reports
# its own arrival (see notifyIfUpdated in cmd/keenetic-xray-control-server) --
# but on failure nothing else ever will: the old process is still running
# and has no way to know this ran at all, so this script DMs the
# configured chats itself before exiting non-zero.
set -u

REQ=/var/lib/keenetic-xray-control-server/update.request
INSTALLER=https://raw.githubusercontent.com/kuzzrus/keenetic-xray-go/main/server-install.sh
CONFIG=/etc/keenetic-xray-control-server/config.json
TMP=/tmp/keenetic-xray-server-install.$$.sh

# Clear the trigger first so the .path unit re-arms and a later button
# press fires again.
rm -f "$REQ"

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
else
    fetch() { wget -qO "$2" "$1"; }
fi

# Download-then-run, not `fetch ... | sh`: a pipeline's exit status is the
# *last* command's -- a fetch failure that produces no output would leave
# `sh` running an empty script and exiting 0, masking the real failure
# just as it did on the router agent's own self-update before the same
# fix there (internal/botcontrol/commands.go's selfUpdate).
if fetch "$INSTALLER" "$TMP"; then
    sh "$TMP"
    rc=$?
else
    rc=$?
fi
rm -f "$TMP"

if [ "$rc" -ne 0 ] && command -v curl >/dev/null 2>&1; then
    token=$(sed -n 's/.*"telegram_token": *"\([^"]*\)".*/\1/p' "$CONFIG" 2>/dev/null | head -1)
    chats=$(sed -n '/"allowed_chat_ids"/,/]/p' "$CONFIG" 2>/dev/null | grep -o -- '-\{0,1\}[0-9]\{1,\}')
    if [ -n "$token" ]; then
        for chat in $chats; do
            curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
                -d "chat_id=${chat}" \
                --data-urlencode "text=⚠️ Самообновление control-server не удалось (код $rc). Подробности: journalctl -u keenetic-xray-control-server-update.service" \
                >/dev/null 2>&1
        done
    fi
fi

exit "$rc"
