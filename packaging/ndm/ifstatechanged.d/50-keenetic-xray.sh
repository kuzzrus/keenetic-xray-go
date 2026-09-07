#!/bin/sh
# Keenetic's ndm runs /opt/etc/ndm/ifstatechanged.d/* when an
# interface's status changes, exporting $system_name, $up (up/down),
# $link, $connected and $change. When an interface this project keeps
# config on comes back up -- the in-router WireGuard transport
# (WireguardN) or a Proxy interface after a firmware event -- the object
# groups and routes bound to it may have been dropped. Only react to an
# "up" transition (nothing to re-assert onto a down interface) and let
# the daemon decide what's actually stale; it re-runs a full reconcile,
# debounced, so a WAN flap that fires this repeatedly still costs one
# pass.

# shellcheck disable=SC2154  # $up is exported by ndm
[ "$up" = "up" ] || exit 0

PIDFILE="${KEENETIC_XRAY_PID_FILE:-/opt/var/run/keenetic-xray.pid}"
[ -f "$PIDFILE" ] || exit 0
# Line 1 is the PID; line 2, when present, is a start-time token the CLI
# uses to spot PID reuse (see writeDaemonPIDFile). Only the PID matters here.
read -r PID < "$PIDFILE" 2>/dev/null
[ -n "$PID" ] && [ -d "/proc/$PID" ] && kill -USR1 "$PID" 2>/dev/null

exit 0
