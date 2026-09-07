#!/bin/sh
# Keenetic's ndm runs /opt/etc/ndm/ifipchanged.d/* whenever an
# interface's IPv4 address or subnet changes. That's the case the
# 2-minute reconcile tick is slowest on: the router's LAN IP moved, so
# the Proxy0 upstream host this project configured now points at the old
# address and LAN clients can't reach xray until the daemon re-detects
# it. Nudge it to reconcile now (re-runs LANIP detection + re-asserts
# Proxy0 / MSS / routes / WG-transport).

PIDFILE="${KEENETIC_XRAY_PID_FILE:-/opt/var/run/keenetic-xray.pid}"
[ -f "$PIDFILE" ] || exit 0
# Line 1 is the PID; line 2, when present, is a start-time token the CLI
# uses to spot PID reuse (see writeDaemonPIDFile). Only the PID matters here.
read -r PID < "$PIDFILE" 2>/dev/null
[ -n "$PID" ] && [ -d "/proc/$PID" ] && kill -USR1 "$PID" 2>/dev/null

exit 0
