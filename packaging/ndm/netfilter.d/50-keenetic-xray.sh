#!/bin/sh
# Keenetic's ndm runs every /opt/etc/ndm/netfilter.d/* script whenever it
# rebuilds the firewall, exporting $type (iptables/ip6tables) and $table
# (filter/nat/mangle/raw). When it touches a table this project keeps
# rules in, nudge the daemon to re-assert its Proxy0 / MSS-clamp / route /
# WG-transport config right away -- the daemon also polls every 2 minutes,
# but this makes the common "rule vanished after a policy edit" case
# self-heal within a second.

# shellcheck disable=SC2154  # $type / $table are exported by ndm
[ "$type" = "iptables" ] || exit 0
case "$table" in
    mangle | filter) ;;
    *) exit 0 ;;
esac

PIDFILE="${KEENETIC_XRAY_PID_FILE:-/opt/var/run/keenetic-xray.pid}"
[ -f "$PIDFILE" ] || exit 0
PID=$(cat "$PIDFILE" 2>/dev/null)
[ -n "$PID" ] && [ -d "/proc/$PID" ] && kill -USR1 "$PID" 2>/dev/null

exit 0
