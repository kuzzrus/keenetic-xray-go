#!/bin/sh
# Keenetic's ndm runs every /opt/etc/ndm/netfilter.d/* script whenever it
# rebuilds the firewall, exporting $type (iptables/ip6tables) and $table
# (filter/nat/mangle/raw). When it touches a table this project keeps
# rules in, nudge the daemon to re-assert them right away -- the daemon
# also polls every 2 minutes, but this makes the common "rule vanished
# after a policy edit or a DHCP renew" case self-heal within a second.
#
# Our tables: filter (l7sni's NFLOG in FORWARD), mangle (the MSS clamp),
# nat (adaptive routing's REDIRECT in PREROUTING). nat used to be missing
# here, so a nat rebuild left adaptive-routed traffic going direct until
# the next 2-minute poll.

# shellcheck disable=SC2154  # $type / $table are exported by ndm
[ "$type" = "iptables" ] || exit 0
case "$table" in
    filter | mangle | nat) ;;
    *) exit 0 ;;
esac

PIDFILE="${KEENETIC_XRAY_PID_FILE:-/opt/var/run/keenetic-xray.pid}"
[ -f "$PIDFILE" ] || exit 0
# Line 1 is the PID; line 2, when present, is a start-time token the CLI
# uses to spot PID reuse (see writeDaemonPIDFile). Only the PID matters here.
read -r PID < "$PIDFILE" 2>/dev/null
[ -n "$PID" ] && [ -d "/proc/$PID" ] && kill -USR1 "$PID" 2>/dev/null

exit 0
