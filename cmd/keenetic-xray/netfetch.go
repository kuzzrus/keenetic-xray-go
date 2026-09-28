package main

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/netfetch"
)

// The router's own tunnel -- the production xray's local SOCKS inbound --
// is internal/netfetch's last way out for this binary's downloads:
// xray-core, naive and susanin updates, presets, the RU range list,
// subscriptions, the rollback .ipk. The port is read from the config on
// every use, since a bot action can change it; on a first install no
// xray runs yet, and that step just fails fast. cmdDaemon points Logf at
// daemon.log; the CLI prints to stderr.
func init() {
	netfetch.TunnelSOCKS = tunnelSOCKS
	netfetch.Logf = func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func tunnelSOCKS() string {
	cfg, err := config.Load(configPath())
	if err != nil || cfg.Failover.SOCKSPort <= 0 {
		return ""
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.Failover.SOCKSPort))
}
