package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kuzzrus/keenetic-xray-go/internal/config"
	"github.com/kuzzrus/keenetic-xray-go/internal/tungate"
)

// While the transport is off -- or there is no router to have an interface
// on -- the gate has nothing to guard, whatever the config says.
func TestTunGateConfig_ProbeIsOffWithoutATransport(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	cfg := config.Default()
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}
	src := &tunGateConfig{}
	if err := src.probe(context.Background()); !errors.Is(err, tungate.ErrOff) {
		t.Errorf("probe with the transport off = %v, want ErrOff", err)
	}

	// On in the config, but this is not a router.
	cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: "OpkgTun0"}
	if err := cfg.Save(cfgFile); err != nil {
		t.Fatal(err)
	}
	src = &tunGateConfig{}
	if err := src.probe(context.Background()); !errors.Is(err, tungate.ErrOff) {
		t.Errorf("probe off a router = %v, want ErrOff", err)
	}
}

// An unreadable config says nothing about the tunnel: the gate must neither
// close nor open on it.
func TestTunGateConfig_UnreadableConfigIsNoVerdict(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	if err := os.WriteFile(cfgFile, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := &tunGateConfig{}
	if err := src.probe(context.Background()); !errors.Is(err, tungate.ErrSkip) {
		t.Errorf("probe with a broken config = %v, want ErrSkip", err)
	}
	if err := src.set(context.Background(), false); err == nil {
		t.Error("set with no usable config succeeded")
	}
}

// The config is re-read at most every tunGateConfigTTL, and a later broken
// file keeps the last good one.
func TestTunGateConfig_CachesAndKeepsTheLastGoodConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "config.json")
	t.Setenv("KEENETIC_XRAY_CONFIG", cfgFile)
	save := func(iface string) {
		cfg := config.Default()
		cfg.TunTransport = config.TunTransportConfig{Enabled: true, Iface: iface}
		if err := cfg.Save(cfgFile); err != nil {
			t.Fatal(err)
		}
	}
	save("OpkgTun0")
	src := &tunGateConfig{}
	if c, ok := src.get(); !ok || c.TunTransport.Iface != "OpkgTun0" {
		t.Fatalf("first get = %+v, %v", c, ok)
	}

	save("OpkgTun1")
	if c, _ := src.get(); c.TunTransport.Iface != "OpkgTun0" {
		t.Errorf("config re-read inside the TTL: %q", c.TunTransport.Iface)
	}
	src.at = time.Now().Add(-2 * tunGateConfigTTL)
	if c, _ := src.get(); c.TunTransport.Iface != "OpkgTun1" {
		t.Errorf("config not re-read after the TTL: %q", c.TunTransport.Iface)
	}

	if err := os.WriteFile(cfgFile, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	src.at = time.Now().Add(-2 * tunGateConfigTTL)
	if c, ok := src.get(); !ok || c.TunTransport.Iface != "OpkgTun1" {
		t.Errorf("a broken file lost the last good config: %+v, %v", c, ok)
	}
}
