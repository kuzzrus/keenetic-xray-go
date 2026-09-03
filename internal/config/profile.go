// Package config defines the persisted configuration shape (profiles,
// failover/agent settings), VLESS URI parsing, and Xray-core JSON config
// generation shared by the production and isolated-pretest instances.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Profile is a single VLESS server entry, parsed from either a raw vless://
// link or one entry of a subscription. Fields map directly onto the query
// parameters of the VLESS URI scheme.
type Profile struct {
	Remark     string `json:"remark"`
	UUID       string `json:"uuid"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Encryption string `json:"encryption"` // almost always "none"
	Flow       string `json:"flow,omitempty"`

	Network  string `json:"network"`  // tcp | ws | grpc | http ("h2" accepted as an alias) | xhttp
	Security string `json:"security"` // none | tls | reality

	SNI         string   `json:"sni,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // fp=
	ALPN        []string `json:"alpn,omitempty"`
	PublicKey   string   `json:"public_key,omitempty"` // pbk= (REALITY)
	ShortID     string   `json:"short_id,omitempty"`   // sid= (REALITY)
	SpiderX     string   `json:"spider_x,omitempty"`   // spx= (REALITY)

	Path        string `json:"path,omitempty"`         // ws/h2/xhttp
	Host        string `json:"host,omitempty"`         // ws/h2/xhttp Host header
	ServiceName string `json:"service_name,omitempty"` // grpc
	HeaderType  string `json:"header_type,omitempty"`  // tcp
	Mode        string `json:"mode,omitempty"`         // xhttp: packet-up | stream-up | stream-one
}

// Validate checks that a Profile has the fields required to generate a
// working Xray outbound.
func (p *Profile) Validate() error {
	if p.UUID == "" {
		return fmt.Errorf("missing uuid")
	}
	if p.Address == "" {
		return fmt.Errorf("missing address")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("invalid port %d", p.Port)
	}
	switch p.Network {
	case "tcp", "ws", "grpc", "h2", "http", "xhttp":
	default:
		return fmt.Errorf("unsupported network %q", p.Network)
	}
	switch p.Security {
	case "none", "tls", "reality":
	default:
		return fmt.Errorf("unsupported security %q", p.Security)
	}
	if p.Security == "reality" {
		if p.PublicKey == "" || p.ShortID == "" {
			return fmt.Errorf("reality security requires public_key and short_id")
		}
		if p.SNI == "" {
			return fmt.Errorf("reality security requires sni (the server name to present in the TLS handshake)")
		}
	}
	return nil
}

// Subscription is the persisted metadata for a configured subscription URL.
// Fetch/decode/parse/refresh logic lives in internal/subscription (M2);
// this is just the storage shape, kept here since it's part of Config.
type Subscription struct {
	URL           string    `json:"url"`
	LastFetchedAt time.Time `json:"last_fetched_at,omitempty"`
	PrimaryKey    string    `json:"primary_key,omitempty"` // matched by Profile.Remark
	BackupKey     string    `json:"backup_key,omitempty"`
}

// FailoverConfig holds the tunable health-check/failover parameters.
type FailoverConfig struct {
	CheckIntervalSeconds      int    `json:"check_interval_seconds"`
	FailuresRequired          int    `json:"failures_required"`
	RecoverySuccessesRequired int    `json:"recovery_successes_required"`
	CooldownCycles            int    `json:"cooldown_cycles"`
	RollbackBackoffSeconds    int    `json:"rollback_backoff_seconds"`
	HealthCheckURL            string `json:"health_check_url"`
	SOCKSPort                 int    `json:"socks_port"`
	HTTPPort                  int    `json:"http_port"`
	PretestPort               int    `json:"pretest_port"`
}

// DefaultFailoverConfig returns the plan's defaults: the numbers given
// directly (3 attempts / 10s interval / symmetric counts) plus the
// cooldown/backoff/port defaults proposed and flagged as open to tuning.
func DefaultFailoverConfig() FailoverConfig {
	return FailoverConfig{
		CheckIntervalSeconds:      10,
		FailuresRequired:          3,
		RecoverySuccessesRequired: 3,
		CooldownCycles:            2,
		RollbackBackoffSeconds:    300,
		HealthCheckURL:            "https://www.gstatic.com/generate_204",
		SOCKSPort:                 1080,
		HTTPPort:                  1081,
		PretestPort:               11080,
	}
}

// AgentConfig holds control-server connectivity settings for the optional
// remote-control agent (M9). Disabled by default.
type AgentConfig struct {
	Enabled           bool   `json:"enabled"`
	ControlServerURL  string `json:"control_server_url,omitempty"`
	FingerprintSHA256 string `json:"fingerprint_sha256,omitempty"`
	TokenFile         string `json:"token_file,omitempty"`
	RouterID          string `json:"router_id,omitempty"`
}

const (
	VariantMini = "mini"
	VariantFull = "full"
)

// Proxy0Config controls whether the daemon points Keenetic's Proxy
// interface at the local Xray inbound (via `keenetic-xray proxy0`), so
// LAN traffic can be policy-routed through the proxy. On by default (see
// config.Default); when enabled the inbound binds 0.0.0.0 instead of
// loopback so Proxy0 can reach it.
type Proxy0Config struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface,omitempty"` // "" -> "Proxy0"
	Protocol  string `json:"protocol,omitempty"`  // "" -> "socks5"; also "http"
	LANIP     string `json:"lan_ip,omitempty"`    // override; "" -> auto-detect via ndmc
}

// Config is the full persisted /opt/etc/keenetic-xray/config.json shape.
type Config struct {
	Variant      string         `json:"variant"` // "mini" | "full"
	Profiles     []Profile      `json:"profiles"`
	PrimaryIndex int            `json:"primary_index"` // -1 if unset
	BackupIndex  int            `json:"backup_index"`  // -1 if unset
	Subscription *Subscription  `json:"subscription,omitempty"`
	Failover     FailoverConfig `json:"failover"`
	Agent        AgentConfig    `json:"agent"`
	Proxy0       Proxy0Config   `json:"proxy0"`
}

// Default returns a fresh Config with no profiles configured yet, ready to
// be filled in by `keenetic-xray setup` or postinst-setup. Proxy0 is on
// by default (the daemon only actually configures it when ndmc is present
// and profiles exist); `install.sh --no-proxy0` / `keenetic-xray proxy0
// off` turn it back off.
func Default() *Config {
	return &Config{
		Variant:      VariantFull,
		PrimaryIndex: -1,
		BackupIndex:  -1,
		Failover:     DefaultFailoverConfig(),
		Agent:        AgentConfig{Enabled: false},
		Proxy0:       Proxy0Config{Enabled: true},
	}
}

// Load reads config.json from path. A missing file is not an error — it
// returns Default() so callers (status, doctor, the setup wizard) can
// treat "not configured yet" as ordinary state instead of special-casing
// os.IsNotExist everywhere.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	cfg := Default()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the config as indented JSON to path with 0600 permissions —
// it may contain a subscription URL and other values not meant to be
// world-readable.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("refusing to save invalid config: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// Validate checks internal consistency: known variant, in-range profile
// indices, and that every profile is individually valid.
func (c *Config) Validate() error {
	switch c.Variant {
	case VariantMini, VariantFull:
	default:
		return fmt.Errorf("unknown variant %q", c.Variant)
	}
	if c.PrimaryIndex < -1 || c.PrimaryIndex >= len(c.Profiles) {
		return fmt.Errorf("primary_index %d out of range (-1 for unset, or 0..%d)", c.PrimaryIndex, len(c.Profiles)-1)
	}
	if c.BackupIndex < -1 || c.BackupIndex >= len(c.Profiles) {
		return fmt.Errorf("backup_index %d out of range (-1 for unset, or 0..%d)", c.BackupIndex, len(c.Profiles)-1)
	}
	for i, p := range c.Profiles {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("profile %d (%s): %w", i, p.Remark, err)
		}
	}
	switch c.Proxy0.Protocol {
	case "", "socks5", "http":
	default:
		return fmt.Errorf("proxy0.protocol %q: want socks5 or http", c.Proxy0.Protocol)
	}
	return nil
}

// Proxy0Port is the local inbound port Keenetic's Proxy0 should be
// pointed at, chosen to match Proxy0.Protocol.
func (c *Config) Proxy0Port() int {
	if c.Proxy0.Protocol == "http" {
		return c.Failover.HTTPPort
	}
	return c.Failover.SOCKSPort
}

// Primary returns the currently-selected primary profile, or nil if unset.
func (c *Config) Primary() *Profile { return c.profileAt(c.PrimaryIndex) }

// Backup returns the currently-selected backup profile, or nil if unset.
func (c *Config) Backup() *Profile { return c.profileAt(c.BackupIndex) }

func (c *Config) profileAt(i int) *Profile {
	if i < 0 || i >= len(c.Profiles) {
		return nil
	}
	return &c.Profiles[i]
}
