// Package config defines the persisted configuration shape (profiles,
// failover/agent settings), VLESS URI parsing, and Xray-core JSON config
// generation shared by the production and isolated-pretest instances.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

	// XHTTPExtra is the raw JSON from a share link's `extra=` parameter --
	// the xhttp transport-tuning blob that carries `xmux` (connection
	// reuse), `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `xPaddingBytes`
	// and so on. Dropping it makes every new connection redo the full
	// xhttp + REALITY handshake. GenerateXrayConfig merges these keys into
	// `xhttpSettings` verbatim, so new upstream tuning fields work without
	// a code change here.
	XHTTPExtra json.RawMessage `json:"xhttp_extra,omitempty"`
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
	if len(p.XHTTPExtra) > 0 {
		var obj map[string]any
		if err := json.Unmarshal(p.XHTTPExtra, &obj); err != nil {
			return fmt.Errorf("xhttp_extra must be a JSON object: %w", err)
		}
	}
	return nil
}

// ImportKey is a stable identity for the *server endpoint* a Profile
// points at: the connection coordinates that decide which server this
// is, with the display name and every credential deliberately left out.
// Renaming a profile or rotating its UUID / REALITY keys keeps the same
// ImportKey; changing host, port, transport, security mode, SNI, Host
// header, path, gRPC service or xhttp mode makes it a different server.
//
// It exists so a failover slot fed from a subscription can be re-found in
// a later fetch whose provider reordered or renamed its nodes -- a
// positional or Remark selector would silently resolve to a different
// server. 16 hex chars (64 bits) is far more than enough to tell a
// handful of subscription entries apart.
func (p *Profile) ImportKey() string {
	lc := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	network := lc(p.Network)
	if network == "h2" {
		network = "http"
	}
	// Path and ServiceName stay case-sensitive (URL paths and gRPC
	// service names are); everything else is lowercased so trivial
	// provider formatting differences don't fork the identity.
	fields := []string{
		lc(p.Address),
		strconv.Itoa(p.Port),
		network,
		lc(p.Security),
		lc(p.SNI),
		lc(p.Host),
		strings.TrimSpace(p.Path),
		strings.TrimSpace(p.ServiceName),
		lc(p.Mode),
	}
	sum := sha256.Sum256([]byte(strings.Join(fields, "\x1f")))
	return hex.EncodeToString(sum[:8])
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

// SlotSource records where a single failover slot's profile came from, so
// primary and backup can be fed from independent links or subscriptions.
// URL is a secret (kept in the 0600 config.json, never echoed); Selector
// picks one entry from a multi-profile subscription (an index, a Remark
// substring, or "" / "first" for the first).
//
// ImportKey is the stable identity (Profile.ImportKey) of the profile
// this slot last resolved to. It's the real anchor: a subscription
// provider that reorders or renames its nodes would make a positional or
// Remark Selector silently point at a different server, so once a slot
// has resolved once we re-find that same server by ImportKey and only
// fall back to Selector if it's genuinely gone. Empty on configs written
// before this field existed; backfilled on the next refresh.
type SlotSource struct {
	URL       string `json:"url"`
	Selector  string `json:"selector,omitempty"`
	ImportKey string `json:"import_key,omitempty"`
}

// FailoverConfig holds the tunable health-check/failover parameters.
type FailoverConfig struct {
	CheckIntervalSeconds      int    `json:"check_interval_seconds"`
	FailuresRequired          int    `json:"failures_required"`
	RecoverySuccessesRequired int    `json:"recovery_successes_required"`
	CooldownCycles            int    `json:"cooldown_cycles"`
	RollbackBackoffSeconds    int    `json:"rollback_backoff_seconds"`
	HealthCheckURL            string `json:"health_check_url"`
	// HealthCheckFallbackURLs are tried, in order, only if HealthCheckURL's
	// attempts all fail -- insurance against that one endpoint being the
	// thing that's actually down or throttled, independent of the tunnel.
	HealthCheckFallbackURLs []string `json:"health_check_fallback_urls,omitempty"`
	// CheckRetries/CheckRetryDelaySeconds: extra attempts against the same
	// URL, within a single Tick, before moving to the next URL or counting
	// the tick as a failure. Smooths over a single sub-second blip that a
	// bare "N consecutive ticks" counter would otherwise treat the same as
	// a real outage.
	CheckRetries           int `json:"check_retries"`
	CheckRetryDelaySeconds int `json:"check_retry_delay_seconds"`
	SOCKSPort              int `json:"socks_port"`
	HTTPPort               int `json:"http_port"`
	PretestPort            int `json:"pretest_port"`
	// PrimaryStuckWarnHours: after this long carrying traffic on backup
	// without primary recovering, the daemon pushes ONE advisory to the
	// bot (the operator otherwise only learns it by opening /doctor).
	// Re-armed once primary is live again. 0 disables.
	PrimaryStuckWarnHours int `json:"primary_stuck_warn_hours,omitempty"`
	// QualitySweepMinutes: how often the daemon probes *every* saved
	// profile (not just the live one) through a throwaway isolated xray,
	// so `status` can show which backups are actually reachable before a
	// failover ever picks one. Sequential, never touches live traffic.
	// 0 disables; otherwise 15..1440.
	QualitySweepMinutes int `json:"quality_sweep_minutes,omitempty"`
}

// QualitySweepEnabled reports whether the periodic all-profiles health
// sweep is configured to run.
func (f FailoverConfig) QualitySweepEnabled() bool { return f.QualitySweepMinutes > 0 }

// PrimaryStuckWarnAfter is PrimaryStuckWarnHours as a Duration; zero
// means the advisory is off.
func (f FailoverConfig) PrimaryStuckWarnAfter() time.Duration {
	return time.Duration(f.PrimaryStuckWarnHours) * time.Hour
}

// DefaultFailoverConfig returns the plan's defaults: the numbers given
// directly (3 attempts / 10s interval / symmetric counts) plus the
// cooldown/backoff/port defaults proposed and flagged as open to tuning.
// The fallback-URL/retry defaults mirror the reference installer
// (keenetic_xray_installer's watchdog: CHECK_URLS + CHECK_RETRIES) --
// loaded into an *existing* config.json that predates these fields too,
// since Load starts from these defaults before unmarshalling over them.
func DefaultFailoverConfig() FailoverConfig {
	return FailoverConfig{
		CheckIntervalSeconds:      10,
		FailuresRequired:          3,
		RecoverySuccessesRequired: 3,
		CooldownCycles:            2,
		RollbackBackoffSeconds:    300,
		HealthCheckURL:            "https://www.gstatic.com/generate_204",
		HealthCheckFallbackURLs: []string{
			"https://cp.cloudflare.com/generate_204",
			"http://connectivitycheck.gstatic.com/generate_204",
		},
		CheckRetries:           1,
		CheckRetryDelaySeconds: 2,
		SOCKSPort:              1080,
		HTTPPort:               1081,
		PretestPort:            11080,
		PrimaryStuckWarnHours:  3,
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
	Interface string `json:"interface,omitempty"` // "" -> "Proxy0"; also Proxy1, Proxy2, ...
	Protocol  string `json:"protocol,omitempty"`  // "" -> "socks5"; also "http"
	LANIP     string `json:"lan_ip,omitempty"`    // override; "" -> auto-detect via ndmc

	// MSSClamp is the TCP MSS forced on forwarded connections while
	// Proxy0 is on -- the fix for a PMTU black hole where the tunnel
	// (Proxy0 -> xray -> xhttp/reality) can't carry full 1460-MSS
	// segments, so large transfers (video) stall ~20s on retransmit.
	// 0 -> the default DefaultMSSClamp; a negative value disables it;
	// a positive value is used as-is (1200..1452).
	MSSClamp int `json:"mss_clamp,omitempty"`
}

// DefaultMSSClamp is the MSS applied when Proxy0.MSSClamp is 0. Chosen
// conservatively: 1500 WAN MTU minus IP/TCP (40) minus TLS record and
// xhttp/VLESS framing headroom.
const DefaultMSSClamp = 1360

// MSSClampValue resolves Proxy0.MSSClamp to the MSS to enforce, or 0 for
// "don't clamp".
func (p Proxy0Config) MSSClampValue() int {
	switch {
	case p.MSSClamp < 0:
		return 0
	case p.MSSClamp == 0:
		return DefaultMSSClamp
	default:
		return p.MSSClamp
	}
}

// MSSClampText renders Proxy0.MSSClamp for humans: "авто (1360)", an
// explicit value, or "выкл".
func (p Proxy0Config) MSSClampText() string {
	switch {
	case p.MSSClamp < 0:
		return "выкл"
	case p.MSSClamp == 0:
		return fmt.Sprintf("авто (%d)", DefaultMSSClamp)
	default:
		return strconv.Itoa(p.MSSClamp)
	}
}

// ParseMSSClampArg maps a CLI/bot token to the value stored in
// Proxy0.MSSClamp: "auto" -> 0 (use DefaultMSSClamp), "off" -> -1
// (disable), a decimal -> itself, range-checked to 1200..1452.
func ParseMSSClampArg(s string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "default", "":
		return 0, nil
	case "off", "none", "disable", "0":
		return -1, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("mss %q: нужно число 1200..1452, либо auto / off", s)
	}
	if n < 1200 || n > 1452 {
		return 0, fmt.Errorf("mss %d вне диапазона 1200..1452 (auto = %d, off — отключить)", n, DefaultMSSClamp)
	}
	return n, nil
}

// WGTransportConfig manages an in-router WireGuard carrier from Keenetic
// into the local xray: LAN -> WireguardN -> xray `wireguard` inbound ->
// VLESS/xhttp out. An alternative to Proxy0/SOCKS as the way selected
// traffic reaches the tunnel -- the two coexist, and which traffic uses
// which is chosen per `routes` list or by Keenetic policy. Off by
// default. All the key material is generated by the daemon, never
// user-entered: XraySecretKey/XrayPublicKey is xray's WG keypair (xray
// is the "server"), KeeneticPublicKey is read back off the interface
// after the router generates its own, PSK is shared both ways.
type WGTransportConfig struct {
	Enabled bool `json:"enabled"`

	// Iface is the Keenetic interface this owns ("Wireguard4"). The
	// daemon picks the lowest free one on first enable and pins it here
	// so re-runs are stable.
	Iface string `json:"iface,omitempty"`
	Port  int    `json:"port,omitempty"` // xray WG inbound UDP port; 0 -> DefaultWGPort
	Addr  string `json:"addr,omitempty"` // the /32 the Keenetic side takes on the tunnel; "" -> DefaultWGAddr
	MTU   int    `json:"mtu,omitempty"`  // 0 -> DefaultWGMTU

	XraySecretKey     string `json:"xray_secret_key,omitempty"`
	XrayPublicKey     string `json:"xray_public_key,omitempty"`
	KeeneticPublicKey string `json:"keenetic_public_key,omitempty"`
	PSK               string `json:"psk,omitempty"`
}

// RCIConfig toggles reading the running config over the local RCI JSON
// API. URL is the router-local base (scheme + host + port), default
// DefaultRCIURL; no credentials -- KeeneticOS serves RCI without auth to
// 127.0.0.1.
type RCIConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url,omitempty"` // "" -> DefaultRCIURL
}

// DefaultRCIURL is where KeeneticOS's ndhttpd answers RCI on the router
// itself. Port 79 is the historical command port; `keenetic-xray rci
// probe` also tries 80 and stores whichever answers.
const DefaultRCIURL = "http://127.0.0.1:79"

func (r RCIConfig) BaseURL() string {
	if r.URL == "" {
		return DefaultRCIURL
	}
	return r.URL
}

// Defaults for WGTransportConfig. The address is a deliberately obscure
// RFC1918 /32 unlikely to collide with a hand-made tunnel; MTU 1280 is
// the IPv6 minimum and matches KeeneticOS's own WG default.
const (
	DefaultWGPort = 41199
	DefaultWGAddr = "172.31.209.2"
	DefaultWGMTU  = 1280
)

func (w WGTransportConfig) WGPort() int {
	if w.Port == 0 {
		return DefaultWGPort
	}
	return w.Port
}

func (w WGTransportConfig) WGAddr() string {
	if w.Addr == "" {
		return DefaultWGAddr
	}
	return w.Addr
}

func (w WGTransportConfig) WGMTU() int {
	if w.MTU == 0 {
		return DefaultWGMTU
	}
	return w.MTU
}

// Ready reports whether both sides' key material is present -- i.e. the
// xray `wireguard` inbound can actually be rendered.
func (w WGTransportConfig) Ready() bool {
	return w.XraySecretKey != "" && w.XrayPublicKey != "" && w.KeeneticPublicKey != ""
}

// EnsureKeys fills in the xray-side WG keypair and the pre-shared key if
// they're missing (the Keenetic side generates its own, read back
// separately). Idempotent; returns whether anything was generated.
func (w *WGTransportConfig) EnsureKeys() (generated bool, err error) {
	if w.XraySecretKey == "" || w.XrayPublicKey == "" {
		priv, pub, e := GenerateWGKeypair()
		if e != nil {
			return generated, e
		}
		w.XraySecretKey, w.XrayPublicKey, generated = priv, pub, true
	}
	if w.PSK == "" {
		psk, e := GenerateWGPSK()
		if e != nil {
			return generated, e
		}
		w.PSK, generated = psk, true
	}
	return generated, nil
}

// wgIfaceRe / routeIfaceRe: a Keenetic WireGuard interface name, and the
// wider set a `routes` list may target (a Proxy interface OR a WireGuard
// one -- both are valid `dns-proxy route` destinations).
var (
	wgIfaceRe    = regexp.MustCompile(`^Wireguard[0-9]+$`)
	routeIfaceRe = regexp.MustCompile(`^(Proxy|Wireguard)[0-9]+$`)
)

// ValidWGIface reports whether s names a Keenetic WireGuard interface.
func ValidWGIface(s string) bool { return wgIfaceRe.MatchString(s) }

// ValidRouteIface reports whether s is an acceptable RouteList.Interface:
// empty (the Proxy0 default) or a Proxy<n>/Wireguard<n> name.
func ValidRouteIface(s string) bool { return s == "" || routeIfaceRe.MatchString(s) }

// proxyIfaceRe matches the Keenetic Proxy interface names this project
// can drive -- Proxy0 (the default) through however many the firmware
// exposes. Deliberately not capped at a specific N: newer firmware keeps
// adding slots, and an over-tight check would reject a valid one.
var proxyIfaceRe = regexp.MustCompile(`^Proxy[0-9]+$`)

// ValidProxyIface reports whether s is an acceptable Proxy0.Interface
// value: empty (meaning the "Proxy0" default) or "Proxy<n>". Shared by
// the CLI flag parser and the bot action so both reject the same typos
// ("proxy1", "Proxy 1") with the same rule.
func ValidProxyIface(s string) bool {
	return s == "" || proxyIfaceRe.MatchString(s)
}

// IfaceName resolves Interface to a concrete name ("" -> "Proxy0"), for
// display and for passing to ndmc.
func (p Proxy0Config) IfaceName() string {
	if p.Interface == "" {
		return "Proxy0"
	}
	return p.Interface
}

// ProtoName resolves Protocol to a concrete name ("" -> "socks5").
func (p Proxy0Config) ProtoName() string {
	if p.Protocol == "" {
		return "socks5"
	}
	return p.Protocol
}

// CurrentSchemaVersion is bumped whenever config.json's shape changes in
// a way an old file needs help with. Load runs migrateConfig to bring an
// older file forward; a file from a *newer* schema is refused rather than
// silently misread.
const CurrentSchemaVersion = 1

// Config is the full persisted /opt/etc/keenetic-xray/config.json shape.
type Config struct {
	// SchemaVersion is 0 in any file written before this field existed;
	// migrateConfig treats 0 as "the pre-versioning shape".
	SchemaVersion int           `json:"schema_version,omitempty"`
	Variant       string        `json:"variant"` // "mini" | "full"
	Profiles      []Profile     `json:"profiles"`
	PrimaryIndex  int           `json:"primary_index"` // -1 if unset
	BackupIndex   int           `json:"backup_index"`  // -1 if unset
	Subscription  *Subscription `json:"subscription,omitempty"`
	// PrimarySource / BackupSource feed the two slots from independent
	// links or subscriptions (set via the bot's 🔗 Источники). Optional;
	// a single shared Subscription still works the old way.
	PrimarySource *SlotSource    `json:"primary_source,omitempty"`
	BackupSource  *SlotSource    `json:"backup_source,omitempty"`
	Failover      FailoverConfig `json:"failover"`
	Agent         AgentConfig    `json:"agent"`
	Proxy0        Proxy0Config   `json:"proxy0"`

	// WGTransport, when enabled, stands up a Keenetic WireGuard interface
	// that carries selected LAN traffic into the local xray `wireguard`
	// inbound -- an alternative router->xray hop to Proxy0/SOCKS. See
	// WGTransportConfig and internal/keenetic.ApplyWGTransport.
	WGTransport WGTransportConfig `json:"wg_transport,omitempty"`

	// RCI, when enabled, makes the keenetic layer read the running
	// config over Keenetic's local RCI JSON API (http://127.0.0.1, no
	// auth from loopback) instead of shelling out to `ndmc -c "show
	// running-config"`. A hedge for firmware that sandboxes Entware away
	// from ndmc; writes and other reads still use ndmc. Off by default.
	RCI RCIConfig `json:"rci,omitempty"`

	// XrayCoreTag pins which vendored Xray-core release this router
	// tracks. Empty -> xraycore.DefaultTag (the stable pin). Set to an
	// upstream tag (e.g. a vetted pre-release) to opt that one router
	// onto it; persisted here so a package self-update keeps the choice
	// instead of reverting to the default. internal/config can't name
	// xraycore.DefaultTag without an import cycle, so the ""-resolution
	// happens at the call sites (cmd, botcontrol) that already use it.
	XrayCoreTag string `json:"xray_core_tag,omitempty"`

	// Routing holds named lists of domains/subnets that Keenetic's
	// DNS-based routing (KeeneticOS 5.0+) should send through the Proxy0
	// interface -- i.e. through the tunnel -- while everything else stays
	// direct. internal/keenetic applies each list as an `object-group
	// fqdn` plus a `dns-proxy route`. Empty -> the daemon touches none of
	// the router's routing config.
	Routing RoutingConfig `json:"routing,omitempty"`

	// XHTTPMode, when set, forces the xhttp transport mode on every
	// xhttp profile regardless of what its share link said -- a global
	// override that survives a subscription refresh (unlike editing a
	// profile). "" keeps each link's own mode. One of
	// auto|packet-up|stream-up|stream-one.
	XHTTPMode string `json:"xhttp_mode,omitempty"`

	// PresetsNoAutoUpdate turns off the daily pull of the built-in
	// routing-list presets from the repo (internal/presets.Refresh). The
	// embedded copy is then the only source until the agent is updated.
	PresetsNoAutoUpdate bool `json:"presets_no_auto_update,omitempty"`

	// PresetsSourceURL overrides where preset refreshes are fetched from
	// (default: internal/presets.DefaultSourceURL). For a fork or a
	// mirror; "" -> the default.
	PresetsSourceURL string `json:"presets_source_url,omitempty"`

	// DNS, when set, has the daemon keep Keenetic's dns-proxy pointed at
	// the chosen DNS-over-TLS / DNS-over-HTTPS upstreams. Empty -> the
	// router's DNS config is left entirely alone.
	DNS DNSConfig `json:"dns,omitempty"`
}

// DNSConfig is the desired set of secure DNS upstreams for Keenetic's
// built-in dns-proxy. Provider is a dnsupstream catalogue id (or
// "custom"/""), kept for the UI; DoT/DoH are the concrete endpoints the
// daemon reconciles onto the router. internal/keenetic only ever
// adds/removes upstreams whose IP/URL is in this project's known set, so
// a hand-added upstream is never touched.
type DNSConfig struct {
	Provider string         `json:"provider,omitempty"`
	DoT      []DNSHostTLS   `json:"dot,omitempty"`
	DoH      []DNSHostHTTPS `json:"doh,omitempty"`
}

type DNSHostTLS struct {
	IP  string `json:"ip"`
	SNI string `json:"sni"`
}

type DNSHostHTTPS struct {
	URL string `json:"url"`
}

// Configured reports whether any secure upstream is set.
func (d DNSConfig) Configured() bool { return len(d.DoT) > 0 || len(d.DoH) > 0 }

var dnsSNIRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (d DNSConfig) validate() error {
	for _, t := range d.DoT {
		if net.ParseIP(strings.TrimSpace(t.IP)) == nil {
			return fmt.Errorf("dns: DoT upstream %q: не IP-адрес", t.IP)
		}
		if !dnsSNIRe.MatchString(strings.ToLower(strings.TrimSpace(t.SNI))) {
			return fmt.Errorf("dns: DoT upstream %s: SNI %q не похож на имя хоста", t.IP, t.SNI)
		}
	}
	for _, h := range d.DoH {
		u := strings.TrimSpace(h.URL)
		if !strings.HasPrefix(u, "https://") || len(u) < len("https://a.bc/") || strings.ContainsAny(u, " \t\"") {
			return fmt.Errorf("dns: DoH upstream %q: нужен https:// URL", h.URL)
		}
	}
	return nil
}

// ValidXHTTPMode reports whether s is an acceptable XHTTPMode: empty
// (keep the link's) or one of xray's four xhttp modes.
func ValidXHTTPMode(s string) bool {
	switch s {
	case "", "auto", "packet-up", "stream-up", "stream-one":
		return true
	}
	return false
}

// RoutingConfig is the persisted set of DNS-route lists. Each list maps
// to one router-side object-group; the whole set is reconciled onto the
// router by internal/keenetic.ApplyRoutes.
type RoutingConfig struct {
	Lists []RouteList `json:"lists,omitempty"`
}

// RouteList is one named group of domains/subnets to route through a
// Proxy interface. Name is what the operator typed; the object-group on
// the router is "keenetic-xray-" + SanitizeRouteListName(Name), so this
// project's lists never collide with ones made by hand in the Keenetic
// web UI.
type RouteList struct {
	Name      string   `json:"name"`
	Entries   []string `json:"entries"`             // normalized domains + IPv4 + CIDR
	Interface string   `json:"interface,omitempty"` // "" -> Proxy0.IfaceName()
	Exclusive bool     `json:"exclusive,omitempty"` // add "reject": matched traffic is dropped, not leaked direct, when the interface is down
	Disabled  bool     `json:"disabled,omitempty"`  // keep the list but stop routing it

	// Preset, when set, is the id of the built-in list (internal/presets)
	// this list was seeded from -- "youtube", "youtube-ip". PresetRev is
	// that preset's content hash at the last sync. The bot/CLI compare
	// Entries against the embedded preset to show "update available" and
	// offer a re-sync; a plain hand-made list leaves both empty.
	Preset    string `json:"preset,omitempty"`
	PresetRev string `json:"preset_rev,omitempty"`
}

// MaxRouteEntriesPerList caps one list. Generous -- the point is to stop
// a paste of a whole geosite dump, not to be stingy.
const MaxRouteEntriesPerList = 256

var (
	routeDomainRe = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	routeIPish    = regexp.MustCompile(`^[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?$`)
)

// RouteEntryKind distinguishes the two things a route list can hold, for
// counting in status messages.
type RouteEntryKind int

const (
	RouteDomain RouteEntryKind = iota
	RouteSubnet
)

// ClassifyRouteEntry validates and normalizes one route-list entry --
// a domain, a bare IPv4, or an IPv4 CIDR -- returning its kind and the
// canonical form to store. Rejections carry a Russian reason suitable
// for showing the operator directly.
func ClassifyRouteEntry(s string) (RouteEntryKind, string, error) {
	e := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), ".")))
	switch {
	case e == "":
		return 0, "", fmt.Errorf("пустая запись")
	case strings.Contains(e, "*"):
		return 0, "", fmt.Errorf("%q: маска * не нужна — Keenetic включает поддомены сам", s)
	case strings.Contains(e, ":"):
		return 0, "", fmt.Errorf("%q: IPv6 в v1 не поддерживается (укажи IPv4-адрес или подсеть)", s)
	}

	if routeIPish.MatchString(e) {
		return classifyRouteIP(e, s)
	}

	if routeDomainRe.MatchString(e) {
		return RouteDomain, e, nil
	}
	if strings.ContainsFunc(e, func(r rune) bool { return r > 127 }) {
		return 0, "", fmt.Errorf("%q: IDN не поддерживается — введи домен в punycode (xn--…)", s)
	}
	return 0, "", fmt.Errorf("%q: не похоже ни на домен, ни на IPv4/подсеть", s)
}

func classifyRouteIP(e, orig string) (RouteEntryKind, string, error) {
	cidr := e
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, "", fmt.Errorf("%q: некорректный IPv4/подсеть", orig)
	}
	ones, _ := ipnet.Mask.Size()
	if ones == 0 {
		return 0, "", fmt.Errorf("%q: 0.0.0.0/0 отправит в туннель весь трафик — укажи конкретные подсети", orig)
	}
	if v4 := ip.To4(); v4 == nil {
		return 0, "", fmt.Errorf("%q: только IPv4", orig)
	}
	if isReservedV4(ipnet.IP) {
		return 0, "", fmt.Errorf("%q: приватная/служебная подсеть — её не маршрутизируют в туннель", orig)
	}
	if ones == 32 {
		return RouteSubnet, ipnet.IP.String(), nil
	}
	return RouteSubnet, ipnet.String(), nil
}

// isReservedV4 reports whether the network base address is in a range
// that must never be routed through the tunnel (own LAN, loopback,
// link-local, multicast).
func isReservedV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return true
	}
	switch {
	case v4[0] == 10:
		return true
	case v4[0] == 127:
		return true
	case v4[0] == 169 && v4[1] == 254:
		return true
	case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
		return true
	case v4[0] == 192 && v4[1] == 168:
		return true
	case v4[0] >= 224: // multicast + reserved
		return true
	}
	return false
}

// SanitizeRouteListName reduces a list name to the lowercase
// [a-z0-9-] form used for the router object-group name (after the
// "keenetic-xray-" prefix). "" means the name has nothing usable and
// must be rejected.
func SanitizeRouteListName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 24 {
		s = strings.Trim(s[:24], "-")
	}
	return s
}

// ValidRouteListName reports whether name is acceptable: 1..32 chars, no
// control characters, and at least one [a-z0-9] once sanitized (so it can
// name a router object-group).
func ValidRouteListName(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" || len([]rune(n)) > 32 {
		return false
	}
	for _, r := range n {
		if r < 0x20 {
			return false
		}
	}
	return SanitizeRouteListName(name) != ""
}

// Validate checks every route list: a usable name, distinct sanitized
// (router-side) names, a valid interface, and entries that pass
// ClassifyRouteEntry, within the per-list cap.
func (rc RoutingConfig) Validate() error {
	seen := map[string]string{} // sanitized name -> original, for collision reporting
	for _, l := range rc.Lists {
		if !ValidRouteListName(l.Name) {
			return fmt.Errorf("routing list %q: name must be 1..32 chars with some latin/digits", l.Name)
		}
		san := SanitizeRouteListName(l.Name)
		if prev, ok := seen[san]; ok {
			return fmt.Errorf("routing lists %q and %q map to the same router name %q -- rename one", prev, l.Name, san)
		}
		seen[san] = l.Name

		if l.Interface != "" && !ValidRouteIface(l.Interface) {
			return fmt.Errorf("routing list %q: interface %q: want a name like Proxy0 or Wireguard4", l.Name, l.Interface)
		}
		if len(l.Entries) > MaxRouteEntriesPerList {
			return fmt.Errorf("routing list %q: %d entries, max %d", l.Name, len(l.Entries), MaxRouteEntriesPerList)
		}
		for _, e := range l.Entries {
			if _, _, err := ClassifyRouteEntry(e); err != nil {
				return fmt.Errorf("routing list %q: %w", l.Name, err)
			}
		}
	}
	return nil
}

// RouteIface resolves this list's target Proxy interface name.
func (l RouteList) RouteIface() string {
	if l.Interface != "" {
		return l.Interface
	}
	return "Proxy0"
}

// xrayTagRe is the shape of an XTLS/Xray-core release tag: vMAJOR.MINOR
// .PATCH (upstream uses calendar-ish v26.9.8). Kept loose on the
// numbers; it only needs to reject obvious junk before it reaches a
// download URL.
var xrayTagRe = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// ValidXrayCoreTag reports whether s is an acceptable XrayCoreTag: empty
// (the default pin) or a "vN.N.N" release tag.
func ValidXrayCoreTag(s string) bool {
	return s == "" || xrayTagRe.MatchString(s)
}

// Default returns a fresh Config with no profiles configured yet, ready to
// be filled in by `keenetic-xray setup` or postinst-setup. Proxy0 is on
// by default (the daemon only actually configures it when ndmc is present
// and profiles exist); `install.sh --no-proxy0` / `keenetic-xray proxy0
// off` turn it back off.
func Default() *Config {
	return &Config{
		SchemaVersion: CurrentSchemaVersion,
		Variant:       VariantFull,
		PrimaryIndex:  -1,
		BackupIndex:   -1,
		Failover:      DefaultFailoverConfig(),
		Agent:         AgentConfig{Enabled: false},
		Proxy0:        Proxy0Config{Enabled: true},
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
	cfg.SchemaVersion = 0 // Default() sets nothing; a file without the field is v0
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if cfg.SchemaVersion > CurrentSchemaVersion {
		return nil, fmt.Errorf("%s: schema_version %d is newer than this build understands (%d) -- update keenetic-xray",
			path, cfg.SchemaVersion, CurrentSchemaVersion)
	}
	migrateConfig(cfg)
	return cfg, nil
}

// migrateConfig brings a config loaded from an older schema forward,
// field by field, then stamps CurrentSchemaVersion. Each step is
// idempotent -- running it on an already-current config is a no-op.
func migrateConfig(c *Config) {
	// v0 -> v1: schema_version introduced; no shape change, just the stamp.
	// (Future migrations: `if c.SchemaVersion < 2 { ... }`, in order.)
	c.SchemaVersion = CurrentSchemaVersion
}

// Save writes the config as indented JSON to path with 0600 permissions
// (it may hold a subscription URL and WG keys). The write is atomic:
// data goes to a temp file in the same directory, then os.Rename swaps it
// in -- so a power loss on a router mid-write leaves the old config
// intact instead of a truncated one the daemon can't parse.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("refusing to save invalid config: %w", err)
	}
	c.SchemaVersion = CurrentSchemaVersion // whatever it was loaded as, it's current now
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".config-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful Rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replacing config: %w", err)
	}
	return nil
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
	if !ValidProxyIface(c.Proxy0.Interface) {
		return fmt.Errorf("proxy0.interface %q: want a name like Proxy0 or Proxy1", c.Proxy0.Interface)
	}
	if v := c.Proxy0.MSSClamp; v > 0 && (v < 1200 || v > 1452) {
		return fmt.Errorf("proxy0.mss_clamp %d out of range (1200..1452, 0 for default, negative to disable)", v)
	}
	if !ValidXrayCoreTag(c.XrayCoreTag) {
		return fmt.Errorf("xray_core_tag %q: want a release tag like v26.9.8", c.XrayCoreTag)
	}
	if err := c.Routing.Validate(); err != nil {
		return err
	}
	if !ValidXHTTPMode(c.XHTTPMode) {
		return fmt.Errorf("xhttp_mode %q: want auto|packet-up|stream-up|stream-one", c.XHTTPMode)
	}
	if m := c.Failover.QualitySweepMinutes; m != 0 && (m < 15 || m > 1440) {
		return fmt.Errorf("failover.quality_sweep_minutes %d out of range (0 to disable, or 15..1440)", m)
	}
	if err := c.WGTransport.validate(); err != nil {
		return err
	}
	if err := c.DNS.validate(); err != nil {
		return err
	}
	return nil
}

func (w WGTransportConfig) validate() error {
	if w.Iface != "" && !ValidWGIface(w.Iface) {
		return fmt.Errorf("wg_transport.iface %q: want a name like Wireguard4", w.Iface)
	}
	if w.Port != 0 && (w.Port < 1 || w.Port > 65535) {
		return fmt.Errorf("wg_transport.port %d out of range", w.Port)
	}
	if w.Addr != "" {
		if ip := net.ParseIP(w.Addr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("wg_transport.addr %q: want an IPv4 address", w.Addr)
		}
	}
	if w.MTU != 0 && (w.MTU < 1280 || w.MTU > 1420) {
		return fmt.Errorf("wg_transport.mtu %d out of range (1280..1420)", w.MTU)
	}
	for name, k := range map[string]string{
		"xray_secret_key":     w.XraySecretKey,
		"xray_public_key":     w.XrayPublicKey,
		"keenetic_public_key": w.KeeneticPublicKey,
		"psk":                 w.PSK,
	} {
		if k != "" && !ValidWGKey(k) {
			return fmt.Errorf("wg_transport.%s is not a valid 32-byte base64 key", name)
		}
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

// UpsertProfile ensures p is in c.Profiles -- updating the existing entry
// if one already matches by identity (UUID+Address+Port), appending
// otherwise -- and returns its index either way. Shared by the bot's
// per-slot source flow (🔗 Источники) and subscription refresh's
// independent-slot preservation, so a profile from one source is never
// silently duplicated by another.
func (c *Config) UpsertProfile(p Profile) int {
	for i, e := range c.Profiles {
		if e.UUID == p.UUID && e.Address == p.Address && e.Port == p.Port {
			c.Profiles[i] = p
			return i
		}
	}
	c.Profiles = append(c.Profiles, p)
	return len(c.Profiles) - 1
}

// IndependentSlots snapshots the primary/backup profile of any slot fed
// by its own SlotSource, so a caller about to wholesale-replace Profiles
// (a subscription refresh) can restore that slot afterward -- otherwise
// refreshing the *shared* Subscription silently discards a slot that
// subscription had nothing to do with.
type IndependentSlots struct {
	Primary *Profile
	Backup  *Profile
}

// SnapshotIndependentSlots captures the current primary/backup profile
// for each slot that has its own PrimarySource/BackupSource. Call this
// before replacing c.Profiles.
func (c *Config) SnapshotIndependentSlots() IndependentSlots {
	var s IndependentSlots
	if c.PrimarySource != nil {
		if p := c.Primary(); p != nil {
			cp := *p
			s.Primary = &cp
		}
	}
	if c.BackupSource != nil {
		if p := c.Backup(); p != nil {
			cp := *p
			s.Backup = &cp
		}
	}
	return s
}

// Restore re-adds each captured slot's profile to c.Profiles (via
// UpsertProfile, so an identical entry the fresh fetch already carries
// isn't duplicated) and repoints the corresponding index at it,
// overriding whatever the caller derived from the fresh fetch. Call
// after replacing c.Profiles and setting Primary/BackupIndex from a
// refresh -- an independent source always wins over a shared
// subscription's own remark-match for the same slot.
func (s IndependentSlots) Restore(c *Config) {
	if s.Primary != nil {
		c.PrimaryIndex = c.UpsertProfile(*s.Primary)
	}
	if s.Backup != nil {
		c.BackupIndex = c.UpsertProfile(*s.Backup)
	}
}

// Redacted returns a deep copy of c with every credential / token /
// secret-carrying URL masked -- safe to drop into a diagnostic bundle
// or paste into a chat. Kept: server addresses, ports, SNI, transport
// tuning, failover knobs (all needed to debug). Masked: VLESS UUIDs,
// REALITY public-key/short-id, subscription & slot-source URLs, WG key
// material, and the path of any DoH URL (can carry a client token).
func (c *Config) Redacted() *Config {
	b, err := json.Marshal(c)
	if err != nil {
		return &Config{}
	}
	var d Config
	if err := json.Unmarshal(b, &d); err != nil {
		return &Config{}
	}

	mask := func(s string) string {
		if s == "" {
			return ""
		}
		return "<redacted>"
	}
	for i := range d.Profiles {
		p := &d.Profiles[i]
		p.UUID = mask(p.UUID)
		p.PublicKey = mask(p.PublicKey)
		p.ShortID = mask(p.ShortID)
	}
	if d.Subscription != nil {
		d.Subscription.URL = mask(d.Subscription.URL)
	}
	if d.PrimarySource != nil {
		d.PrimarySource.URL = mask(d.PrimarySource.URL)
	}
	if d.BackupSource != nil {
		d.BackupSource.URL = mask(d.BackupSource.URL)
	}
	d.WGTransport.XraySecretKey = mask(d.WGTransport.XraySecretKey)
	d.WGTransport.XrayPublicKey = mask(d.WGTransport.XrayPublicKey)
	d.WGTransport.KeeneticPublicKey = mask(d.WGTransport.KeeneticPublicKey)
	d.WGTransport.PSK = mask(d.WGTransport.PSK)
	for i := range d.DNS.DoH {
		d.DNS.DoH[i].URL = redactURLPath(d.DNS.DoH[i].URL)
	}
	return &d
}

// redactURLPath keeps scheme://host of a URL but replaces the path and
// query with "/<redacted>" -- a DoH URL's path segment is often a
// per-client token.
func redactURLPath(u string) string {
	scheme := ""
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = rest[:i+3]
		rest = rest[i+3:]
	}
	host := rest
	if i := strings.IndexAny(rest, "/?"); i >= 0 {
		host = rest[:i]
	}
	if host == "" {
		return u
	}
	return scheme + host + "/<redacted>"
}
