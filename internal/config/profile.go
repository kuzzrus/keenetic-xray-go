// Package config defines the persisted configuration shape (profiles,
// failover/agent settings), VLESS URI parsing, and Xray-core JSON config
// generation shared by the production and isolated-pretest instances.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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
type SlotSource struct {
	URL      string `json:"url"`
	Selector string `json:"selector,omitempty"`
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
}

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

// Config is the full persisted /opt/etc/keenetic-xray/config.json shape.
type Config struct {
	Variant      string        `json:"variant"` // "mini" | "full"
	Profiles     []Profile     `json:"profiles"`
	PrimaryIndex int           `json:"primary_index"` // -1 if unset
	BackupIndex  int           `json:"backup_index"`  // -1 if unset
	Subscription *Subscription `json:"subscription,omitempty"`
	// PrimarySource / BackupSource feed the two slots from independent
	// links or subscriptions (set via the bot's 🔗 Источники). Optional;
	// a single shared Subscription still works the old way.
	PrimarySource *SlotSource    `json:"primary_source,omitempty"`
	BackupSource  *SlotSource    `json:"backup_source,omitempty"`
	Failover      FailoverConfig `json:"failover"`
	Agent         AgentConfig    `json:"agent"`
	Proxy0        Proxy0Config   `json:"proxy0"`

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

		if l.Interface != "" && !ValidProxyIface(l.Interface) {
			return fmt.Errorf("routing list %q: interface %q: want a name like Proxy0", l.Name, l.Interface)
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
// .PATCH (upstream uses calendar-ish v26.7.28). Kept loose on the
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
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating config directory: %w", err)
		}
	}
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
	if !ValidProxyIface(c.Proxy0.Interface) {
		return fmt.Errorf("proxy0.interface %q: want a name like Proxy0 or Proxy1", c.Proxy0.Interface)
	}
	if !ValidXrayCoreTag(c.XrayCoreTag) {
		return fmt.Errorf("xray_core_tag %q: want a release tag like v26.7.28", c.XrayCoreTag)
	}
	if err := c.Routing.Validate(); err != nil {
		return err
	}
	if !ValidXHTTPMode(c.XHTTPMode) {
		return fmt.Errorf("xhttp_mode %q: want auto|packet-up|stream-up|stream-one", c.XHTTPMode)
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
