// Package config loads the Spikes402 JSON configuration file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/Choffolo/spikes402/internal/botid"
	"github.com/Choffolo/spikes402/internal/gate"
	"github.com/Choffolo/spikes402/internal/lightning"
	"github.com/Choffolo/spikes402/pow"
	"path/filepath"
)

const (
	maxPriceSats  = 1_000_000
	maxPriceRules = 100

	// MinPowSecondsPerSat is the lowest pow_seconds_per_sat accepted
	// without unsafe_allow_dangerous_config.
	MinPowSecondsPerSat = 1.0
)

// checkPathPattern is the syntax rule shared by "protect" and "prices".
func checkPathPattern(what, p string, caseSensitive bool) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf(`%s %q must start with "/"`, what, p)
	}
	if _, err := path.Match(strings.TrimSuffix(p, "/**"), "/"); err != nil {
		return fmt.Errorf("%s %q: %w", what, p, err)
	}
	if err := gate.UsablePattern(p, caseSensitive); err != nil {
		return fmt.Errorf("%s %q: %w", what, p, err)
	}
	return nil
}

// Config is the content of the configuration file. See config.example.json.
type Config struct {
	Listen               string             `json:"listen"`                  // address to listen on, default ":8402" ("127.0.0.1:8402" with the fake backend)
	Origin               string             `json:"origin"`                  // website to protect, e.g. "http://localhost:8080"
	PriceSats            int64              `json:"price_sats"`              // default price per request in sats
	Protect              []string           `json:"protect"`                 // path patterns that require payment
	Prices               []gate.PriceRule   `json:"prices,omitempty"`        // optional per-path prices; first match wins
	Surge                gate.SurgeConfig   `json:"surge,omitempty"`         // optional demand-based price multiplier, off by default
	Previews             []gate.PreviewRule `json:"previews,omitempty"`      // optional teaser of a protected page on its 402 page; first match wins
	PowSecondsPerSat     float64            `json:"pow_seconds_per_sat"`     // CPU-core seconds of work per sat, default 10
	PowDifficulty        int                `json:"pow_difficulty"`          // 0 = derived from price and pow_seconds_per_sat
	PowAlgorithm         string             `json:"pow_algorithm"`           // "sha256d" (default) or "argon2id"
	Argon2MemoryMiB      int                `json:"argon2_memory_mib"`       // argon2id memory per attempt, default 16
	Argon2MaxMemoryMiB   int                `json:"argon2_max_memory_mib"`   // concurrent Argon2id checks, default 256
	ChallengeTTLSeconds  int                `json:"challenge_ttl_seconds"`   // default 600
	ChallengesPerMinute  int                `json:"challenges_per_minute"`   // per client, default 30
	MaxInvoicesPerMinute int                `json:"max_invoices_per_minute"` // all clients together, default 300
	MaxPendingInvoices   int                `json:"max_pending_invoices"`    // default 10000
	ClientIPHeader       string             `json:"client_ip_header"`        // e.g. "X-Forwarded-For", default "" (use the TCP address)
	TrustedProxies       []string           `json:"trusted_proxies"`         // IPs/CIDRs allowed to set forwarding and client_ip_header
	PreserveHost         bool               `json:"preserve_host"`           // send the public Host to the origin (trusted proxies only)
	SecretKey            string             `json:"secret_key"`              // or env SPIKES402_SECRET_KEY
	StateDir             string             `json:"state_dir"`               // spent tokens and withdrawal intents; default "<config dir>/state"
	Lightning            Lightning          `json:"lightning"`

	Paused bool `json:"paused,omitempty"` // serve protected paths free; no invoices (dashboard toggle)

	ProtectCaseSensitive bool `json:"protect_case_sensitive"` // match "protect" patterns case-sensitively (default: case-insensitive)
	MaxConnections       int  `json:"max_connections"`        // open client connections at once, default 10000
	ReadTimeoutSeconds   int  `json:"read_timeout_seconds"`   // to read a whole request, default 60
	WriteTimeoutSeconds  int  `json:"write_timeout_seconds"`  // to send a whole response, default 300

	// UnsafeAllowDangerousConfig accepts settings that are refused by
	// default because they disable protections (see checkDangerous).
	UnsafeAllowDangerousConfig bool `json:"unsafe_allow_dangerous_config"`

	// Bot identification. Policies are off by default: everyone pays the same.
	IdentifyBots      *bool                  `json:"identify_bots"`         // default true
	KnownBots         []botid.Bot            `json:"known_bots"`            // default: botid.DefaultBots
	BotPolicies       map[string]gate.Policy `json:"bot_policies"`          // default: none
	WebBotAuthDevMode bool                   `json:"web_bot_auth_dev_mode"` // accept http/localhost key directories (fake backend only)

	// Web Bot Auth trust. A valid signature only makes a request
	// "verified-signed" if its key directory is hosted on one of these
	// domains (or a subdomain); otherwise the request counts as unknown.
	WebBotAuthTrustedAgents []string `json:"web_bot_auth_trusted_agents"`
	// PublicHosts are this site's host names. Signatures made for any
	// other host are refused, so they cannot be relayed from another site.
	PublicHosts []string `json:"public_hosts"`

	Admin    Admin    `json:"admin"`
	Withdraw Withdraw `json:"withdraw"`

	Lottery    Lottery    `json:"lottery"`     // sha256d work on real Bitcoin block headers (see lottery.go)
	BrowserPoW BrowserPoW `json:"browser_pow"` // how the 402 page offers its proof-of-work to people
}

// Admin configures the admin API and dashboard. It is off unless a key is set.
type Admin struct {
	Listen     string   `json:"listen"`       // default "127.0.0.1:8404"
	Key        string   `json:"key"`          // or env SPIKES402_ADMIN_KEY; "" = admin off
	AIKey      string   `json:"ai_key"`       // or env SPIKES402_AI_KEY; for the MCP server
	AICanApply bool     `json:"ai_can_apply"` // let the AI apply changes, not only propose them
	AllowedIPs []string `json:"allowed_ips"`  // required when listening beyond localhost
	VisitorIPs string   `json:"visitor_ips"`  // in the siege monitor: "hash" (default), "truncate" or "full"
}

// Withdraw configures withdrawals from the Lightning node. Off by default.
// The destination can only be set here, never through the API.
type Withdraw struct {
	Enabled              bool   `json:"enabled"`
	Destination          string `json:"destination"`            // Lightning/BIP353 address (name@domain, "₿" optional) or Bitcoin address
	Password             string `json:"password"`               // or env SPIKES402_WITHDRAW_PASSWORD
	PhoenixdFullPassword string `json:"phoenixd_full_password"` // or env PHOENIXD_FULL_PASSWORD
	FeerateSatByte       int64  `json:"feerate_sat_vbyte"`      // on-chain destination only
}

// Lightning selects and configures the Lightning backend.
type Lightning struct {
	Backend          string `json:"backend"`           // "fake" or "phoenixd"
	PhoenixdURL      string `json:"phoenixd_url"`      // default "http://127.0.0.1:9740"
	PhoenixdPassword string `json:"phoenixd_password"` // or env PHOENIXD_PASSWORD
}

// Load reads, completes and validates a configuration file. Secrets may
// come from the environment so they never have to be written in the file.
func Load(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields() // catch typos in option names
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if v := os.Getenv("SPIKES402_SECRET_KEY"); v != "" {
		c.SecretKey = v
	}
	if v := os.Getenv("PHOENIXD_PASSWORD"); v != "" {
		c.Lightning.PhoenixdPassword = v
	}
	if v := os.Getenv("SPIKES402_ADMIN_KEY"); v != "" {
		c.Admin.Key = v
	}
	if v := os.Getenv("SPIKES402_AI_KEY"); v != "" {
		c.Admin.AIKey = v
	}
	if c.Withdraw.Enabled { // spending secrets are only read when needed
		if v := os.Getenv("SPIKES402_WITHDRAW_PASSWORD"); v != "" {
			c.Withdraw.Password = v
		}
		if v := os.Getenv("PHOENIXD_FULL_PASSWORD"); v != "" {
			c.Withdraw.PhoenixdFullPassword = v
		}
	}
	if err := c.complete(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := c.resolveStateDir(file); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return applyOverridesFile(&c, file)
}

func (c *Config) resolveStateDir(configFile string) error {
	abs, err := filepath.Abs(configFile)
	if err != nil {
		return err
	}
	base := filepath.Dir(abs)
	if c.StateDir == "" {
		c.StateDir = filepath.Join(base, "state")
		return nil
	}
	if !filepath.IsAbs(c.StateDir) {
		c.StateDir = filepath.Join(base, c.StateDir)
	}
	return nil
}

// OverridesFile is where dashboard settings are saved: state_dir/config.overrides.json.
func (c *Config) OverridesFile() string {
	if c == nil || c.StateDir == "" {
		return ""
	}
	return filepath.Join(c.StateDir, "config.overrides.json")
}

func (c *Config) complete() error {
	if c.Listen == "" {
		c.Listen = ":8402"
		if c.Lightning.Backend == "fake" {
			c.Listen = "127.0.0.1:8402" // the fake backend must not be reachable from outside
		}
	}
	if c.ChallengeTTLSeconds == 0 {
		c.ChallengeTTLSeconds = 600
	}
	if c.PowSecondsPerSat == 0 {
		c.PowSecondsPerSat = 10
	}
	if c.ChallengesPerMinute == 0 {
		c.ChallengesPerMinute = 30
	}
	if c.MaxInvoicesPerMinute == 0 {
		c.MaxInvoicesPerMinute = 300
	}
	if c.MaxPendingInvoices == 0 {
		c.MaxPendingInvoices = 10_000
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 10_000
	}
	if c.ReadTimeoutSeconds == 0 {
		c.ReadTimeoutSeconds = 60
	}
	if c.WriteTimeoutSeconds == 0 {
		c.WriteTimeoutSeconds = 300
	}
	if c.MaxConnections < 1 || c.ReadTimeoutSeconds < 1 || c.WriteTimeoutSeconds < 1 {
		return errors.New(`"max_connections", "read_timeout_seconds" and "write_timeout_seconds" must be positive`)
	}
	if err := checkHosts("web_bot_auth_trusted_agents", c.WebBotAuthTrustedAgents); err != nil {
		return err
	}
	if err := checkHosts("public_hosts", c.PublicHosts); err != nil {
		return err
	}
	if len(c.WebBotAuthTrustedAgents) > 0 && len(c.PublicHosts) == 0 {
		return errors.New(`"web_bot_auth_trusted_agents" needs "public_hosts" (your site's host names), so signatures made for other sites are refused`)
	}
	if c.Lightning.Backend == "phoenixd" && c.Lightning.PhoenixdURL == "" {
		c.Lightning.PhoenixdURL = "http://127.0.0.1:9740"
	}

	u, err := url.Parse(c.Origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New(`"origin" must be an http(s) URL`)
	}
	if c.PriceSats < 1 {
		return errors.New(`"price_sats" must be at least 1`)
	}
	if c.PriceSats > maxPriceSats {
		return fmt.Errorf(`"price_sats" must be at most %d`, maxPriceSats)
	}
	if len(c.Protect) == 0 {
		return errors.New(`"protect" needs at least one path pattern, e.g. "/premium/**"`)
	}
	for _, p := range c.Protect {
		if err := checkPathPattern("protect pattern", p, c.ProtectCaseSensitive); err != nil {
			return err
		}
	}
	if len(c.Prices) > maxPriceRules {
		return fmt.Errorf(`"prices" can list at most %d rules`, maxPriceRules)
	}
	for i, r := range c.Prices {
		if err := checkPathPattern("prices pattern", r.Pattern, c.ProtectCaseSensitive); err != nil {
			return err
		}
		if r.PriceSats < 1 || r.PriceSats > maxPriceSats {
			return fmt.Errorf(`prices[%d].price_sats must be between 1 and %d`, i, maxPriceSats)
		}
	}
	if err := c.checkSurge(); err != nil {
		return err
	}
	if len(c.Previews) > maxPriceRules {
		return fmt.Errorf(`"previews" can list at most %d rules`, maxPriceRules)
	}
	for i, r := range c.Previews {
		if err := checkPathPattern("previews pattern", r.Pattern, c.ProtectCaseSensitive); err != nil {
			return err
		}
		if err := r.Check(); err != nil {
			return fmt.Errorf("previews[%d]: %w", i, err)
		}
	}
	if c.PowSecondsPerSat < 0 {
		return errors.New(`"pow_seconds_per_sat" must be positive`)
	}
	if c.PowSecondsPerSat < MinPowSecondsPerSat && !c.UnsafeAllowDangerousConfig {
		return fmt.Errorf(`"pow_seconds_per_sat" must be at least %g (one CPU-core second per sat) so proof-of-work cannot be switched off; set "unsafe_allow_dangerous_config": true if you really mean a lower value`, MinPowSecondsPerSat)
	}
	if c.PowAlgorithm == "" {
		c.PowAlgorithm = pow.SHA256d
	}
	if c.PowAlgorithm == pow.Argon2id && c.Argon2MemoryMiB == 0 {
		c.Argon2MemoryMiB = 16
	}
	switch c.PowAlgorithm {
	case pow.SHA256d:
		if c.Argon2MemoryMiB != 0 {
			return errors.New(`"argon2_memory_mib" only applies with "pow_algorithm": "argon2id"`)
		}
		if c.PowDifficulty < 0 || c.PowDifficulty > pow.MaxDifficulty {
			return fmt.Errorf(`"pow_difficulty" must be between 1 and %d`, pow.MaxDifficulty)
		}
	case pow.Argon2id:
		if c.Argon2MemoryMiB < pow.MinArgonMemoryMiB || c.Argon2MemoryMiB > pow.MaxArgonMemoryMiB {
			return fmt.Errorf(`"argon2_memory_mib" must be between %d and %d`, pow.MinArgonMemoryMiB, pow.MaxArgonMemoryMiB)
		}
		if c.PowDifficulty < 0 || c.PowDifficulty > pow.MaxArgonDifficulty {
			return fmt.Errorf(`"pow_difficulty" must be between 1 and %d with argon2id`, pow.MaxArgonDifficulty)
		}
	default:
		return errors.New(`"pow_algorithm" must be "sha256d" or "argon2id"`)
	}
	if err := c.checkLottery(); err != nil {
		return err
	}
	switch c.BrowserPoW.Mode {
	case "":
		c.BrowserPoW.Mode = gate.BrowserPoWButton
	case gate.BrowserPoWButton, gate.BrowserPoWAuto, gate.BrowserPoWOff:
	default:
		return errors.New(`"browser_pow.mode" must be "button", "auto" or "off"`)
	}
	if c.Argon2MaxMemoryMiB == 0 {
		c.Argon2MaxMemoryMiB = gate.DefaultArgonMaxMemoryMiB
	}
	if c.Argon2MaxMemoryMiB < 1 || c.Argon2MaxMemoryMiB > gate.MaxArgonMaxMemoryMiB {
		return fmt.Errorf(`"argon2_max_memory_mib" must be between 1 and %d`, gate.MaxArgonMaxMemoryMiB)
	}
	if c.PowAlgorithm == pow.Argon2id && c.Argon2MemoryMiB > c.Argon2MaxMemoryMiB {
		return fmt.Errorf(`"argon2_memory_mib" (%d) is more than "argon2_max_memory_mib" (%d)`, c.Argon2MemoryMiB, c.Argon2MaxMemoryMiB)
	}
	for k, p := range c.BotPolicies {
		if p.PriceMultiplier == 0 {
			p.PriceMultiplier = 1
			c.BotPolicies[k] = p
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("bot_policies %q: %w", k, err)
		}
	}
	for _, b := range c.KnownBots {
		if b.Name == "" || b.UserAgent == "" {
			return errors.New(`each of "known_bots" needs a "name" and a "user_agent"`)
		}
		if b.IPRangesURL != "" && !strings.HasPrefix(b.IPRangesURL, "https://") {
			return fmt.Errorf("known_bots %q: ip_ranges_url must be https", b.Name)
		}
	}
	if c.ChallengeTTLSeconds < 10 {
		return errors.New(`"challenge_ttl_seconds" must be at least 10`)
	}
	if c.ChallengesPerMinute < 1 || c.MaxInvoicesPerMinute < 1 || c.MaxPendingInvoices < 1 {
		return errors.New(`"challenges_per_minute", "max_invoices_per_minute" and "max_pending_invoices" must be at least 1`)
	}
	if _, err := c.TrustedProxyNets(); err != nil {
		return err
	}
	if c.ClientIPHeader != "" && len(c.TrustedProxies) == 0 {
		return errors.New(`"client_ip_header" needs "trusted_proxies": the addresses of the proxies allowed to set it`)
	}
	if c.PreserveHost && len(c.TrustedProxies) == 0 {
		return errors.New(`"preserve_host" needs "trusted_proxies": the public Host is only forwarded from those addresses`)
	}
	if c.SecretKey != "" && len(c.SecretKey) < 32 {
		return errors.New(`"secret_key" must be at least 32 characters (try: openssl rand -hex 32)`)
	}
	switch c.Lightning.Backend {
	case "fake":
	case "phoenixd":
		if c.WebBotAuthDevMode {
			return errors.New(`"web_bot_auth_dev_mode" is for local testing only and cannot be used with a real Lightning backend`)
		}
		if c.SecretKey == "" {
			return errors.New(`"secret_key" (or SPIKES402_SECRET_KEY) is required with a real Lightning backend`)
		}
		if c.Lightning.PhoenixdPassword == "" {
			return errors.New(`phoenixd needs "phoenixd_password" (or PHOENIXD_PASSWORD)`)
		}
	default:
		return errors.New(`"lightning.backend" must be "fake" or "phoenixd"`)
	}
	if err := c.checkAdmin(); err != nil {
		return err
	}
	if err := c.checkWithdraw(); err != nil {
		return err
	}
	return c.checkDangerous()
}

// checkDangerous refuses settings that switch protections off, unless
// "unsafe_allow_dangerous_config" is set.
func (c *Config) checkDangerous() error {
	if c.UnsafeAllowDangerousConfig {
		return nil
	}
	const hint = ` (set "unsafe_allow_dangerous_config": true only if you really mean it)`
	for _, l := range []struct {
		name string
		list []string
	}{{"trusted_proxies", c.TrustedProxies}, {"admin.allowed_ips", c.Admin.AllowedIPs}} {
		nets, _ := parseNets(l.list) // validated above
		for _, n := range nets {
			if ones, _ := n.Mask.Size(); ones == 0 {
				return fmt.Errorf("%q contains %s, i.e. every address on the internet%s", l.name, n, hint)
			}
		}
	}
	if c.Lightning.Backend == "fake" && !IsLoopback(c.Listen) {
		return fmt.Errorf(`the fake Lightning backend lets anyone "pay" for free: "listen" must be a localhost address (e.g. "127.0.0.1:8402"), not %q%s`, c.Listen, hint)
	}
	return nil
}

// IsLoopback reports whether a listen address only accepts connections
// from the same machine.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkHosts validates a list of bare host names ("example.com").
func checkHosts(name string, list []string) error {
	for i, h := range list {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h == "" || strings.ContainsAny(h, "/:@ *") || !strings.Contains(h, ".") && h != "localhost" {
			return fmt.Errorf("%s: %q is not a host name (write e.g. \"example.com\", without https:// or a port)", name, list[i])
		}
		list[i] = h
	}
	return nil
}

func (c *Config) checkAdmin() error {
	a := &c.Admin
	if a.Listen == "" {
		a.Listen = "127.0.0.1:8404"
	}
	if a.VisitorIPs == "" {
		a.VisitorIPs = "hash"
	}
	switch a.VisitorIPs {
	case "hash", "truncate", "full":
	default:
		return errors.New(`"admin.visitor_ips" must be "hash", "truncate" or "full"`)
	}
	if a.Key == "" {
		if a.AIKey != "" || a.AICanApply || len(a.AllowedIPs) > 0 {
			return errors.New(`admin settings need "admin.key" (or SPIKES402_ADMIN_KEY)`)
		}
		return nil
	}
	if len(a.Key) < 32 {
		return errors.New(`"admin.key" must be at least 32 characters (try: openssl rand -hex 32)`)
	}
	if a.AIKey != "" && (len(a.AIKey) < 32 || a.AIKey == a.Key) {
		return errors.New(`"admin.ai_key" must be at least 32 characters and differ from "admin.key"`)
	}
	if a.AICanApply && a.AIKey == "" {
		return errors.New(`"admin.ai_can_apply" needs "admin.ai_key"`)
	}
	if a.Key == c.SecretKey || (a.AIKey != "" && a.AIKey == c.SecretKey) {
		return errors.New(`admin keys must differ from "secret_key"`)
	}
	if _, _, err := net.SplitHostPort(a.Listen); err != nil {
		return fmt.Errorf(`"admin.listen": %w`, err)
	}
	if _, err := c.AdminAllowedNets(); err != nil {
		return err
	}
	if !IsLoopback(a.Listen) && len(a.AllowedIPs) == 0 {
		return errors.New(`"admin.listen" beyond localhost needs "admin.allowed_ips"`)
	}
	return nil
}

func (c *Config) checkWithdraw() error {
	w := &c.Withdraw
	w.Destination = lightning.NormalizeDestination(w.Destination)
	if !w.Enabled {
		if w.Destination != "" || w.Password != "" || w.PhoenixdFullPassword != "" {
			return errors.New(`withdraw settings are set but "withdraw.enabled" is false`)
		}
		return nil
	}
	if c.Admin.Key == "" {
		return errors.New(`withdrawals need the admin dashboard ("admin.key")`)
	}
	switch {
	case lightning.IsLightningAddress(w.Destination):
	case lightning.IsBitcoinAddress(w.Destination):
		if w.FeerateSatByte < 1 || w.FeerateSatByte > 1000 {
			return errors.New(`an on-chain "withdraw.destination" needs "withdraw.feerate_sat_vbyte" (1-1000)`)
		}
	default:
		return errors.New(`"withdraw.destination" must be a Lightning address or a BIP353 address (name@domain, a leading ₿ is fine; phoenixd pays both) or a Bitcoin address`)
	}
	if len(w.Password) < 16 {
		return errors.New(`"withdraw.password" (or SPIKES402_WITHDRAW_PASSWORD) must be at least 16 characters`)
	}
	for _, other := range []string{c.Admin.Key, c.Admin.AIKey, c.SecretKey, c.Lightning.PhoenixdPassword} {
		if w.Password == other {
			return errors.New(`"withdraw.password" must differ from every other key and password`)
		}
	}
	if c.Lightning.Backend == "phoenixd" {
		if w.PhoenixdFullPassword == "" || w.PhoenixdFullPassword == c.Lightning.PhoenixdPassword {
			return errors.New(`withdrawals need phoenixd's FULL-ACCESS password in "withdraw.phoenixd_full_password" (or PHOENIXD_FULL_PASSWORD)`)
		}
	}
	return nil
}

// AdminEnabled reports whether the admin API should run.
func (c *Config) AdminEnabled() bool { return c.Admin.Key != "" }

// AdminAllowedNets parses admin.allowed_ips.
func (c *Config) AdminAllowedNets() ([]*net.IPNet, error) {
	nets, err := parseNets(c.Admin.AllowedIPs)
	if err != nil {
		return nil, fmt.Errorf("admin.allowed_ips: %w", err)
	}
	return nets, nil
}

// TrustedProxyNets parses trusted_proxies ("10.0.0.1", "10.0.0.0/8", "::1").
func (c *Config) TrustedProxyNets() ([]*net.IPNet, error) {
	nets, err := parseNets(c.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("trusted_proxies: %w", err)
	}
	return nets, nil
}

func parseNets(list []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, p := range list {
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil && ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR range", p)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// IdentifyBotsOn reports whether bot identification is enabled.
func (c *Config) IdentifyBotsOn() bool {
	return c.IdentifyBots == nil || *c.IdentifyBots
}

// Bots returns the list of known bots to check.
func (c *Config) Bots() []botid.Bot {
	if c.KnownBots != nil {
		return c.KnownBots
	}
	return botid.DefaultBots
}

// PoW returns the puzzle for a price: the fixed pow_difficulty if set,
// otherwise derived from the price and pow_seconds_per_sat.
func (c *Config) PoW(priceSats int64) pow.Params {
	if c.PowDifficulty > 0 {
		return pow.Params{Algorithm: c.PowAlgorithm, Difficulty: c.PowDifficulty, MemoryMiB: c.Argon2MemoryMiB}
	}
	return pow.ForPrice(c.PowAlgorithm, c.Argon2MemoryMiB, priceSats, c.PowSecondsPerSat)
}

// ChallengeTTL returns the challenge lifetime as a duration.
func (c *Config) ChallengeTTL() time.Duration {
	return time.Duration(c.ChallengeTTLSeconds) * time.Second
}

// Changes are the settings an admin may change at run time. Nil fields
// stay as they are. Changes last until restart: edit the file to keep them.
type Changes struct {
	PriceSats           *int64                  `json:"price_sats,omitempty"`
	Prices              *[]gate.PriceRule       `json:"prices,omitempty"`
	Protect             *[]string               `json:"protect,omitempty"`
	PowSecondsPerSat    *float64                `json:"pow_seconds_per_sat,omitempty"`
	ChallengesPerMinute *int                    `json:"challenges_per_minute,omitempty"`
	BotPolicies         *map[string]gate.Policy `json:"bot_policies,omitempty"`
	Paused              *bool                   `json:"paused,omitempty"`
}

// Empty reports whether ch changes nothing.
func (ch Changes) Empty() bool {
	return ch.PriceSats == nil && ch.Prices == nil && ch.Protect == nil && ch.PowSecondsPerSat == nil && ch.ChallengesPerMinute == nil && ch.BotPolicies == nil && ch.Paused == nil
}

// Apply returns a validated copy of c with the changes; c is untouched.
func (c *Config) Apply(ch Changes) (*Config, error) {
	if ch.Empty() {
		return nil, errors.New("no changes")
	}
	n := *c
	n.BotPolicies = maps.Clone(c.BotPolicies)
	n.Prices = append([]gate.PriceRule(nil), c.Prices...)
	n.Protect = append([]string(nil), c.Protect...)
	n.Surge.Groups = maps.Clone(c.Surge.Groups)
	if ch.PriceSats != nil {
		n.PriceSats = *ch.PriceSats
	}
	if ch.Prices != nil {
		n.Prices = append([]gate.PriceRule(nil), (*ch.Prices)...)
	}
	if ch.Protect != nil {
		n.Protect = append([]string(nil), (*ch.Protect)...)
	}
	if ch.Paused != nil {
		n.Paused = *ch.Paused
	}
	if ch.PowSecondsPerSat != nil {
		if v := *ch.PowSecondsPerSat; !(v > 0 && v <= 3600) || math.IsNaN(v) {
			return nil, errors.New(`"pow_seconds_per_sat" must be above 0 and at most 3600`)
		}
		n.PowSecondsPerSat = *ch.PowSecondsPerSat
	}
	if ch.ChallengesPerMinute != nil {
		n.ChallengesPerMinute = *ch.ChallengesPerMinute
	}
	if ch.BotPolicies != nil {
		if len(*ch.BotPolicies) > 100 {
			return nil, errors.New("too many bot_policies")
		}
		n.BotPolicies = maps.Clone(*ch.BotPolicies)
	}
	if n.PriceSats > maxPriceSats {
		return nil, fmt.Errorf(`"price_sats" must be at most %d`, maxPriceSats)
	}
	if n.ChallengesPerMinute < 1 || n.ChallengesPerMinute > 100_000 {
		return nil, errors.New(`"challenges_per_minute" must be between 1 and 100,000`)
	}
	if err := n.complete(); err != nil {
		return nil, err
	}
	return &n, nil
}

// Public is the configuration without any secret, for the dashboard.
type Public struct {
	Origin               string                 `json:"origin"`
	Protect              []string               `json:"protect"`
	PriceSats            int64                  `json:"price_sats"`
	Prices               []gate.PriceRule       `json:"prices"`
	Surge                gate.SurgeConfig       `json:"surge"`
	Paused               bool                   `json:"paused"`
	PowAlgorithm         string                 `json:"pow_algorithm"`
	PowSecondsPerSat     float64                `json:"pow_seconds_per_sat"`
	PowDifficulty        int                    `json:"pow_difficulty"`
	Argon2MemoryMiB      int                    `json:"argon2_memory_mib,omitempty"`
	CurrentPoW           pow.Params             `json:"current_pow"`
	ChallengeTTLSeconds  int                    `json:"challenge_ttl_seconds"`
	ChallengesPerMinute  int                    `json:"challenges_per_minute"`
	MaxInvoicesPerMinute int                    `json:"max_invoices_per_minute"`
	MaxPendingInvoices   int                    `json:"max_pending_invoices"`
	IdentifyBots         bool                   `json:"identify_bots"`
	BotPolicies          map[string]gate.Policy `json:"bot_policies"`
	LightningBackend     string                 `json:"lightning_backend"`
	AICanApply           bool                   `json:"ai_can_apply"`
	VisitorIPs           string                 `json:"visitor_ips"`
	WithdrawEnabled      bool                   `json:"withdraw_enabled"`
	WithdrawDestination  string                 `json:"withdraw_destination,omitempty"`
	Editable             []string               `json:"editable"`
}

// Public returns the configuration without secrets.
func (c *Config) Public() Public {
	p := Public{
		Origin: c.Origin, Protect: append([]string(nil), c.Protect...), PriceSats: c.PriceSats, Prices: c.Prices, Surge: c.Surge, Paused: c.Paused, PowAlgorithm: c.PowAlgorithm,
		PowSecondsPerSat: c.PowSecondsPerSat, PowDifficulty: c.PowDifficulty, Argon2MemoryMiB: c.Argon2MemoryMiB,
		CurrentPoW: c.PoW(c.PriceSats), ChallengeTTLSeconds: c.ChallengeTTLSeconds, ChallengesPerMinute: c.ChallengesPerMinute,
		MaxInvoicesPerMinute: c.MaxInvoicesPerMinute, MaxPendingInvoices: c.MaxPendingInvoices,
		IdentifyBots: c.IdentifyBotsOn(), BotPolicies: c.BotPolicies, LightningBackend: c.Lightning.Backend,
		AICanApply: c.Admin.AICanApply, VisitorIPs: c.Admin.VisitorIPs, WithdrawEnabled: c.Withdraw.Enabled,
		Editable: []string{"price_sats", "prices", "protect", "pow_seconds_per_sat", "challenges_per_minute", "bot_policies", "paused"},
	}
	if p.BotPolicies == nil {
		p.BotPolicies = map[string]gate.Policy{}
	}
	if p.Prices == nil {
		p.Prices = []gate.PriceRule{}
	}
	if c.Withdraw.Enabled {
		p.WithdrawDestination = c.Withdraw.Destination
	}
	return p
}

// GateSettings converts the live-editable part of c for the gate.
func (c *Config) GateSettings() gate.Settings {
	return gate.Settings{
		PriceSats: c.PriceSats, Prices: append([]gate.PriceRule(nil), c.Prices...),
		Protect: append([]string(nil), c.Protect...), Paused: c.Paused,
		PoW: c.PoW, Policies: c.BotPolicies, ChallengesPerMinute: c.ChallengesPerMinute,
		Surge: c.Surge,
	}
}

// checkSurge validates optional dynamic pricing and fills defaults when
// it is in use. Group keys must be one of the protect or prices patterns
// so a typo cannot silently create an unused group.
func (c *Config) checkSurge() error {
	if err := c.Surge.Normalize(); err != nil {
		return err
	}
	known := map[string]struct{}{}
	for _, p := range c.Protect {
		known[p] = struct{}{}
	}
	for _, r := range c.Prices {
		known[r.Pattern] = struct{}{}
	}
	for pat := range c.Surge.Groups {
		if err := checkPathPattern("surge.groups pattern", pat, c.ProtectCaseSensitive); err != nil {
			return err
		}
		if _, ok := known[pat]; !ok {
			// allow a case-insensitive match when protect is not case-sensitive
			if !c.ProtectCaseSensitive {
				found := false
				for k := range known {
					if strings.EqualFold(k, pat) {
						found = true
						break
					}
				}
				if found {
					continue
				}
			}
			return fmt.Errorf("surge.groups %q does not match a protect or prices pattern", pat)
		}
	}
	return nil
}

// BrowserPoW configures the proof-of-work on the 402 page.
type BrowserPoW struct {
	Mode string `json:"mode"` // "button" (default), "auto" or "off"
}
