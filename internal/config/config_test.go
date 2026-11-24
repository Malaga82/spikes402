package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, json string) (*Config, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(f, []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(f)
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load("../../config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8402" || c.PowSecondsPerSat != 10 || c.PoW(c.PriceSats).Difficulty != 24 || c.ChallengeTTLSeconds != 600 || c.PassTTL() != 10*time.Second ||
		c.ChallengesPerMinute != 30 || c.MaxInvoicesPerMinute != 300 || c.MaxPendingInvoices != 10_000 || c.ClientIPHeader != "" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestPassTTLConfig(t *testing.T) {
	base := `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"lightning":{"backend":"fake"}}`
	c, err := load(t, base)
	if err != nil || c.PassTTL() != 10*time.Second || c.Public().PassTTLSeconds != 10 {
		t.Fatalf("omitted: ttl=%v public=%d err=%v", c.PassTTL(), c.Public().PassTTLSeconds, err)
	}
	for _, n := range []int{0, 10, 60} {
		c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"pass_ttl_seconds":`+strconv.Itoa(n)+`,"lightning":{"backend":"fake"}}`)
		if err != nil || c.PassTTL() != time.Duration(n)*time.Second || c.Public().PassTTLSeconds != n {
			t.Fatalf("%d: ttl=%v public=%d err=%v", n, c.PassTTL(), c.Public().PassTTLSeconds, err)
		}
	}
	for _, n := range []int{-1, 61} {
		if _, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"pass_ttl_seconds":`+strconv.Itoa(n)+`,"lightning":{"backend":"fake"}}`); err == nil || !strings.Contains(err.Error(), "pass_ttl_seconds") {
			t.Fatalf("%d: want pass_ttl_seconds error, got %v", n, err)
		}
	}
}

func TestEnvSecrets(t *testing.T) {
	t.Setenv("SPIKES402_SECRET_KEY", strings.Repeat("k", 32))
	t.Setenv("PHOENIXD_PASSWORD", "pw")
	c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"lightning":{"backend":"phoenixd"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Lightning.PhoenixdPassword != "pw" || c.Lightning.PhoenixdURL != "http://127.0.0.1:9740" {
		t.Fatalf("unexpected: %+v", c.Lightning)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]string{
		"no origin":           `{"price_sats":5,"protect":["/x"],"lightning":{"backend":"fake"}}`,
		"zero price":          `{"origin":"http://o","price_sats":0,"protect":["/x"],"lightning":{"backend":"fake"}}`,
		"huge price":          `{"origin":"http://o","price_sats":1000001,"protect":["/x"],"lightning":{"backend":"fake"}}`,
		"bad prices pattern":  `{"origin":"http://o","price_sats":5,"protect":["/x"],"prices":[{"pattern":"x","price_sats":2}],"lightning":{"backend":"fake"}}`,
		"zero path price":     `{"origin":"http://o","price_sats":5,"protect":["/x"],"prices":[{"pattern":"/x","price_sats":0}],"lightning":{"backend":"fake"}}`,
		"huge path price":     `{"origin":"http://o","price_sats":5,"protect":["/x"],"prices":[{"pattern":"/x","price_sats":1000001}],"lightning":{"backend":"fake"}}`,
		"preview bad mode":    `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[{"pattern":"/x","mode":"full"}],"lightning":{"backend":"fake"}}`,
		"preview no mode":     `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[{"pattern":"/x"}],"lightning":{"backend":"fake"}}`,
		"preview huge chars":  `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[{"pattern":"/x","mode":"excerpt","max_chars":1001}],"lightning":{"backend":"fake"}}`,
		"preview chars/title": `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[{"pattern":"/x","mode":"title","max_chars":10}],"lightning":{"backend":"fake"}}`,
		"preview bad pattern": `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[{"pattern":"x","mode":"title"}],"lightning":{"backend":"fake"}}`,
		"no patterns":         `{"origin":"http://o","price_sats":5,"lightning":{"backend":"fake"}}`,
		"bad pattern":         `{"origin":"http://o","price_sats":5,"protect":["x"],"lightning":{"backend":"fake"}}`,
		"trailing slash":      `{"origin":"http://o","price_sats":5,"protect":["/docs/"],"lightning":{"backend":"fake"}}`,
		"short secret":        `{"origin":"http://o","price_sats":5,"protect":["/x"],"secret_key":"short","lightning":{"backend":"fake"}}`,
		"typo":                `{"origin":"http://o","price_sat":5,"protect":["/x"],"lightning":{"backend":"fake"}}`,
		"no backend":          `{"origin":"http://o","price_sats":5,"protect":["/x"]}`,
		"negative pow":        `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_seconds_per_sat":-1,"lightning":{"backend":"fake"}}`,
		"bad rate limit":      `{"origin":"http://o","price_sats":5,"protect":["/x"],"challenges_per_minute":-1,"lightning":{"backend":"fake"}}`,
		"header no proxies":   `{"origin":"http://o","price_sats":5,"protect":["/x"],"client_ip_header":"X-Forwarded-For","lightning":{"backend":"fake"}}`,
		"preserve no proxies": `{"origin":"http://o","price_sats":5,"protect":["/x"],"preserve_host":true,"lightning":{"backend":"fake"}}`,
		"bad proxy":           `{"origin":"http://o","price_sats":5,"protect":["/x"],"trusted_proxies":["nope"],"lightning":{"backend":"fake"}}`,
		"phoenixd no pw":      `{"origin":"http://o","price_sats":5,"protect":["/x"],"secret_key":"` + strings.Repeat("k", 32) + `","lightning":{"backend":"phoenixd"}}`,
		"bad algorithm":       `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"scrypt","lightning":{"backend":"fake"}}`,
		"bad browser_pow":     `{"origin":"http://o","price_sats":5,"protect":["/x"],"browser_pow":{"mode":"always"},"lightning":{"backend":"fake"}}`,
		"argon memory bomb":   `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"argon2id","argon2_memory_mib":4096,"lightning":{"backend":"fake"}}`,
		"argon too little":    `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"argon2id","argon2_memory_mib":1,"lightning":{"backend":"fake"}}`,
		"argon too hard":      `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"argon2id","pow_difficulty":30,"lightning":{"backend":"fake"}}`,
		"memory w/o argon":    `{"origin":"http://o","price_sats":5,"protect":["/x"],"argon2_memory_mib":16,"lightning":{"backend":"fake"}}`,
		"argon over budget":   `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"argon2id","argon2_memory_mib":64,"argon2_max_memory_mib":32,"lightning":{"backend":"fake"}}`,
		"argon budget huge":   `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_algorithm":"argon2id","argon2_max_memory_mib":99999,"lightning":{"backend":"fake"}}`,
		"negative pow diff":   `{"origin":"http://o","price_sats":5,"protect":["/x"],"pow_difficulty":-1,"lightning":{"backend":"fake"}}`,
		"bad policy":          `{"origin":"http://o","price_sats":5,"protect":["/x"],"bot_policies":{"impostor":{"action":"ban"}},"lightning":{"backend":"fake"}}`,
		"bad multiplier":      `{"origin":"http://o","price_sats":5,"protect":["/x"],"bot_policies":{"impostor":{"action":"pay","price_multiplier":-2}},"lightning":{"backend":"fake"}}`,
		"bot without name":    `{"origin":"http://o","price_sats":5,"protect":["/x"],"known_bots":[{"user_agent":"x"}],"lightning":{"backend":"fake"}}`,
		"bot list over http":  `{"origin":"http://o","price_sats":5,"protect":["/x"],"known_bots":[{"name":"x","user_agent":"x","ip_ranges_url":"http://x"}],"lightning":{"backend":"fake"}}`,
		"dev mode in prod":    `{"origin":"http://o","price_sats":5,"protect":["/x"],"web_bot_auth_dev_mode":true,"secret_key":"` + strings.Repeat("k", 32) + `","lightning":{"backend":"phoenixd","phoenixd_password":"p"}}`,
		"surge cap":           `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"max_multiplier":11},"lightning":{"backend":"fake"}}`,
		"surge step":          `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"step":-1},"lightning":{"backend":"fake"}}`,
		"surge floor":         `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"min_per_minute":-5},"lightning":{"backend":"fake"}}`,
		"surge ratio":         `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"surge_ratio":1},"lightning":{"backend":"fake"}}`,
		"surge interval":      `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"step_interval_minutes":0.01},"lightning":{"backend":"fake"}}`,
		"surge unknown group": `{"origin":"http://o","price_sats":5,"protect":["/x"],"surge":{"enabled":true,"groups":{"/nope/**":{"enabled":true}}},"lightning":{"backend":"fake"}}`,
	}
	for name, json := range cases {
		if _, err := load(t, json); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPowFromPrice(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":10,"protect":["/x"],"pow_seconds_per_sat":1,"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if d := c.PoW(c.PriceSats).Difficulty; d != 24 { // 10 sats x 1 s x 2e6 hashes/s = 2^24.25
		t.Fatalf("got %d", d)
	}
	c, err = load(t, `{"origin":"http://o","price_sats":10,"protect":["/x"],"pow_difficulty":12,"lightning":{"backend":"fake"}}`)
	if err != nil || c.PoW(c.PriceSats).Difficulty != 12 {
		t.Fatalf("explicit difficulty: %v %+v", err, c)
	}
}

func TestTrustedProxies(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x"],"client_ip_header":"X-Forwarded-For",
		"trusted_proxies":["127.0.0.1","::1","10.0.0.0/8"],"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	nets, _ := c.TrustedProxyNets()
	if len(nets) != 3 || nets[0].String() != "127.0.0.1/32" || nets[1].String() != "::1/128" || nets[2].String() != "10.0.0.0/8" {
		t.Fatalf("got %v", nets)
	}
}

func TestArgon2id(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":1,"protect":["/x"],"pow_algorithm":"argon2id","lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	p := c.PoW(1)
	if p.Algorithm != "argon2id" || p.MemoryMiB != 16 || p.Difficulty != 10 { // 10 s / (16 MiB / 1500 MiB/s) = 2^9.9
		t.Fatalf("got %+v", p)
	}
	if p := c.PoW(10); p.Difficulty != 13 { // ten times the price, ~2^3.3 more work
		t.Fatalf("got %+v", p)
	}
	if c.Argon2MaxMemoryMiB != 256 {
		t.Fatalf("default budget %d, want 256", c.Argon2MaxMemoryMiB)
	}
}

func TestBotDefaults(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":1,"protect":["/x"],"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IdentifyBotsOn() || len(c.Bots()) == 0 || len(c.BotPolicies) != 0 || c.WebBotAuthDevMode {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	c, err = load(t, `{"origin":"http://o","price_sats":1,"protect":["/x"],"identify_bots":false,
		"known_bots":[{"name":"MyBot","user_agent":"MyBot","reverse_dns":["example.org"]}],
		"bot_policies":{"impostor":{"action":"pow-only"},"verified":{"action":"pay","price_multiplier":2}},"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.IdentifyBotsOn() || c.Bots()[0].Name != "MyBot" || c.BotPolicies["impostor"].PriceMultiplier != 1 || c.BotPolicies["verified"].PriceMultiplier != 2 {
		t.Fatalf("got %+v", c)
	}
}

func TestDangerousConfigRefused(t *testing.T) {
	const b = `"origin":"http://o","price_sats":5,"protect":["/x/**"],"lightning":{"backend":"fake"}`
	for name, extra := range map[string]string{
		"trust every IPv4":        `"client_ip_header":"X-Forwarded-For","trusted_proxies":["0.0.0.0/0"]`,
		"trust every IPv6":        `"client_ip_header":"X-Forwarded-For","trusted_proxies":["10.0.0.1","::/0"]`,
		"admin open to all":       `"admin":{"key":"` + strings.Repeat("a", 32) + `","listen":"0.0.0.0:8404","allowed_ips":["0.0.0.0/0"]}`,
		"fake backend, public":    `"listen":":8402"`,
		"fake backend, LAN":       `"listen":"192.168.1.5:8402"`,
		"fake backend, all v6":    `"listen":"[::]:8402"`,
		"trusted agents, no host": `"web_bot_auth_trusted_agents":["example.com"]`,
		"bad trusted agent":       `"web_bot_auth_trusted_agents":["https://example.com/x"],"public_hosts":["mysite.example"]`,
		"bad public host":         `"public_hosts":["mysite.example:443"]`,
		"zero connections":        `"max_connections":-1`,
	} {
		if _, err := load(t, `{`+b+`,`+extra+`}`); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The explicit override accepts the dangerous ones.
	for _, extra := range []string{`"trusted_proxies":["0.0.0.0/0"],"client_ip_header":"X-Real-IP"`, `"listen":":8402"`} {
		if _, err := load(t, `{`+b+`,"unsafe_allow_dangerous_config":true,`+extra+`}`); err != nil {
			t.Errorf("override: %v", err)
		}
	}
	// Normal settings stay accepted, and the fake backend defaults to localhost.
	c, err := load(t, `{`+b+`,"client_ip_header":"X-Forwarded-For","trusted_proxies":["10.0.0.0/8","::1"],"public_hosts":["MySite.Example."],"web_bot_auth_trusted_agents":["Bots.Example"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8402" || c.PublicHosts[0] != "mysite.example" || c.WebBotAuthTrustedAgents[0] != "bots.example" ||
		c.MaxConnections != 10_000 || c.ReadTimeoutSeconds != 60 || c.WriteTimeoutSeconds != 300 || c.ProtectCaseSensitive {
		t.Fatalf("unexpected: %+v", c)
	}
}

func TestPathPrices(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/articles/**","/premium/**"],`+
		`"prices":[{"pattern":"/premium/special/**","price_sats":1},{"pattern":"/premium/**","price_sats":20}],`+
		`"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.PriceSats != 5 || len(c.Prices) != 2 || c.Prices[0].PriceSats != 1 || c.Prices[1].Pattern != "/premium/**" {
		t.Fatalf("got %+v", c.Prices)
	}
	if pub := c.Public(); len(pub.Prices) != 2 {
		t.Fatalf("public prices: %+v", pub.Prices)
	}
}

func TestPriceRuleLimits(t *testing.T) {
	raw := `{"origin":"http://o","price_sats":5,"protect":["/x"],"prices":[` +
		strings.Repeat(`{"pattern":"/x","price_sats":1},`, maxPriceRules) +
		`{"pattern":"/x","price_sats":1}],"lightning":{"backend":"fake"}}`
	if _, err := load(t, raw); err == nil {
		t.Fatal("accepted too many price rules")
	}
	if _, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x"],"prices":[{"pattern":"/[","price_sats":2}],"lightning":{"backend":"fake"}}`); err == nil {
		t.Fatal("accepted a bad prices glob")
	}
}

func TestPreviewsConfig(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"previews":[{"pattern":"/x/free/**","mode":"none"},{"pattern":"/x/**","mode":"excerpt","max_chars":200}],"lightning":{"backend":"fake"}}`)
	if err != nil || len(c.Previews) != 2 || c.Previews[1].MaxChars != 200 {
		t.Fatalf("%+v, %v", c.Previews, err)
	}
	if c, err = load(t, `{"origin":"http://o","price_sats":5,"protect":["/x/**"],"lightning":{"backend":"fake"}}`); err != nil || len(c.Previews) != 0 {
		t.Fatalf("previews must be off by default: %+v, %v", c.Previews, err)
	}
	raw := `{"origin":"http://o","price_sats":5,"protect":["/x"],"previews":[` +
		strings.Repeat(`{"pattern":"/x","mode":"title"},`, maxPriceRules) +
		`{"pattern":"/x","mode":"title"}],"lightning":{"backend":"fake"}}`
	if _, err := load(t, raw); err == nil {
		t.Fatal("accepted too many preview rules")
	}
}

func TestStateDirDefaultAndRelative(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "c.json")
	js := `{"origin":"http://o","price_sats":1,"protect":["/x/**"],"secret_key":"` + strings.Repeat("k", 32) + `","lightning":{"backend":"fake"}}`
	if err := os.WriteFile(file, []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != filepath.Join(dir, "state") {
		t.Fatalf("default state_dir: %s", c.StateDir)
	}

	js2 := `{"origin":"http://o","price_sats":1,"protect":["/x/**"],"state_dir":"data","secret_key":"` + strings.Repeat("k", 32) + `","lightning":{"backend":"fake"}}`
	file2 := filepath.Join(dir, "d.json")
	if err := os.WriteFile(file2, []byte(js2), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(file2)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir != filepath.Join(dir, "data") {
		t.Fatalf("relative state_dir: %s", c.StateDir)
	}
}

func TestTrailingSlashProtectPattern(t *testing.T) {
	_, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/docs/"],"lightning":{"backend":"fake"}}`)
	if err == nil || !strings.Contains(err.Error(), "trailing slash") {
		t.Fatalf("got %v", err)
	}
}

func TestSurgeConfig(t *testing.T) {
	c, err := load(t, `{"origin":"http://o","price_sats":5,"protect":["/x"],"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Surge.Active() {
		t.Fatal("surge must be off by default")
	}
	c, err = load(t, `{"origin":"http://o","price_sats":5,"protect":["/articles/**","/premium/**"],`+
		`"prices":[{"pattern":"/premium/**","price_sats":20}],`+
		`"surge":{"enabled":true},"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Surge.Active() || c.Surge.MaxMultiplier != 3 || c.Surge.MinPerMinute != 60 || c.Surge.SurgeRatio != 2 || c.Surge.Step != 0.25 || c.Surge.StepIntervalMinutes != 2 {
		t.Fatalf("defaults: %+v", c.Surge)
	}
	if pub := c.Public(); !pub.Surge.Active() || pub.Surge.MaxMultiplier != 3 {
		t.Fatalf("public: %+v", pub.Surge)
	}
	s := c.GateSettings()
	if !s.Surge.Active() {
		t.Fatal("gate settings lost surge")
	}
	c, err = load(t, `{"origin":"http://o","price_sats":5,"protect":["/articles/**","/premium/**"],`+
		`"surge":{"enabled":false,"max_multiplier":3,"groups":{"/premium/**":{"enabled":true,"max_multiplier":5}}},`+
		`"lightning":{"backend":"fake"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Surge.Active() || c.Surge.Groups["/premium/**"].MaxMultiplier != 5 {
		t.Fatalf("group override: %+v", c.Surge)
	}
}
