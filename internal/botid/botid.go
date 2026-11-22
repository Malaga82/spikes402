// Package botid tells who is knocking: a bot that signed its request
// (Web Bot Auth), a well-known crawler whose address checks out, an
// impostor that only claims to be one, or someone unknown.
package botid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Choffolo/spikes402/webbotauth"
)

// Bot is a well-known crawler and how its operator says to check it.
type Bot struct {
	Name        string   `json:"name"`
	UserAgent   string   `json:"user_agent"`    // case-insensitive substring of User-Agent
	IPRangesURL string   `json:"ip_ranges_url"` // operator's published IP ranges (JSON "prefixes")
	ReverseDNS  []string `json:"reverse_dns"`   // hostname suffixes for reverse DNS + forward confirmation
}

// DefaultBots are checked with the IP range lists their operators
// publish, and reverse DNS where the operator documents it.
var DefaultBots = []Bot{
	{"Googlebot", "Googlebot", "https://developers.google.com/crawling/ipranges/common-crawlers.json", []string{"googlebot.com"}},
	{"AdsBot-Google", "AdsBot-Google", "https://developers.google.com/crawling/ipranges/special-crawlers.json", nil},
	{"Bingbot", "bingbot", "https://www.bing.com/toolbox/bingbot.json", []string{"search.msn.com"}},
	{"GPTBot", "GPTBot", "https://openai.com/gptbot.json", nil},
	{"OAI-SearchBot", "OAI-SearchBot", "https://openai.com/searchbot.json", nil},
	{"ChatGPT-User", "ChatGPT-User", "https://openai.com/chatgpt-user.json", nil},
	{"ClaudeBot", "ClaudeBot", "https://claude.com/crawling/bots.json", nil},
	{"PerplexityBot", "PerplexityBot", "https://www.perplexity.com/perplexitybot.json", nil},
	{"Perplexity-User", "Perplexity-User", "https://www.perplexity.com/perplexity-user.json", nil},
	{"Applebot", "Applebot", "https://search.developer.apple.com/applebot.json", []string{"applebot.apple.com"}},
	{"DuckDuckBot", "DuckDuckBot", "https://duckduckgo.com/duckduckbot.json", nil},
	{"CCBot", "CCBot", "https://index.commoncrawl.org/ccbot.json", nil},
}

// Kind is the class of a request.
type Kind string

const (
	Unknown  Kind = "unknown"         // no (checkable) claim
	Impostor Kind = "impostor"        // claims a known bot, the check says no
	Verified Kind = "verified"        // known bot, address checks out
	Signed   Kind = "verified-signed" // valid Web Bot Auth signature from a trusted agent
)

// Class is the result of Classify.
type Class struct {
	Kind   Kind
	Name   string // bot name, or the Web Bot Auth agent URL
	Method string // "web-bot-auth", "ip-list" or "reverse-dns"
	Note   string // extra information, e.g. why a signature did not verify
}

// String formats the class for logs and the Spikes402-Class header.
func (c Class) String() string {
	s := string(c.Kind)
	if c.Name != "" {
		s += fmt.Sprintf("; name=%q", c.Name)
	}
	if c.Method != "" {
		s += "; method=" + c.Method
	}
	if c.Note != "" {
		s += fmt.Sprintf("; note=%q", c.Note)
	}
	return s
}

// Resolver is the part of net.Resolver used here (replaceable in tests).
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Limits.
const (
	dnsTimeout       = 1500 * time.Millisecond
	dnsCacheTTL      = time.Hour
	maxDNSCache      = 10_000
	maxDNSInFlight   = 16
	maxNames         = 5 // PTR names checked per address
	rangesRefresh    = 24 * time.Hour
	rangesRetry      = time.Hour
	rangesTimeout    = 15 * time.Second
	maxRangesBytes   = 2 << 20
	maxRangesEntries = 50_000
)

// Classifier classifies requests. Create it with New.
type Classifier struct {
	// TrustedAgents are the domains whose Web Bot Auth key directories are
	// trusted (a directory on the domain or a subdomain). A valid signature
	// from anywhere else proves nothing, since anyone can publish a key,
	// so such requests are classified by the other checks. Empty: no
	// request is ever "verified-signed". Set before the first Classify.
	TrustedAgents []string

	bots     []Bot
	sig      *webbotauth.Verifier // nil: Web Bot Auth off
	resolver Resolver
	client   *http.Client
	now      func() time.Time

	mu     sync.RWMutex
	ranges map[string][]netip.Prefix // bot name -> published ranges

	dnsMu    sync.Mutex
	dnsCache map[string]dnsResult // ip|bot -> result
	dnsSem   chan struct{}
}

type dnsResult struct {
	ok      bool
	expires time.Time
}

// New returns a classifier. sig may be nil to turn Web Bot Auth off.
func New(bots []Bot, sig *webbotauth.Verifier) *Classifier {
	return &Classifier{
		bots:     bots,
		sig:      sig,
		resolver: net.DefaultResolver,
		client:   &http.Client{Timeout: rangesTimeout},
		now:      time.Now,
		ranges:   make(map[string][]netip.Prefix),
		dnsCache: make(map[string]dnsResult),
		dnsSem:   make(chan struct{}, maxDNSInFlight),
	}
}

// Classify says who sent r. ip is the client address, scheme the scheme
// the client used.
func (c *Classifier) Classify(r *http.Request, ip net.IP, scheme string) Class {
	var note string
	if c.sig != nil {
		res := c.sig.Verify(r, scheme)
		switch res.Outcome {
		case webbotauth.Verified:
			if c.trusted(res.Agent) {
				return Class{Kind: Signed, Name: res.Agent, Method: "web-bot-auth"}
			}
			note = "signature valid, but its key directory is not on a trusted domain (web_bot_auth_trusted_agents): " + res.Agent
		case webbotauth.Invalid, webbotauth.Unverified:
			note = "signature " + string(res.Outcome) + ": " + res.Reason
		}
	}

	ua := strings.ToLower(r.UserAgent())
	for _, b := range c.bots {
		if b.UserAgent == "" || !strings.Contains(ua, strings.ToLower(b.UserAgent)) {
			continue
		}
		kind, method, why := c.check(b, ip)
		if why != "" {
			note = join(note, why)
		}
		return Class{Kind: kind, Name: b.Name, Method: method, Note: note}
	}
	return Class{Kind: Unknown, Note: note}
}

// trusted reports whether a key directory URL is on a trusted domain.
func (c *Classifier) trusted(agentURL string) bool {
	u, err := url.Parse(agentURL)
	if err != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, d := range c.TrustedAgents {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// check verifies a claimed bot. A claim that cannot be checked right now
// (list not loaded, DNS failing or busy) is Unknown, not Impostor.
func (c *Classifier) check(b Bot, ip net.IP) (Kind, string, string) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return Unknown, "", "claims " + b.Name + ", no client address"
	}
	addr = addr.Unmap()
	c.mu.RLock()
	prefixes, loaded := c.ranges[b.Name]
	c.mu.RUnlock()
	if loaded {
		for _, p := range prefixes {
			if p.Contains(addr) {
				return Verified, "ip-list", ""
			}
		}
		// Try the operator's documented reverse-DNS check after a list miss.
		if len(b.ReverseDNS) == 0 {
			return Impostor, "ip-list", ""
		}
	}
	if len(b.ReverseDNS) > 0 {
		ok, err := c.reverseDNS(b, addr)
		if err != nil {
			return Unknown, "", "claims " + b.Name + ", not checked: " + err.Error()
		}
		if ok {
			return Verified, "reverse-dns", ""
		}
		return Impostor, "reverse-dns", ""
	}
	return Unknown, "", "claims " + b.Name + ", not checked: IP list not loaded"
}

var errDNSBusy = errors.New("too many DNS checks in flight")

// reverseDNS does forward-confirmed reverse DNS: the PTR name must end
// in one of the bot's suffixes and resolve back to the same address.
func (c *Classifier) reverseDNS(b Bot, addr netip.Addr) (bool, error) {
	key := addr.String() + "|" + b.Name
	now := c.now()
	c.dnsMu.Lock()
	if r, ok := c.dnsCache[key]; ok && now.Before(r.expires) {
		c.dnsMu.Unlock()
		return r.ok, nil
	}
	c.dnsMu.Unlock()

	select {
	case c.dnsSem <- struct{}{}:
		defer func() { <-c.dnsSem }()
	default:
		return false, errDNSBusy
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	names, err := c.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
			return false, errors.New("reverse DNS failed")
		}
		names = nil // no PTR record: a definite "no"
	}
	ok := false
	for i, name := range names {
		if i >= maxNames {
			break
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if !hasSuffix(name, b.ReverseDNS) {
			continue
		}
		ips, err := c.resolver.LookupIPAddr(ctx, name)
		if err != nil {
			return false, errors.New("forward DNS failed")
		}
		for _, a := range ips {
			if fa, _ := netip.AddrFromSlice(a.IP); fa.Unmap() == addr {
				ok = true
			}
		}
	}

	c.dnsMu.Lock()
	if len(c.dnsCache) >= maxDNSCache {
		for k, r := range c.dnsCache {
			if !now.Before(r.expires) {
				delete(c.dnsCache, k)
			}
		}
		if len(c.dnsCache) >= maxDNSCache {
			clear(c.dnsCache) // bounded memory beats a perfect cache
		}
	}
	c.dnsCache[key] = dnsResult{ok: ok, expires: now.Add(dnsCacheTTL)}
	c.dnsMu.Unlock()
	return ok, nil
}

func hasSuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		s = strings.ToLower(s)
		if strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// Run loads the published IP ranges now and refreshes them daily until
// ctx ends. A failed download keeps the previous list and is retried
// after an hour.
func (c *Classifier) Run(ctx context.Context, logf func(string, ...any)) {
	for {
		failed, loaded := false, 0
		for _, b := range c.bots {
			if b.IPRangesURL == "" {
				continue
			}
			p, err := c.fetchRanges(ctx, b.IPRangesURL)
			if err != nil {
				failed = true
				logf("botid: cannot load IP ranges of %s: %v", b.Name, err)
				continue
			}
			c.mu.Lock()
			c.ranges[b.Name] = p
			c.mu.Unlock()
			loaded++
		}
		if loaded > 0 {
			logf("botid: published IP ranges loaded for %d bots", loaded)
		}
		wait := rangesRefresh
		if failed {
			wait = rangesRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (c *Classifier) fetchRanges(ctx context.Context, url string) ([]netip.Prefix, error) {
	ctx, cancel := context.WithTimeout(ctx, rangesTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Spikes402 (+https://github.com/Choffolo/spikes402)")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRangesBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRangesBytes {
		return nil, errors.New("list too large")
	}
	return parseRanges(body)
}

// parseRanges reads the {"prefixes":[{"ipv4Prefix":...},{"ipv6Prefix":...}]}
// format shared by Google, Bing, OpenAI, Anthropic, Perplexity, Apple,
// DuckDuckGo and Common Crawl.
func parseRanges(body []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			V4 string `json:"ipv4Prefix"`
			V6 string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, p := range doc.Prefixes {
		for _, s := range []string{p.V4, p.V6} {
			if s == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(s); err == nil && len(out) < maxRangesEntries {
				out = append(out, pfx.Masked())
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no prefixes")
	}
	return out, nil
}

// SetRanges installs ranges directly (tests and demos).
func (c *Classifier) SetRanges(bot string, prefixes []netip.Prefix) {
	c.mu.Lock()
	c.ranges[bot] = prefixes
	c.mu.Unlock()
}
